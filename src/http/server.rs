use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::http::handlers::ServerState;
use crate::http::manual_http::{read_request, write_response, HttpRequest, HttpResponse};
use crate::http::raw_connect::build_connect_response;
use crate::vpn::VpnTunnel;

pub struct HttpServer {
    addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    config: Arc<Config>,
    cert_hash: String,
}

impl HttpServer {
    pub fn new(
        addr: SocketAddr,
        tls_acceptor: TlsAcceptor,
        config: Arc<Config>,
        cert_hash: String,
    ) -> Self {
        Self {
            addr,
            tls_acceptor,
            config,
            cert_hash,
        }
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("HTTP server listening on {}", self.addr);

        // Create shared server state
        let state = Arc::new(ServerState::new(
            self.config.clone(),
            self.cert_hash.clone(),
        ));

        loop {
            let (tcp_stream, remote_addr) = listener.accept().await?;
            let tls_acceptor = self.tls_acceptor.clone();
            let state = state.clone();

            tokio::spawn(async move {
                match tls_acceptor.accept(tcp_stream).await {
                    Ok(mut tls_stream) => {
                        info!("TLS connection established from {}", remote_addr);

                        // Manual HTTP request/response loop
                        loop {
                            debug!("Waiting for next HTTP request...");
                            // Read request
                            let request = match read_request(&mut tls_stream).await {
                                Ok(Some(req)) => req,
                                Ok(None) => {
                                    debug!("Client closed connection cleanly");
                                    break;
                                }
                                Err(e) => {
                                    // Don't log EOF errors as they're expected
                                    let err_str = format!("{}", e);
                                    if !err_str.contains("eof") && !err_str.contains("Eof") {
                                        warn!("Error reading request: {}", e);
                                    }
                                    break;
                                }
                            };

                            info!("Received {} request to {}", request.method, request.path);

                            // Handle CONNECT specially - upgrade to VPN tunnel
                            if request.method == "CONNECT" && request.path == "/CSCOSSLC/tunnel" {
                                info!("CONNECT request - upgrading to VPN tunnel");

                                // Send CONNECT response with EXACT header casing
                                let response_str = build_connect_response(&state);
                                debug!("Sending CONNECT response:\n{}", response_str);

                                if let Err(e) = tls_stream.write_all(response_str.as_bytes()).await
                                {
                                    error!("Failed to write CONNECT response: {}", e);
                                    break;
                                }
                                if let Err(e) = tls_stream.flush().await {
                                    error!("Failed to flush CONNECT response: {}", e);
                                    break;
                                }

                                info!("CONNECT response sent, starting VPN tunnel");

                                // Hand off to VPN tunnel
                                let tunnel = VpnTunnel::new(tls_stream);
                                if let Err(e) = tunnel.run().await {
                                    error!("Tunnel error: {}", e);
                                }
                                info!("VPN tunnel ended");
                                return; // Exit the connection handler
                            }

                            // Handle regular HTTP requests
                            let response = handle_http_request(&request, &state).await;
                            let http_version = request.version;

                            if let Err(e) =
                                write_response(&mut tls_stream, &response, http_version).await
                            {
                                error!("Failed to write response: {}", e);
                                break;
                            }

                            // Check Connection header for keep-alive
                            let connection = request.header("Connection").unwrap_or("");
                            if http_version == 0 && connection.to_lowercase() != "keep-alive" {
                                // HTTP/1.0 defaults to close
                                break;
                            }
                            if connection.to_lowercase() == "close" {
                                break;
                            }

                            // Continue loop for keep-alive
                        }
                    }
                    Err(e) => {
                        error!("TLS handshake failed from {}: {}", remote_addr, e);
                    }
                }
            });
        }
    }
}

/// Handle a regular HTTP request and return a response
async fn handle_http_request(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    let path = req.path.split('?').next().unwrap_or(&req.path);

    match (req.method.as_str(), path) {
        // GET requests
        ("GET", "/") | ("GET", "") => handle_auth_init_manual(req, state),

        // AnyConnect update/manifest checks - return minimal responses
        ("GET", p) if p.ends_with("/binaries/update.txt") => {
            info!("AnyConnect update check: {}", p);
            HttpResponse::ok()
                .header("Content-Type", "text/xml")
                .body_str("0,0,0000\n")
        }

        ("GET", p) if p.ends_with("VPNManifest.xml") => {
            info!("AnyConnect manifest check: {}", p);
            HttpResponse::ok()
                .header("Content-Type", "text/xml")
                .body_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n</vpn>\n")
        }

        ("GET", p) if p.starts_with("/+CSCOT+/") => {
            info!("AnyConnect customization check: {}", p);
            HttpResponse::ok()
                .header("Content-Type", "text/xml")
                .body_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n</vpn>\n")
        }

        ("GET", p) if p.starts_with("/1/") => {
            info!("AnyConnect index/other check: {}", p);
            HttpResponse::ok()
                .header("Content-Type", "text/html")
                .body_str("<html></html>\n")
        }

        ("GET", "/logout") | ("GET", "//logout") => {
            info!("AnyConnect logout request");
            HttpResponse::ok()
                .header("Content-Type", "text/xml")
                .header("X-Transcend-Version", "1")
                .body_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<logout><result>success</result></logout>")
        }

        // POST to / - initial auth request
        ("POST", "/") | ("POST", "") => handle_auth_init_manual(req, state),

        // POST to /auth - authentication form submission
        ("POST", "/auth") => {
            let content_type = req.header("Content-Type").unwrap_or("");
            if content_type.contains("xml") {
                handle_xml_auth_manual(req, state)
            } else {
                handle_form_auth_manual(req, state)
            }
        }

        // Default 404
        _ => {
            warn!("Unknown request: {} {}", req.method, req.path);
            HttpResponse::not_found().body_str("Not Found")
        }
    }
}

/// Handle initial auth request (GET or POST to /)
fn handle_auth_init_manual(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    // Check for existing session cookie
    if let Some(cookie) = req.header("Cookie") {
        if let Some(token) = extract_webvpn_token(cookie) {
            if let Some(session) = state.session_manager.get_session_by_token(&token) {
                info!("Valid session found: {}", session.session_id);
                // Return session preserved response
                return HttpResponse::ok()
                    .header("Content-Type", "text/xml; charset=utf-8")
                    .header("X-Transcend-Version", "1")
                    .header("Cache-Control", "no-store")
                    .header("Pragma", "no-cache")
                    .header(
                        "Set-Cookie",
                        &format!(
                            "webvpncontext={}; path=/; Secure; HttpOnly",
                            session.session_id
                        ),
                    )
                    .body_str(&build_auth_form_xml(state));
            }
        }
    }

    // No session - return auth form
    HttpResponse::ok()
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("X-Transcend-Version", "1")
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .body_str(&build_auth_form_xml(state))
}

/// Handle XML auth submission
fn handle_xml_auth_manual(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    let body = String::from_utf8_lossy(&req.body);
    info!("XML auth submission: {}", body);

    // TODO: Parse XML and validate credentials
    // For now, accept any auth
    create_auth_success_response(state)
}

/// Handle form auth submission
fn handle_form_auth_manual(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    let body = String::from_utf8_lossy(&req.body);
    info!("Form auth submission: {}", body);

    // TODO: Parse form and validate credentials
    // For now, accept any auth
    create_auth_success_response(state)
}

/// Create auth success response with session cookies
fn create_auth_success_response(state: &Arc<ServerState>) -> HttpResponse {
    // Create new session with UserInfo
    use crate::auth::UserInfo;
    use std::collections::HashMap;
    let user_info = UserInfo {
        username: "user".to_string(),
        groups: vec![],
        attributes: HashMap::new(),
    };
    let session = state.session_manager.create_session(user_info);
    let session_id = &session.session_id;
    let session_token = &session.session_token;

    // Build cookie values
    let webvpncontext = format!("webvpncontext={}; path=/; Secure; HttpOnly", session_id);
    let webvpn = format!(
        "webvpn={}@{}@{}@{}; path=/; Secure; HttpOnly",
        &session_token[..6],
        session_id,
        &session_token[6..10],
        &session_token[10..13]
    );
    let webvpnc = format!(
        "webvpnc=bu:/&p:t&iu:1/&sh:{}; path=/; Secure; HttpOnly",
        state.cert_hash
    );

    let xml = r#"<config-auth client="vpn" type="complete">
    <version who="sg">0.1(1)</version>
    <auth id="success">
        <title>SSL VPN Service</title>
        <banner>Welcome to AI4CE VPN</banner>
    </auth>
</config-auth>
"#;

    HttpResponse::ok()
        .header("Content-Type", "text/xml")
        .header("Connection", "Keep-Alive")
        .header("X-Transcend-Version", "1")
        .header("Set-Cookie", &webvpncontext)
        .header("Set-Cookie", &webvpn)
        .header("Set-Cookie", &webvpnc)
        .body_str(xml)
}

/// Build auth form XML
fn build_auth_form_xml(_state: &Arc<ServerState>) -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
    <version who="sg">0.1</version>
    <auth id="main">
        <title>Login</title>
        <message>Please enter your username and password</message>
        <banner>Welcome to AI4CE VPN</banner>
        <form action="/auth" method="post">
            <input label="Username:" name="username" type="text"></input>
            <input label="Password:" name="password" type="password"></input>
        </form>
    </auth>
</config-auth>
"#
    .to_string()
}

/// Extract webvpn token from Cookie header
fn extract_webvpn_token(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("webvpn=") {
            return Some(value.to_string());
        }
    }
    None
}
