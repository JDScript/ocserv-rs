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
                .body_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n<file-version>1.1.0</file-version>\n</vpn>\n")
        }

        ("GET", p) if p.starts_with("/+CSCOT+/") => {
            info!("AnyConnect customization check: {} - returning 404", p);
            // ocserv returns 404 for these paths
            HttpResponse::new(404, "Not found")
                .header("Connection", "close")
                .body_str("<html><body><h1>404 Not Found</h1></body></html>")
        }

        ("GET", p) if p.ends_with("/1/index.html") => {
            info!("AnyConnect index check: {}", p);
            // ocserv returns 200 OK with <html></html> for index
            HttpResponse::ok()
                .header("Connection", "Keep-Alive")
                .header("Content-Type", "text/html")
                .header("X-Transcend-Version", "1")
                .body_str("<html></html>")
        }

        // For other /1/ paths (binaries, etc.), if not handled above, return 404
        ("GET", p) if p.starts_with("/1/") => {
            info!("AnyConnect unknown /1/ request: {} - returning 404", p);
            HttpResponse::new(404, "Not Found")
                .header("Connection", "close")
                .header("X-Transcend-Version", "1")
                .body_str("Not Found")
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
    // Special case: HTTP/1.0 with Connection: close and no cookies
    // This is likely a VPN agent keepalive/session check
    // Don't return auth form - return webvpnlogin cookie to trigger proper auth flow
    let connection = req.header("Connection").unwrap_or("");
    let has_cookies = req.header("Cookie").is_some();

    if req.version == 0 && connection.to_lowercase() == "close" && !has_cookies {
        debug!(
            "HTTP/1.0 Connection:close without cookies - VPN agent check - returning 204 No Content"
        );
        // 204 No Content is ideal for liveness probes
        // It says "Success, but nothing to see here", avoiding auth parsing triggers
        return HttpResponse::new(204, "No Content")
            .header("X-Transcend-Version", "1")
            .header("Connection", "close");
    }

    // Check for existing session cookie
    if let Some(cookie) = req.header("Cookie") {
        debug!("Got Cookie header: {}", cookie);
        if let Some(token) = extract_webvpn_token(cookie) {
            debug!("Extracted webvpn token: {}", token);
            if let Some(session) = state.session_manager.get_session_by_token(&token) {
                info!("Valid session found: {}", session.session_id);
                // For AnyConnect, valid session should return success response (type="complete")
                // Not the auth form - returning auth form causes logout!
                use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
                let context_b64 = BASE64.encode(session.session_id.as_bytes());

                let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<config-auth client=\"vpn\" type=\"complete\">\n<version who=\"sg\">0.1(1)</version>\n<auth id=\"success\">\n<title>SSL VPN Service</title>\n<banner>Welcome to AI4CE VPN</banner>\n</auth>\n</config-auth>";
                return HttpResponse::ok()
                    .header("Content-Type", "text/xml")
                    .header("X-Transcend-Version", "1")
                    .header(
                        "Set-Cookie",
                        &format!("webvpncontext={}; Secure; HttpOnly", context_b64),
                    )
                    .body_str(xml);
            } else {
                debug!("No session found for token");
            }
        } else {
            debug!("No webvpn token in cookies");
        }
    } else {
        debug!("No Cookie header in request");
    }

    // No session - return auth form with webvpncontext clearing (like ocserv)
    HttpResponse::ok()
        .header(
            "Set-Cookie",
            "webvpncontext=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure; HttpOnly",
        )
        .header("Content-Type", "text/xml")
        .header("X-Transcend-Version", "1")
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
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use std::collections::HashMap;

    let user_info = UserInfo {
        username: "user".to_string(),
        groups: vec![],
        attributes: HashMap::new(),
    };
    let session = state.session_manager.create_session(user_info);
    let session_id = &session.session_id;
    let session_token = &session.session_token;

    // CRITICAL: ocserv uses THE SAME value for both webvpncontext and webvpn!
    // This is what enables session sharing between AnyConnect components
    let cookie_b64 = BASE64.encode(session_token.as_bytes());

    // Build cookie values matching ocserv format - SAME value for both!
    let webvpncontext = format!("webvpncontext={}; Secure; HttpOnly", cookie_b64);
    let webvpn = format!("webvpn={}; Secure; HttpOnly", cookie_b64);

    // webvpnc: ocserv sends TWO cookies - first clears old, then sets new
    let webvpnc_clear =
        "webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure; HttpOnly".to_string();

    // AnyConnect might expect UPPERCASE hash?
    let webvpnc_set = format!(
        "webvpnc=bu:/&p:t&iu:1/&sh:{}; path=/; Secure; HttpOnly",
        state.cert_hash.to_uppercase()
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
        .header("Connection", "Keep-Alive")
        .header("Content-Type", "text/xml")
        .header("X-Transcend-Version", "1")
        .header("Set-Cookie", &webvpncontext)
        .header("Set-Cookie", &webvpn)
        .header("Set-Cookie", &webvpnc_clear)
        .header("Set-Cookie", &webvpnc_set)
        .body_str(xml)
}

/// Build auth form XML
fn build_auth_form_xml(_state: &Arc<ServerState>) -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
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

/// Extract webvpn token from Cookie header (decodes Base64)
fn extract_webvpn_token(cookie: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("webvpn=") {
            // Decode Base64 to get raw token
            if let Ok(decoded) = BASE64.decode(value) {
                if let Ok(token) = String::from_utf8(decoded) {
                    return Some(token);
                }
            }
            // If decode fails, try raw value (backward compat)
            return Some(value.to_string());
        }
    }
    None
}
