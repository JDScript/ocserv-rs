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
                                use crate::vpn::tun_device::TunDevice;
                                match TunDevice::new(None, &state.config.network) {
                                    Ok(tun) => {
                                        info!("Created TUN device: {}", tun.name());
                                        tun.configure_routing();
                                        let tunnel = VpnTunnel::new(tls_stream, tun);
                                        if let Err(e) = tunnel.run().await {
                                            error!("Tunnel error: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to create TUN device: {}", e);
                                    }
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
    use crate::http::handlers::{auth, sso};

    let path = req.path.split('?').next().unwrap_or(&req.path);

    match (req.method.as_str(), path) {
        // GET requests
        ("GET", "/") | ("GET", "") => auth::handle_auth_init(req, state),

        // SSO: Initiate Login
        ("GET", "/+CSCOE+/saml/sp/login") => sso::handle_saml_login(req, state),

        // SSO: ACS
        ("POST", "/+CSCOE+/saml/sp/acs") => sso::handle_saml_acs(req, state),

        // SSO: Final Login Page
        ("GET", "/+CSCOE+/saml_ac_login.html") => sso::handle_saml_success(req, state),

        // Mock IdP (Development only)
        ("GET", "/dev/idp") => {
            if state.config.auth.saml.dev_idp_enabled {
                sso::handle_mock_idp_get(req, state)
            } else {
                HttpResponse::new(404, "Not Found").body_str("Mock IdP disabled")
            }
        }
        ("POST", "/dev/idp") => {
            if state.config.auth.saml.dev_idp_enabled {
                sso::handle_mock_idp_post(req, state)
            } else {
                HttpResponse::new(404, "Not Found").body_str("Mock IdP disabled")
            }
        }

        // AnyConnect update/manifest checks
        ("GET", p) if p.ends_with("/binaries/update.txt") => {
            debug!("AnyConnect update check: {}", p);
            HttpResponse::ok()
                .header("Content-Type", "text/xml")
                .body_str("0,0,0000\n")
        }

        ("GET", p) if p.ends_with("VPNManifest.xml") => {
            debug!("AnyConnect manifest check: {}", p);
            HttpResponse::ok()
                .header("Content-Type", "text/xml")
                .body_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n<file-version>1.1.0</file-version>\n</vpn>\n")
        }

        ("GET", p) if p.starts_with("/+CSCOT+/") => {
            debug!("AnyConnect customization check: {} - returning 404", p);
            HttpResponse::new(404, "Not found")
                .header("Connection", "close")
                .body_str("<html><body><h1>404 Not Found</h1></body></html>")
        }

        ("GET", p) if p.ends_with("/1/index.html") => {
            debug!("AnyConnect index check: {}", p);
            HttpResponse::ok()
                .header("Connection", "Keep-Alive")
                .header("Content-Type", "text/html")
                .header("X-Transcend-Version", "1")
                .body_str("<html></html>")
        }

        // For other /1/ paths
        ("GET", p) if p.starts_with("/1/") => {
            debug!("AnyConnect unknown /1/ request: {} - returning 404", p);
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
        ("POST", "/") | ("POST", "") => auth::handle_auth_init(req, state),

        // POST to /auth
        ("POST", "/auth") => {
            let content_type = req.header("Content-Type").unwrap_or("");
            if content_type.contains("xml") {
                auth::handle_xml_auth(req, state)
            } else {
                auth::handle_form_auth(req, state)
            }
        }

        // Default 404
        _ => {
            warn!("Unknown request: {} {}", req.method, req.path);
            HttpResponse::not_found().body_str("Not Found")
        }
    }
}
