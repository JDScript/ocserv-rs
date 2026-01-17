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

        // Start DTLS server if configured
        if let Some(dtls_port) = self.config.server.dtls_port {
            let dtls_sessions = state.dtls_sessions.clone();
            let cert_path = self.config.server.cert_path.clone();
            let key_path = self.config.server.key_path.clone();
            info!("Starting DTLS server on UDP port {}", dtls_port);

            tokio::spawn(async move {
                match crate::vpn::dtls::DtlsServer::new(
                    dtls_port,
                    dtls_sessions,
                    &cert_path,
                    &key_path,
                )
                .await
                {
                    Ok(server) => {
                        if let Err(e) = server.run().await {
                            error!("DTLS server error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to create DTLS server: {}", e);
                    }
                }
            });
        }

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

                                // Debug: Log all headers to see what client sends
                                for (name, value) in &request.headers {
                                    if name.to_lowercase().contains("dtls") {
                                        info!("  DTLS header: {}: {}", name, value);
                                    }
                                }

                                // Determine DTLS mode based on client headers
                                use crate::http::raw_connect::{
                                    DtlsConfig, DtlsParams, LegacyDtlsParams,
                                };
                                use rand::Rng;

                                let mut dtls_config: Option<DtlsConfig> = None;
                                let dtls_port = state.config.server.dtls_port.unwrap_or(8443);

                                // Check for PSK-NEGOTIATE first (modern OpenConnect)
                                let dtls_ciphersuite =
                                    request.header("X-DTLS-CipherSuite").unwrap_or("");
                                let supports_psk = dtls_ciphersuite.contains("PSK-NEGOTIATE");

                                // Check for legacy DTLS (AnyConnect sends X-DTLS-Master-Secret)
                                let master_secret = request.header("X-DTLS-Master-Secret");
                                let dtls12_ciphersuite = request.header("X-DTLS12-CipherSuite");

                                info!(
                                    "DTLS check: supports_psk={}, has_master_secret={}",
                                    supports_psk,
                                    master_secret.is_some()
                                );

                                if supports_psk {
                                    // Modern PSK mode
                                    info!("Client supports DTLS with PSK-NEGOTIATE");

                                    // Generate 32-byte App-ID
                                    let app_id_bytes: [u8; 32] = rand::rng().random();
                                    let app_id_hex = hex::encode(&app_id_bytes);

                                    // Export PSK from TLS session
                                    let mut psk = [0u8; 32];
                                    let (_, tls_conn) = tls_stream.get_ref();

                                    if let Err(e) = tls_conn.export_keying_material(
                                        &mut psk,
                                        b"EXPORTER-openconnect-psk",
                                        None,
                                    ) {
                                        warn!("Failed to export PSK: {:?}", e);
                                    } else {
                                        info!(
                                            "Exported 32-byte PSK for DTLS (App-ID: {})",
                                            app_id_hex
                                        );

                                        use crate::vpn::dtls::DtlsSessionInfo;
                                        let mut sessions = state.dtls_sessions.write().unwrap();
                                        sessions.insert(
                                            app_id_hex.clone(),
                                            DtlsSessionInfo {
                                                psk: psk.to_vec(),
                                                tun_tx: None,
                                            },
                                        );

                                        dtls_config = Some(DtlsConfig::Psk(DtlsParams {
                                            port: dtls_port,
                                            app_id: app_id_hex,
                                            rekey_time: 86400,
                                            keepalive: 30,
                                        }));
                                    }
                                } else if let Some(_master_secret) = master_secret {
                                    // Legacy DTLS mode (AnyConnect)
                                    info!("Client uses legacy DTLS with Master-Secret");

                                    // Generate 32-byte session ID
                                    let session_id_bytes: [u8; 32] = rand::rng().random();
                                    let session_id_hex = hex::encode(&session_id_bytes);

                                    // Select best cipher from client's list
                                    // Prefer DTLS 1.2 ciphers if available
                                    let (selected_cipher, is_dtls12) =
                                        if let Some(ciphers) = dtls12_ciphersuite {
                                            // Pick first supported cipher from DTLS12 list
                                            let first_cipher = ciphers
                                                .split(':')
                                                .next()
                                                .unwrap_or("AES256-GCM-SHA384");
                                            (first_cipher.to_string(), true)
                                        } else {
                                            // Fall back to DTLS 0.9/1.0 ciphers
                                            let first_cipher = dtls_ciphersuite
                                                .split(':')
                                                .next()
                                                .unwrap_or("AES256-SHA");
                                            (first_cipher.to_string(), false)
                                        };

                                    info!(
                                        "Selected legacy DTLS cipher: {} (DTLS12: {})",
                                        selected_cipher, is_dtls12
                                    );

                                    // Store session info for DTLS server
                                    // Note: For legacy DTLS, we need to implement session resumption
                                    // which requires the master_secret. For now, store the session_id.
                                    {
                                        use crate::vpn::dtls::DtlsSessionInfo;
                                        let mut sessions = state.dtls_sessions.write().unwrap();
                                        // Store master secret as "PSK" for now (will need proper session resumption)
                                        sessions.insert(
                                            session_id_hex.clone(),
                                            DtlsSessionInfo {
                                                psk: hex::decode(_master_secret)
                                                    .unwrap_or_default(),
                                                tun_tx: None,
                                            },
                                        );
                                    }

                                    dtls_config = Some(DtlsConfig::Legacy(LegacyDtlsParams {
                                        port: dtls_port,
                                        session_id: session_id_hex,
                                        ciphersuite: selected_cipher,
                                        ciphersuite_is_dtls12: is_dtls12,
                                        rekey_time: 86400,
                                        keepalive: 30,
                                    }));
                                }

                                // Send CONNECT response with DTLS headers if supported
                                let response_str =
                                    build_connect_response(&state, dtls_config.as_ref());
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
                                use tokio::sync::mpsc;

                                match TunDevice::new(None, &state.config.network) {
                                    Ok(tun) => {
                                        info!("Created TUN device: {}", tun.name());
                                        tun.configure_routing();

                                        // Extract DTLS session ID if DTLS is configured
                                        let dtls_session_id = match &dtls_config {
                                            Some(DtlsConfig::Psk(p)) => Some(p.app_id.clone()),
                                            Some(DtlsConfig::Legacy(l)) => {
                                                Some(l.session_id.clone())
                                            }
                                            None => None,
                                        };

                                        // Create channel for DTLS packets if DTLS is enabled
                                        let tunnel = if let Some(session_id) = dtls_session_id {
                                            let (dtls_tx, dtls_rx) =
                                                mpsc::channel::<bytes::Bytes>(100);

                                            // Update DTLS session with the tun_tx channel
                                            {
                                                let mut sessions =
                                                    state.dtls_sessions.write().unwrap();
                                                if let Some(info) = sessions.get_mut(&session_id) {
                                                    info.tun_tx = Some(dtls_tx);
                                                    info!(
                                                        "Linked DTLS session {} to TUN device",
                                                        session_id
                                                    );
                                                } else {
                                                    warn!(
                                                        "DTLS session {} not found in store",
                                                        session_id
                                                    );
                                                }
                                            }

                                            VpnTunnel::with_dtls(tls_stream, tun, dtls_rx)
                                        } else {
                                            VpnTunnel::new(tls_stream, tun)
                                        };

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
