use crate::http::handlers::ServerState;
use crate::vpn::dtls::{DtlsSessionInfo, DtlsSessionStore};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};

/// PSK-based DTLS parameters (modern OpenConnect mode)
pub struct DtlsParams {
    pub port: u16,
    pub app_id: String, // Hex-encoded session identifier
    pub rekey_time: u32,
    pub keepalive: u32,
}

/// Legacy DTLS parameters (AnyConnect compatibility mode)
pub struct LegacyDtlsParams {
    pub port: u16,
    pub session_id: String,          // Hex-encoded 32-byte session ID
    pub ciphersuite: String,         // Selected cipher (e.g., "AES256-GCM-SHA384")
    pub ciphersuite_is_dtls12: bool, // Use X-DTLS12-CipherSuite header
    pub rekey_time: u32,
    pub keepalive: u32,
}

/// Combined DTLS configuration
pub enum DtlsConfig {
    Psk(DtlsParams),
    Legacy(LegacyDtlsParams),
}

/// Build the raw CONNECT response with EXACT header casing
pub fn build_connect_response(
    state: &ServerState,
    dtls_config: Option<&DtlsConfig>,
    assigned_ip: std::net::Ipv4Addr,
) -> String {
    let net_config = &state.config.network;
    let link_mtu = net_config.mtu;
    let data_mtu = link_mtu.saturating_sub(32); // Account for CSTP overhead

    let mut response = String::new();
    response.push_str("HTTP/1.1 200 OK\r\n");

    // Core CSTP headers (EXACT CASE - OpenConnect uses strncmp which is case-sensitive!)
    response.push_str(&format!("X-CSTP-Version: 1\r\n"));
    response.push_str(&format!("X-CSTP-Address: {}\r\n", assigned_ip));

    // Use /32 mask for Point-to-Point link to ensure default route works correctly
    response.push_str(&format!("X-CSTP-Netmask: 255.255.255.255\r\n"));

    // Timeouts and keepalives
    response.push_str("X-CSTP-Lease-Duration: 86400\r\n");
    response.push_str("X-CSTP-Session-Timeout: 0\r\n");
    response.push_str("X-CSTP-Idle-Timeout: 0\r\n");
    response.push_str("X-CSTP-Disconnected-Timeout: 0\r\n");
    response.push_str("X-CSTP-Keepalive: 30\r\n");
    response.push_str("X-CSTP-DPD: 30\r\n");

    // MTU - ocserv sends BOTH Base-MTU and MTU
    response.push_str(&format!("X-CSTP-Base-MTU: {}\r\n", link_mtu));
    response.push_str(&format!("X-CSTP-MTU: {}\r\n", data_mtu));

    // Required flags
    response.push_str("X-CSTP-Tunnel-All-DNS: false\r\n");
    response.push_str("X-CSTP-Keep: true\r\n");
    response.push_str("X-CSTP-TCP-Keepalive: true\r\n");
    response.push_str("X-CSTP-License: accept\r\n");
    response.push_str("X-CSTP-Rekey-Method: new-tunnel\r\n");

    // Add DNS servers
    for dns in &net_config.dns_servers {
        response.push_str(&format!("X-CSTP-DNS: {}\r\n", dns));
    }

    // Add Split Include Routes
    for route in &net_config.split_include {
        response.push_str(&format!("X-CSTP-Split-Include: {}\r\n", route));
    }

    // Add DTLS headers based on mode
    match dtls_config {
        Some(DtlsConfig::Psk(dtls)) => {
            response.push_str(&format!("X-DTLS-Port: {}\r\n", dtls.port));
            response.push_str("X-DTLS-CipherSuite: PSK-NEGOTIATE\r\n");
            response.push_str(&format!("X-DTLS-App-ID: {}\r\n", dtls.app_id));
            response.push_str(&format!("X-DTLS-Rekey-Time: {}\r\n", dtls.rekey_time));
            response.push_str("X-DTLS-Rekey-Method: ssl\r\n");
            response.push_str(&format!("X-DTLS-Keepalive: {}\r\n", dtls.keepalive));
            response.push_str("X-DTLS-DPD: 30\r\n");
            info!("Added DTLS-PSK headers: App-ID={}", dtls.app_id);
        }
        Some(DtlsConfig::Legacy(dtls)) => {
            response.push_str(&format!("X-DTLS-Port: {}\r\n", dtls.port));
            response.push_str(&format!("X-DTLS-Session-ID: {}\r\n", dtls.session_id));

            // Use correct header based on DTLS version
            if dtls.ciphersuite_is_dtls12 {
                response.push_str(&format!("X-DTLS12-CipherSuite: {}\r\n", dtls.ciphersuite));
            } else {
                response.push_str(&format!("X-DTLS-CipherSuite: {}\r\n", dtls.ciphersuite));
            }

            response.push_str(&format!("X-DTLS-Rekey-Time: {}\r\n", dtls.rekey_time));
            response.push_str("X-DTLS-Rekey-Method: ssl\r\n");
            response.push_str(&format!("X-DTLS-Keepalive: {}\r\n", dtls.keepalive));
            response.push_str("X-DTLS-DPD: 30\r\n");
            // For legacy mode, also send MTU
            response.push_str(&format!("X-DTLS-MTU: {}\r\n", data_mtu));
            info!(
                "Added legacy DTLS headers: Session-ID={}, Cipher={}",
                dtls.session_id, dtls.ciphersuite
            );
        }
        None => {}
    }

    // End headers
    response.push_str("\r\n");

    response
}

/// Handle CONNECT request directly on the raw TLS stream
/// Returns true if this was a CONNECT request and was handled
pub async fn handle_connect_raw(
    stream: &mut TlsStream<TcpStream>,
    state: Arc<ServerState>,
    initial_data: &[u8],
) -> Result<bool> {
    // Parse the initial data to check if it's a CONNECT request
    let data_str = String::from_utf8_lossy(initial_data);

    if !data_str.starts_with("CONNECT /CSCOSSLC/tunnel") {
        return Ok(false);
    }

    info!("Detected CONNECT request, handling with raw HTTP response");

    // Parse headers to check for DTLS support
    let mut dtls_config: Option<DtlsConfig> = None;

    // Check if client supports PSK-NEGOTIATE
    let supports_dtls_psk =
        data_str.contains("X-DTLS-CipherSuite") && data_str.contains("PSK-NEGOTIATE");

    if supports_dtls_psk {
        info!("Client supports DTLS with PSK-NEGOTIATE");

        // Generate 32-byte App-ID (session identifier)
        let app_id_bytes: [u8; 32] = rand::random();
        let app_id_hex = hex::encode(&app_id_bytes);

        // Export PSK from TLS session using RFC 5705 exporter
        // Label: "EXPORTER-openconnect-psk", no context, 32 bytes
        let mut psk = [0u8; 32];

        // Access the underlying rustls connection to export keying material
        let (_, tls_conn) = stream.get_ref();
        let exported = tls_conn.export_keying_material(
            &mut psk,
            b"EXPORTER-openconnect-psk",
            None, // No context per protocol spec
        );

        if let Err(e) = exported {
            warn!("Failed to export PSK: {:?}", e);
        } else {
            info!("Exported 32-byte PSK for DTLS session");

            // Get DTLS port from config
            let dtls_port = state.config.server.dtls_port.unwrap_or(8443);

            // Register session in DTLS store
            {
                let mut sessions = state.dtls_sessions.write().unwrap();
                sessions.insert(
                    app_id_hex.clone(),
                    DtlsSessionInfo {
                        psk: psk.to_vec(),
                        tun_tx: None, // Will be set when VpnTunnel starts
                        dtls_signal_tx: None,
                        dtls_out_rx: None,
                    },
                );
                info!("Registered DTLS session with App-ID: {}", app_id_hex);
            }

            dtls_config = Some(DtlsConfig::Psk(DtlsParams {
                port: dtls_port,
                app_id: app_id_hex,
                rekey_time: 86400,
                keepalive: 30,
            }));
        }
    } else {
        debug!("Client does not support DTLS-PSK, TCP-only tunnel");
    }

    // Build and send the response with EXACT case headers
    // Use a temporary IP for this raw handler path (mostly used for testing/legacy)
    let temp_ip = "10.10.0.100".parse().unwrap();
    let response = build_connect_response(&state, dtls_config.as_ref(), temp_ip);
    debug!("Sending raw CONNECT response:\n{}", response);

    stream
        .write_all(response.as_bytes())
        .await
        .context("Failed to write CONNECT response")?;
    stream
        .flush()
        .await
        .context("Failed to flush CONNECT response")?;

    info!("CONNECT response sent, starting VPN tunnel");

    // Now hand off to VPN tunnel
    // This function returns true to indicate CONNECT was handled
    // The caller is responsible for starting the VPN tunnel

    Ok(true)
}
