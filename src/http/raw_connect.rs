use crate::http::handlers::ServerState;
use tracing::info;

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
