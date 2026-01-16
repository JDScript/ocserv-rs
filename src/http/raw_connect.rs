use crate::http::handlers::ServerState;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info};

/// Build the raw CONNECT response with EXACT header casing
pub fn build_connect_response(state: &ServerState) -> String {
    let net_config = &state.config.network;
    let dummy_ip = "10.10.0.100";
    let link_mtu = net_config.mtu;
    let data_mtu = link_mtu.saturating_sub(32); // Account for CSTP overhead

    let mut response = String::new();
    response.push_str("HTTP/1.1 200 OK\r\n");

    // Core CSTP headers (EXACT CASE - OpenConnect uses strncmp which is case-sensitive!)
    response.push_str(&format!("X-CSTP-Version: 1\r\n"));
    response.push_str(&format!("X-CSTP-Address: {}\r\n", dummy_ip));
    response.push_str(&format!("X-CSTP-Netmask: 255.255.255.0\r\n"));

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

    // Read until we get the full headers (double CRLF)
    // For now, assume initial_data contains enough - in production we'd buffer more

    // Build and send the response with EXACT case headers
    let response = build_connect_response(&state);
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
    // We need to wrap the stream for VpnTunnel
    // VpnTunnel expects something implementing tokio AsyncRead/AsyncWrite
    // TlsStream<TcpStream> already implements these!

    // Actually we need to take ownership of the stream here
    // This is tricky because we have a mutable reference...
    // We'll need to refactor the caller to pass ownership

    Ok(true)
}
