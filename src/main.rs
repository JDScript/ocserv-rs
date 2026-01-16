use anyhow::Result;
use ocserv_rs::{create_tls_acceptor, load_tls_config, HttpServer};
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting ocserv-rs VPN Server");

    // For testing, we'll use dummy cert/key paths
    // In production, these would come from config
    let cert_path = "server.crt";
    let key_path = "server.key";

    // Check if cert files exist, if not, provide helpful message
    if !std::path::Path::new(cert_path).exists() {
        eprintln!("Certificate file not found: {}", cert_path);
        eprintln!("For testing Phase 2, generate a self-signed certificate:");
        eprintln!("  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'");
        return Ok(());
    }

    // Load TLS configuration
    let tls_config = load_tls_config(cert_path, key_path)?;
    let tls_acceptor = create_tls_acceptor(tls_config);

    // Start HTTP server
    let addr: SocketAddr = "0.0.0.0:8443".parse()?;
    let server = HttpServer::new(addr, tls_acceptor);

    info!("Server ready - Phase 2 HTTP/XML layer active");
    server.run().await?;

    Ok(())
}
