use anyhow::{Context, Result};
use clap::Parser;
use ocserv_rs::{create_tls_acceptor, load_tls_config, Config, HttpServer};
use sha1::Digest;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!("Starting ocserv-rs VPN Server");

    // Load configuration
    let config = if args.config.exists() {
        info!("Loading configuration from {:?}", args.config);
        Config::from_file(&args.config)?
    } else {
        info!("Config file not found, using default configuration for testing");
        Config::default()
    };

    // Wrap in Arc for sharing
    let config = Arc::new(config);

    // Check if cert files exist
    if !std::path::Path::new(&config.server.cert_path).exists() {
        eprintln!("Certificate file not found: {}", config.server.cert_path);
        eprintln!("For testing, you can generate a self-signed certificate:");
        eprintln!("  openssl req -x509 -newkey rsa:4096 -keyout {} -out {} -days 365 -nodes -subj '/CN=localhost'", 
            config.server.key_path, config.server.cert_path);
        // Continue anyway? No, load_tls_config will fail.
    }

    // Load TLS configuration from config paths
    let tls_config = load_tls_config(&config.server.cert_path, &config.server.key_path)
        .context("Failed to load TLS configuration")?;
    let tls_acceptor = create_tls_acceptor(tls_config);

    // Start HTTP server using address from config
    let addr: SocketAddr = config
        .server
        .listen
        .parse()
        .context("Invalid listen address in config")?;

    // Calculate certificate hash for AnyConnect compatibility (webvpnc cookie)
    let cert_bytes = std::fs::read(&config.server.cert_path)
        .context("Failed to read certificate for hash calculation")?;

    // Parse PEM to find the first certificate (DER)
    // ocserv uses the hash of the DER encoded certificate
    let certs = rustls_pemfile::certs(&mut &*cert_bytes)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;

    let first_cert = certs.first().context("No certificate found in file")?;

    let mut hasher = sha1::Sha1::new();
    hasher.update(first_cert.as_ref());
    let hash = hasher.finalize();
    let cert_hash = hex::encode(hash);

    info!("Calculated certificate SHA1 hash: {}", cert_hash);

    let server = HttpServer::new(addr, tls_acceptor, config, cert_hash);

    info!("Server ready - HTTP/XML layer active on {}", addr);
    server.run().await?;

    Ok(())
}
