use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::config::Config;
use crate::http::handlers::{handle_request, ServerState};

pub struct HttpServer {
    addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    config: Arc<Config>,
}

impl HttpServer {
    pub fn new(addr: SocketAddr, tls_acceptor: TlsAcceptor, config: Arc<Config>) -> Self {
        Self {
            addr,
            tls_acceptor,
            config,
        }
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("HTTP server listening on {}", self.addr);

        // Create shared server state
        let state = Arc::new(ServerState::new(self.config.clone()));

        loop {
            let (tcp_stream, remote_addr) = listener.accept().await?;
            let tls_acceptor = self.tls_acceptor.clone();
            let state = state.clone();

            tokio::spawn(async move {
                match tls_acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        info!("TLS connection established from {}", remote_addr);

                        // Wrap TLS stream in TokioIo for Hyper 1.0 compatibility
                        let io = TokioIo::new(tls_stream);

                        let svc_state = state.clone();
                        let service = service_fn(move |req| {
                            let state = svc_state.clone();
                            async move { handle_request(req, state).await }
                        });

                        if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                            error!("Error handling connection from {}: {}", remote_addr, e);
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
