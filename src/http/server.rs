use anyhow::Result;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::http::handlers::{handle_request, ServerState};

pub struct HttpServer {
    addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    state: Arc<ServerState>,
}

impl HttpServer {
    pub fn new(addr: SocketAddr, tls_acceptor: TlsAcceptor) -> Self {
        Self {
            addr,
            tls_acceptor,
            state: Arc::new(ServerState::new()),
        }
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("HTTP server listening on {}", self.addr);

        let tls_acceptor = Arc::new(self.tls_acceptor);
        let state = self.state;

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let tls_acceptor = tls_acceptor.clone();
            let state = state.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_connection(stream, peer_addr, tls_acceptor, state).await
                {
                    error!("Error handling connection from {}: {}", peer_addr, e);
                }
            });
        }
    }

    async fn handle_connection(
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        tls_acceptor: Arc<TlsAcceptor>,
        state: Arc<ServerState>,
    ) -> Result<()> {
        // Perform TLS handshake
        let tls_stream = tls_acceptor.accept(stream).await?;
        info!("TLS connection established from {}", peer_addr);

        let io = TokioIo::new(tls_stream);

        // Create HTTP/1.1 connection
        let service = service_fn(move |req: Request<Incoming>| {
            let state = state.clone();
            async move { handle_request(req, state).await }
        });

        // Serve HTTP requests over the TLS connection
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await?;

        Ok(())
    }
}
