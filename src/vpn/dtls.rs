//! DTLS Server implementation for OpenConnect VPN
//!
//! Implements DTLS 1.2 with PSK authentication per OpenConnect Protocol v1.2

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result};
use bytes::Bytes;
use foreign_types::ForeignTypeRef;
use openssl::ssl::{SslAcceptor, SslContext, SslMethod, SslVerifyMode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// DTLS session information stored after CONNECT handshake
pub struct DtlsSessionInfo {
    /// Pre-shared key (32 bytes, derived via RFC 5705)
    pub psk: Vec<u8>,
    /// Channel to send packets to the TUN device
    pub tun_tx: Option<mpsc::Sender<Bytes>>,
}

/// Thread-safe store mapping session_id (hex) -> session info
pub type DtlsSessionStore = Arc<RwLock<HashMap<String, DtlsSessionInfo>>>;

/// DTLS packet types (1-byte header inside DTLS record)
pub mod packet_type {
    pub const DATA: u8 = 0x00;
    pub const DPD_REQ: u8 = 0x03;
    pub const DPD_RESP: u8 = 0x04;
    pub const DISCONNECT: u8 = 0x05;
    pub const KEEPALIVE: u8 = 0x07;
    pub const COMPRESSED: u8 = 0x08;
}

/// Main DTLS server
pub struct DtlsServer {
    socket: Arc<UdpSocket>,
    ssl_context: SslContext,
    sessions: DtlsSessionStore,
    /// Map of address -> channel for routing incoming packets
    active_sessions: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    /// Map of ssl_ptr -> session_id (populated before handshake)
    pending_session_ids: Arc<RwLock<HashMap<usize, String>>>,
}

impl DtlsServer {
    /// Create a new DTLS server
    pub async fn new(
        port: u16,
        sessions: DtlsSessionStore,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self> {
        let bind_addr = format!("0.0.0.0:{}", port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .context(format!("Failed to bind UDP socket on {}", bind_addr))?;

        info!("DTLS server listening on UDP {}", bind_addr);

        // Build SSL context for DTLS with both PSK and certificate-based auth
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::dtls())?;

        // Load server certificate and private key for legacy DTLS (AnyConnect)
        builder
            .set_certificate_chain_file(cert_path)
            .context("Failed to load DTLS certificate")?;
        builder
            .set_private_key_file(key_path, openssl::ssl::SslFiletype::PEM)
            .context("Failed to load DTLS private key")?;

        // Configure cipher list to support both legacy and PSK modes
        // Include ECDHE-RSA, DHE-RSA, and AES ciphers for AnyConnect compatibility
        builder.set_cipher_list(
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:\
             ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:\
             DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:\
             DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:\
             AES256-GCM-SHA384:AES128-GCM-SHA256:\
             AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:\
             PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256",
        )?;

        // Don't verify client certificates
        builder.set_verify(SslVerifyMode::NONE);

        // Clone sessions for PSK callback
        let sessions_clone = sessions.clone();
        let pending_ids = Arc::new(RwLock::new(HashMap::<usize, String>::new()));
        let pending_ids_clone = pending_ids.clone();

        // PSK callback - per ocserv, we ignore identity and lookup by pre-stored session_id
        builder.set_psk_server_callback(move |ssl, _identity, psk_buf| {
            let ssl_ptr = ssl.as_ptr() as usize;

            // Get the session_id that was stored before handshake started
            let session_id = {
                let map = pending_ids_clone.read().unwrap();
                map.get(&ssl_ptr).cloned()
            };

            if let Some(sid) = session_id {
                let store = sessions_clone.read().unwrap();
                if let Some(info) = store.get(&sid) {
                    let key = &info.psk;
                    if key.len() <= psk_buf.len() {
                        psk_buf[..key.len()].copy_from_slice(key);
                        info!("PSK callback: found key for session {}", sid);
                        return Ok(key.len());
                    } else {
                        error!("PSK buffer too small");
                    }
                } else {
                    debug!("PSK callback: no session found for id {}", sid);
                }
            } else {
                debug!(
                    "PSK callback: no pending session_id for ssl_ptr {}",
                    ssl_ptr
                );
            }

            Ok(0) // Continue with certificate-based auth
        });

        let context = builder.build().into_context();

        Ok(Self {
            socket: Arc::new(socket),
            ssl_context: context,
            sessions,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_session_ids: pending_ids,
        })
    }

    /// Run the DTLS server main loop
    pub async fn run(self) -> Result<()> {
        let mut buf = [0u8; 4096];

        loop {
            // Receive UDP packet
            let (n, addr) = self.socket.recv_from(&mut buf).await?;
            let packet = Bytes::copy_from_slice(&buf[..n]);

            // Check if we have an active session for this address
            let has_session = {
                let sessions = self.active_sessions.read().unwrap();
                sessions.contains_key(&addr)
            };

            if has_session {
                // Forward to existing session
                let tx = {
                    let sessions = self.active_sessions.read().unwrap();
                    sessions.get(&addr).cloned()
                };
                if let Some(tx) = tx {
                    let _ = tx.send(packet).await;
                }
            } else {
                // New session - try to extract session_id from ClientHello
                let session_id = self.extract_session_id_from_client_hello(&packet);

                if let Some(sid) = session_id {
                    info!("New DTLS session from {} with session_id {}", addr, sid);

                    // Verify we have a PSK for this session
                    let has_psk = {
                        let store = self.sessions.read().unwrap();
                        store.contains_key(&sid)
                    };

                    if has_psk {
                        // Create channel for this session
                        let (tx, rx) = mpsc::channel::<Bytes>(100);

                        // Store in active sessions
                        {
                            let mut sessions = self.active_sessions.write().unwrap();
                            sessions.insert(addr, tx.clone());
                        }

                        // Send the initial packet
                        let _ = tx.send(packet).await;

                        // Spawn session handler
                        let socket = self.socket.clone();
                        let ctx = self.ssl_context.clone();
                        let sessions_store = self.sessions.clone();
                        let active_sessions = self.active_sessions.clone();
                        let pending_ids = self.pending_session_ids.clone();
                        let sid_clone = sid.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_dtls_session(
                                socket,
                                addr,
                                rx,
                                ctx,
                                sessions_store,
                                active_sessions,
                                pending_ids,
                                sid_clone,
                            )
                            .await
                            {
                                warn!("DTLS session {} error: {}", addr, e);
                            }
                        });
                    } else {
                        warn!("No PSK found for session_id {}, rejecting", sid);
                    }
                } else {
                    debug!("Could not extract session_id from packet, ignoring");
                }
            }
        }
    }

    /// Extract session_id from DTLS ClientHello
    ///
    /// DTLS 1.2 ClientHello structure:
    /// [0]: Content Type (0x16 = Handshake)
    /// [1-2]: Version
    /// [3-4]: Epoch
    /// [5-10]: Sequence Number (6 bytes)
    /// [11-12]: Length
    /// [13]: Handshake Type (0x01 = ClientHello)
    /// [14-16]: Length (24-bit)
    /// [17-18]: Message Seq
    /// [19-21]: Fragment Offset (24-bit)
    /// [22-24]: Fragment Length (24-bit)
    /// [25-26]: Client Version
    /// [27-58]: Random (32 bytes)
    /// [59]: Session ID Length
    /// [60..]: Session ID bytes
    fn extract_session_id_from_client_hello(&self, packet: &[u8]) -> Option<String> {
        // Minimum size check
        if packet.len() < 60 {
            return None;
        }

        // Check content type (0x16 = Handshake)
        if packet[0] != 0x16 {
            return None;
        }

        // Check handshake type (0x01 = ClientHello)
        if packet.len() > 13 && packet[13] != 0x01 {
            return None;
        }

        // Get session ID length at offset 59
        if packet.len() <= 59 {
            return None;
        }
        let session_id_len = packet[59] as usize;

        if session_id_len == 0 {
            debug!("ClientHello has empty session_id");
            return None;
        }

        // Extract session ID
        let session_id_start = 60;
        if packet.len() < session_id_start + session_id_len {
            return None;
        }

        let session_id_bytes = &packet[session_id_start..session_id_start + session_id_len];
        let session_id_hex = hex::encode(session_id_bytes);

        debug!(
            "Extracted session_id from ClientHello: {} (len={})",
            session_id_hex, session_id_len
        );
        Some(session_id_hex)
    }
}

/// Virtual socket that adapts mpsc channel to AsyncRead/AsyncWrite for tokio-openssl
struct VirtualSocket {
    rx: mpsc::Receiver<Bytes>,
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    read_buf: Bytes,
}

impl AsyncRead for VirtualSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have leftover data, use it first
        if !self.read_buf.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), self.read_buf.len());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf = self.read_buf.slice(to_copy..);
            return Poll::Ready(Ok(()));
        }

        // Try to receive from channel
        match Pin::new(&mut self.rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf = data.slice(to_copy..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // Channel closed
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for VirtualSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.socket.poll_send_to(cx, buf, self.addr) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Handle a single DTLS session
async fn handle_dtls_session(
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    rx: mpsc::Receiver<Bytes>,
    ctx: SslContext,
    store: DtlsSessionStore,
    active_sessions: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    pending_ids: Arc<RwLock<HashMap<usize, String>>>,
    session_id: String,
) -> Result<()> {
    use openssl::ssl::Ssl;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Cleanup on exit
    struct SessionGuard {
        addr: SocketAddr,
        active_sessions: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
        pending_ids: Arc<RwLock<HashMap<usize, String>>>,
        ssl_ptr: usize,
    }
    impl Drop for SessionGuard {
        fn drop(&mut self) {
            self.active_sessions.write().unwrap().remove(&self.addr);
            self.pending_ids.write().unwrap().remove(&self.ssl_ptr);
            info!("DTLS session {} cleaned up", self.addr);
        }
    }

    // Create virtual socket
    let io = VirtualSocket {
        rx,
        socket: socket.clone(),
        addr,
        read_buf: Bytes::new(),
    };

    // Create SSL object
    let ssl = Ssl::new(&ctx)?;
    let ssl_ptr = ssl.as_ptr() as usize;

    // Store session_id for PSK callback BEFORE handshake
    {
        let mut ids = pending_ids.write().unwrap();
        ids.insert(ssl_ptr, session_id.clone());
    }

    let _guard = SessionGuard {
        addr,
        active_sessions: active_sessions.clone(),
        pending_ids: pending_ids.clone(),
        ssl_ptr,
    };

    // Create SSL stream and perform handshake
    let mut stream = tokio_openssl::SslStream::new(ssl, io)?;

    info!("Starting DTLS handshake with {}", addr);
    Pin::new(&mut stream).accept().await?;
    info!("DTLS handshake completed with {}", addr);

    // Get TUN sender for this session
    let tun_tx = {
        let sessions = store.read().unwrap();
        sessions
            .get(&session_id)
            .and_then(|info| info.tun_tx.clone())
    };

    let tun_tx = match tun_tx {
        Some(tx) => tx,
        None => {
            warn!("No TUN sender for session {}", session_id);
            return Ok(());
        }
    };

    // Main data loop
    let mut buf = [0u8; 4096];

    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => {
                info!("DTLS session {} closed (EOF)", addr);
                break;
            }
            Ok(n) => n,
            Err(e) => {
                warn!("DTLS read error from {}: {}", addr, e);
                break;
            }
        };

        if n == 0 {
            continue;
        }

        // Handle packet based on type (1-byte header)
        let pkt_type = buf[0];

        match pkt_type {
            packet_type::DATA => {
                // Strip 1-byte header and forward to TUN
                let data = Bytes::copy_from_slice(&buf[1..n]);
                if tun_tx.send(data).await.is_err() {
                    warn!("TUN channel closed for session {}", addr);
                    break;
                }
            }
            packet_type::DPD_REQ => {
                // Respond with DPD-RESP
                debug!("Received DPD-REQ from {}, sending DPD-RESP", addr);
                let resp = [packet_type::DPD_RESP];
                if let Err(e) = stream.write_all(&resp).await {
                    warn!("Failed to send DPD-RESP to {}: {}", addr, e);
                }
            }
            packet_type::KEEPALIVE => {
                // Respond with KEEPALIVE
                debug!("Received KEEPALIVE from {}", addr);
                let resp = [packet_type::KEEPALIVE];
                if let Err(e) = stream.write_all(&resp).await {
                    warn!("Failed to send KEEPALIVE to {}: {}", addr, e);
                }
            }
            packet_type::DISCONNECT => {
                info!("Received DISCONNECT from {}", addr);
                break;
            }
            _ => {
                debug!("Unknown packet type 0x{:02x} from {}", pkt_type, addr);
            }
        }
    }

    Ok(())
}
