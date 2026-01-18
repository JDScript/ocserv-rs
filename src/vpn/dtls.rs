//! DTLS Server implementation for OpenConnect VPN
//!
//! Implements DTLS 1.2 with PSK authentication per OpenConnect Protocol v1.2

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use bytes::Bytes;
use foreign_types::ForeignTypeRef;
use openssl::pkey::Id;
use openssl::ssl::{SslAcceptor, SslContext, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::vpn::dtls_engine::{DtlsEngine, DtlsMode};

/// Detect certificate type and return appropriate DTLS cipher suite.
fn detect_cipher_suite_for_cert(cert_path: &str) -> Result<&'static str> {
    let cert_pem = std::fs::read(cert_path)
        .context(format!("Failed to read certificate file: {}", cert_path))?;

    let cert = X509::from_pem(&cert_pem).context("Failed to parse certificate PEM")?;

    let pubkey = cert
        .public_key()
        .context("Failed to extract public key from certificate")?;

    match pubkey.id() {
        Id::EC => {
            info!("Detected EC (ECDSA) certificate - using ECDHE-ECDSA cipher suites");
            Ok(
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:\
                ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:\
                PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256",
            )
        }
        Id::RSA => {
            info!("Detected RSA certificate - using ECDHE-RSA/DHE-RSA cipher suites");
            Ok("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:\
                ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:\
                DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:\
                PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256")
        }
        other => {
            warn!(
                "Unknown certificate key type {:?} - using broad cipher suite",
                other
            );
            Ok("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:\
                PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256")
        }
    }
}

/// DTLS session information stored after CONNECT handshake
/// Updated to support DtlsEngine architecture
pub struct DtlsSessionInfo {
    /// Pre-shared key (32 bytes, derived via RFC 5705)
    pub psk: Vec<u8>,
    /// Channel to send Encrpyted packets to VpnTunnel (dtls_rx)
    pub tun_tx: Option<mpsc::Sender<Bytes>>,
    /// Channel to signal VpnTunnel that DTLS is initialized (Engine, Socket, Addr)
    pub dtls_signal_tx: Option<mpsc::Sender<(DtlsEngine, Arc<UdpSocket>, SocketAddr)>>,
}

/// Thread-safe store mapping session_id (hex) -> session info
pub type DtlsSessionStore = Arc<RwLock<HashMap<String, DtlsSessionInfo>>>;

/// DTLS packet types (1-byte header inside DTLS record - handled by DtlsEngine/VpnTunnel now)
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
    /// Map of Address -> Channel to VpnTunnel (for forwarding ENCRYPTED packets)
    active_sessions: Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>,
    /// Map of ssl_ptr -> session_id (populated before handshake)
    pending_session_ids: Arc<RwLock<HashMap<usize, String>>>,
    // Configurable performance parameters
    buffer_size: usize,
}

impl DtlsServer {
    /// Create a new DTLS server
    pub async fn new(
        port: u16,
        sessions: DtlsSessionStore,
        cert_path: &str,
        key_path: &str,
        buffer_size: usize,
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

        // Detect certificate type and configure appropriate cipher suite
        let cipher_suite = detect_cipher_suite_for_cert(cert_path)
            .context("Failed to detect cipher suite for certificate")?;

        builder.set_cipher_list(cipher_suite)?;

        // Don't verify client certificates
        builder.set_verify(SslVerifyMode::NONE);

        // Clone sessions for PSK callback
        let sessions_clone = sessions.clone();
        let pending_ids = Arc::new(RwLock::new(HashMap::<usize, String>::new()));
        let pending_ids_clone = pending_ids.clone();

        // PSK callback - per ocserv, we ignore identity and lookup by pre-stored session_id
        builder.set_psk_server_callback(move |ssl, _identity, psk_buf| {
            let ssl_ptr = ssl.as_ptr() as usize;

            let session_id = {
                let map = pending_ids_clone.read().unwrap();
                map.get(&ssl_ptr).cloned()
            };

            if let Some(sid) = session_id {
                let store = sessions_clone.read().unwrap();
                if let Some(info) = store.get(&sid) {
                    let key = &info.psk;
                    if key.len() <= psk_buf.len() {
                        // copy_from_slice is nightly on slice? No, standard.
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
            buffer_size,
        })
    }

    /// Run the DTLS server main loop
    pub async fn run(self) -> Result<()> {
        // Use configurable buffer size
        let mut buf = vec![0u8; self.buffer_size];
        let socket = self.socket.clone();

        loop {
            // Receive UDP packet
            let (n, addr) = socket.recv_from(&mut buf).await?;
            let packet = Bytes::copy_from_slice(&buf[..n]);

            // Check if we have an active session for this address
            let tx = {
                let sessions = self.active_sessions.read().unwrap();
                sessions.get(&addr).cloned()
            };

            if let Some(tx) = tx {
                // Forward (Encrypted) to VpnTunnel
                if tx.try_send(packet).is_err() {
                    debug!("DTLS session queue full (or closed), dropping packet");
                    // If closed, maybe remove from active_sessions?
                    if tx.is_closed() {
                        warn!("Channel closed for {}, removing session", addr);
                        self.active_sessions.write().unwrap().remove(&addr);
                    }
                }
            } else {
                // New session - try to extract session_id from ClientHello
                let session_id = self.extract_session_id_from_client_hello(&packet);

                if let Some(sid) = session_id {
                    info!("New DTLS session from {} with session_id {}", addr, sid);

                    // Lookup Session
                    let (tun_tx, dtls_signal_tx) = {
                        let store = self.sessions.read().unwrap();
                        if let Some(info) = store.get(&sid) {
                            (info.tun_tx.clone(), info.dtls_signal_tx.clone())
                        } else {
                            (None, None)
                        }
                    };

                    if let (Some(tun_tx), Some(signal_tx)) = (tun_tx, dtls_signal_tx) {
                        // Create DtlsEngine
                        match DtlsEngine::new(&self.ssl_context, DtlsMode::Server) {
                            Ok(mut engine) => {
                                // Register SSL pointer for PSK callback
                                let ptr = engine.ssl_ptr();
                                {
                                    let mut ids = self.pending_session_ids.write().unwrap();
                                    ids.insert(ptr, sid.clone());
                                }

                                // Attach Cleanup Guard
                                struct SessionGuard {
                                    ptr: usize,
                                    // We use Weak or Arc? Arc is fine as DtlsServer holds Arc.
                                    // But pending_session_ids is valid as long as DtlsServer is valid.
                                    // If DtlsServer drops, map drops. Guard dropping might try to access map?
                                    // Yes, guard should hold Arc.
                                    pending_ids: Arc<RwLock<HashMap<usize, String>>>,
                                }

                                impl Drop for SessionGuard {
                                    fn drop(&mut self) {
                                        if let Ok(mut map) = self.pending_ids.write() {
                                            map.remove(&self.ptr);
                                            // debug!("Cleaned up pending session_id for ptr {}", self.ptr);
                                        }
                                    }
                                }

                                let guard = SessionGuard {
                                    ptr,
                                    pending_ids: self.pending_session_ids.clone(),
                                };
                                engine.set_user_data(Box::new(guard));

                                // Add to active sessions
                                {
                                    let mut sessions = self.active_sessions.write().unwrap();
                                    sessions.insert(addr, tun_tx.clone());
                                }

                                // Send Engine to VpnTunnel
                                if signal_tx
                                    .send((engine, socket.clone(), addr))
                                    .await
                                    .is_err()
                                {
                                    warn!("Failed to signal VpnTunnel for DTLS session {}", sid);
                                    self.active_sessions.write().unwrap().remove(&addr);
                                } else {
                                    // Forward the ClientHello packet for processing
                                    if tun_tx.send(packet).await.is_err() {
                                        warn!("VpnTunnel channel closed immediately after signal");
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to create DtlsEngine: {}", e);
                            }
                        }
                    } else {
                        warn!("Session {} found but missing channels", sid);
                    }
                } else {
                    debug!("Could not extract session_id from packet, ignoring");
                }
            }
        }
    }

    /// Extract session_id from DTLS ClientHello
    fn extract_session_id_from_client_hello(&self, packet: &[u8]) -> Option<String> {
        // Minimum size check (header + random...)
        if packet.len() < 60 {
            return None;
        }

        // Check content type (0x16 = Handshake)
        if packet[0] != 0x16 {
            return None;
        }

        // Check handshake type (0x01 = ClientHello)
        // Record Header (13 bytes) + Handshake Header (4 bytes)
        // packet[13] is Handshake Type
        if packet.len() > 13 && packet[13] != 0x01 {
            return None;
        }

        // Get session ID length at offset 59
        // 13 (Rec) + 4 (Hs) + 2 (Ver) + 32 (Rand) = 51?
        // Let's trace carefully:
        // Rec: 0..13
        // Hs: 13..?
        //   Type: 13 (1 byte)
        //   Len: 14..17 (3 bytes)
        //   MsgSeq: 17..19 (2 bytes)
        //   FragOff: 19..22 (3 bytes)
        //   FragLen: 22..25 (3 bytes)
        // ClientVer: 25..27 (2 bytes)
        // Random: 27..59 (32 bytes)
        // SessionID Len: 59 (1 byte)
        // CORRECT.

        if packet.len() <= 59 {
            return None;
        }
        let session_id_len = packet[59] as usize;

        if session_id_len == 0 {
            // debug!("ClientHello has empty session_id");
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
