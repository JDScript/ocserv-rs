use crate::vpn::cstp::{CstpPacket, PacketType, CSTP_HEADER_LEN};
use crate::vpn::dtls_engine::DtlsEngine;
use crate::vpn::tun_device::TunDevice;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

pub struct VpnTunnel<IO> {
    io: IO,
    tun: TunDevice,
    /// Receiver for Encrypted DTLS packets (from DtlsServer)
    dtls_rx: Option<mpsc::Receiver<Bytes>>,
    /// Receiver for DTLS engine and socket (Signal)
    dtls_signal_rx:
        Option<mpsc::Receiver<(DtlsEngine, Arc<tokio::net::UdpSocket>, std::net::SocketAddr)>>,
}

impl<IO> VpnTunnel<IO>
where
    IO: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    pub fn new(io: IO, tun: TunDevice) -> Self {
        Self {
            io,
            tun,
            dtls_rx: None,
            dtls_signal_rx: None,
        }
    }

    /// Create a new tunnel with DTLS support
    pub fn with_dtls(
        io: IO,
        tun: TunDevice,
        dtls_rx: mpsc::Receiver<Bytes>,
        dtls_signal_rx: mpsc::Receiver<(
            DtlsEngine,
            Arc<tokio::net::UdpSocket>,
            std::net::SocketAddr,
        )>,
    ) -> Self {
        Self {
            io,
            tun,
            dtls_rx: Some(dtls_rx),
            dtls_signal_rx: Some(dtls_signal_rx),
        }
    }

    pub async fn run(self) -> Result<()> {
        info!("VPN Tunnel loop started for interface: {}", self.tun.name());

        let (mut tls_r, mut tls_w) = tokio::io::split(self.io);
        let (mut tun_r, mut tun_w) = self.tun.split();

        // Shared state for DTLS
        // We use a regular std::sync::Mutex because DtlsEngine operations are non-blocking (memory only).
        // This avoids async Mutex overhead in the hot path.
        struct DtlsState {
            engine: DtlsEngine,
            socket: Arc<tokio::net::UdpSocket>,
            addr: std::net::SocketAddr,
        }
        let dtls_state: Arc<Mutex<Option<DtlsState>>> = Arc::new(Mutex::new(None));
        let use_dtls = Arc::new(AtomicBool::new(false));

        // INTERNAL CHANNELS:
        // Control Packets: Task 2 (TLS Read) -> Task 1 (TLS Write)
        let (control_tx, mut control_rx) = mpsc::channel::<Bytes>(64);

        // SIGNAL MONITOR TASK
        if let Some(mut signal_rx) = self.dtls_signal_rx {
            let use_dtls_signal = use_dtls.clone();
            let dtls_state_signal = dtls_state.clone();

            tokio::spawn(async move {
                while let Some((engine, socket, addr)) = signal_rx.recv().await {
                    info!("VPN Tunnel: DTLS enabled via signal for {}", addr);
                    {
                        let mut state = dtls_state_signal.lock().unwrap();
                        *state = Some(DtlsState {
                            engine,
                            socket,
                            addr,
                        });
                    }
                    use_dtls_signal.store(true, Ordering::Relaxed);
                }
                use_dtls_signal.store(false, Ordering::Relaxed);
            });
        }

        // TASK 1: TUN Reader & TLS Writer (+ Incoming Control Packets + DTLS Egress)
        let use_dtls_t1 = use_dtls.clone();
        let dtls_state_t1 = dtls_state.clone();

        let task1 = tokio::spawn(async move {
            let mut tun_buf = vec![0u8; 65535]; // Max IP packet
            let mut tls_batch = BytesMut::with_capacity(65535);

            loop {
                tokio::select! {
                     // Priority 1: Control Packets (from Other Task)
                     res = control_rx.recv() => {
                         match res {
                             Some(msg) => {
                                 // Flush existing batch first (if any - though we disabled batching)
                                 if !tls_batch.is_empty() {
                                     if let Err(e) = tls_w.write_all(&tls_batch).await {
                                         error!("TLS write error (pre-control): {}", e);
                                         break;
                                     }
                                      if let Err(e) = tls_w.flush().await {
                                         error!("TLS flush error (pre-control): {}", e);
                                         break;
                                     }
                                     tls_batch.clear();
                                 }

                                 if let Err(e) = tls_w.write_all(&msg).await {
                                     error!("TLS write error (control): {}", e);
                                     break;
                                 }
                                  if let Err(e) = tls_w.flush().await {
                                     error!("TLS flush error (control): {}", e);
                                     break;
                                 }
                             }
                             None => break,
                         }
                     }

                     // Priority 2: TUN Read
                     // Optimization: Read into offset 1 to allow prepending 0x00 (DATA) header without allocation
                     res = tun_r.read(&mut tun_buf[1..]) => {
                         match res {
                             Ok(0) => break, // EOF
                             Ok(n) => {
                                 // Add 1-byte header 0x00 (DATA)
                                 tun_buf[0] = 0x00;
                                 let packet_with_header = &tun_buf[0..n+1];
                                 let payload_only = &tun_buf[1..n+1]; // For TLS fallback

                                 // OPTIMIZATION: DTLS Fast Path
                                 let mut sent_via_dtls = false;
                                 if use_dtls_t1.load(Ordering::Relaxed) {
                                     // Scope the lock to extract data synchronously
                                     let dtls_send_info = {
                                         if let Ok(mut guard) = dtls_state_t1.lock() {
                                             if let Some(state) = guard.as_mut() {
                                                 // Feed packet WITH HEADER
                                                 if state.engine.feed_decrypted(packet_with_header).is_ok() {
                                                     if let Ok(Some(encrypted)) = state.engine.extract_outgoing() {
                                                         Some((encrypted, state.socket.clone(), state.addr))
                                                     } else {
                                                         None
                                                     }
                                                 } else {
                                                     None
                                                 }
                                             } else {
                                                 None
                                             }
                                         } else {
                                             None
                                         }
                                     };

                                     if let Some((encrypted, sock, target)) = dtls_send_info {
                                         // Send async OUTSIDE the lock
                                         if let Err(_e) = sock.send_to(&encrypted, target).await {
                                             // warn!("DTLS send error: {}", _e);
                                         } else {
                                             sent_via_dtls = true;
                                         }
                                     }
                                 }

                                 if !sent_via_dtls {
                                     // TLS Path: Zero-Copy Encode into Buffer
                                     // reusing tls_batch as temp buffer (disabled batching)
                                     // Note: TLS framing expects just the IP payload, acts as transport.
                                     // CstpPacket::write_packet wraps it.
                                     CstpPacket::write_packet(PacketType::Data, payload_only, &mut tls_batch);

                                     if let Err(e) = tls_w.write_all(&tls_batch).await {
                                         error!("TLS write error: {}", e);
                                         break;
                                     }
                                     if let Err(e) = tls_w.flush().await { // Explict flush
                                         error!("TLS flush error: {}", e);
                                         break;
                                     }
                                     tls_batch.clear();
                                 }
                             }
                             Err(e) => {
                                 error!("TUN read error: {}", e);
                                 break;
                             }
                         }
                     }
                }
            }
        });

        // TASK 2: TLS Reader & DTLS Ingress -> TUN Writer
        let mut dtls_rx = self.dtls_rx; // Option<Receiver>
        let dtls_state_t2 = dtls_state.clone();

        let task2 = tokio::spawn(async move {
            let mut tls_in_buf = BytesMut::with_capacity(65535);

            loop {
                tokio::select! {
                    // 1. Encrypted DTLS Packet (Ingress)
                    // Only poll if we have a receiver
                    res = async {
                        match &mut dtls_rx {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending().await,
                        }
                    }, if dtls_rx.is_some() => {
                        match res {
                            Some(encrypted) => {
                                // Decrypt using DtlsEngine
                                let mut to_write_tun = Vec::new();
                                let mut to_send_socket = Vec::new(); // Handshake replies
                                let mut sock_info: Option<(Arc<tokio::net::UdpSocket>, std::net::SocketAddr)> = None;

                                {
                                    if let Ok(mut guard) = dtls_state_t2.lock() {
                                        if let Some(state) = guard.as_mut() {
                                            match state.engine.feed_encrypted(&encrypted) {
                                                Ok(decrypted_list) => {
                                                    for packet in decrypted_list {
                                                        // Handle 1-byte Header
                                                        if packet.is_empty() { continue; }
                                                        let pkt_type = packet[0];

                                                        match pkt_type {
                                                            0x00 => { // DATA
                                                                // packet[0] is header, [1..] is payload
                                                                if packet.len() > 1 {
                                                                    to_write_tun.push(packet[1..].to_vec());
                                                                }
                                                            },
                                                            0x03 => { // DPD_REQ -> Send DPD_RESP (0x04)
                                                                // We can write directly to engine here (it handles encryption)
                                                                let _ = state.engine.feed_decrypted(&[0x04]);
                                                            },
                                                            0x07 => { // KEEPALIVE -> Respond with KEEPALIVE (0x07) or ignore
                                                                // ocserv usually echoes keepalives or sends dummy
                                                                let _ = state.engine.feed_decrypted(&[0x07]);
                                                            },
                                                            0x05 => { // DISCONNECT
                                                                info!("Received DTLS DISCONNECT");
                                                            },
                                                            _ => {
                                                                debug!("RX DTLS Unknown Type: 0x{:02x}", pkt_type);
                                                            }
                                                        }
                                                    }
                                                },
                                                Err(e) => {
                                                     error!("DTLS feed_encrypted failed: {}", e);
                                                }
                                            }
                                            // Check for outgoing (Handshake replies/Control/DPD RESP)
                                            if let Ok(Some(outgoing)) = state.engine.extract_outgoing() {
                                                to_send_socket = outgoing;
                                                sock_info = Some((state.socket.clone(), state.addr));
                                            }
                                        }
                                    }
                                }

                                // Write decrypted to TUN
                                for packet in to_write_tun {
                                    if let Err(e) = tun_w.write_all(&packet).await {
                                        error!("TUN write error (DTLS): {}", e);
                                        return; // Fatal
                                    }
                                }

                                // Send handshake replies if any
                                if !to_send_socket.is_empty() {
                                    if let Some((sock, target)) = sock_info {
                                        let _ = sock.send_to(&to_send_socket, target).await;
                                    }
                                }
                            }
                            None => {
                                dtls_rx = None; // Channel closed
                            }
                        }
                    }

                    // 2. TLS Read
                    res = tls_r.read_buf(&mut tls_in_buf) => {
                        match res {
                            Ok(0) => {
                                info!("TLS connection closed (EOF)");
                                break;
                            }
                            Ok(_n) => {
                                // Process multiple packets in buffer
                                loop {
                                    if tls_in_buf.len() < CSTP_HEADER_LEN {
                                        break; // Need more data
                                    }

                                    // Parse Header (Zero Copy check)
                                    // CSTP Header: Magic(3) + Type(1) + Len(2).. actually depends on version but standard is:
                                    // MAGIC: "STF\x01" (4 bytes)
                                    // Len: u16 (2 bytes)
                                    // Type: u16/u8? CstpPacket code says: Header is 8 bytes.
                                    // MAGIC(4) + Len(2) + Type(1) + Pad(1)

                                    let body_len = u16::from_be_bytes([tls_in_buf[4], tls_in_buf[5]]) as usize;
                                    let total_len = CSTP_HEADER_LEN + body_len;

                                    if tls_in_buf.len() < total_len {
                                        tls_in_buf.reserve(total_len - tls_in_buf.len());
                                        break;
                                    }

                                    let packet_data = tls_in_buf.split_to(total_len);
                                    let packet_type = PacketType::from(packet_data[6]);
                                    let payload = &packet_data[CSTP_HEADER_LEN..];

                                    match packet_type {
                                        PacketType::Data => {
                                            if let Err(e) = tun_w.write_all(payload).await {
                                                 error!("TUN write error (TLS): {}", e);
                                                 return;
                                            }
                                        }
                                        PacketType::DpdReq => {
                                            // Send DpdResp to Task 1
                                            let resp = CstpPacket::new(PacketType::DpdResp, Bytes::copy_from_slice(payload));
                                            let _ = control_tx.send(resp.encode()).await;
                                        }
                                        PacketType::KeepAlive => {
                                            let resp = CstpPacket::new(PacketType::KeepAlive, Bytes::copy_from_slice(payload));
                                            let _ = control_tx.send(resp.encode()).await;
                                        }
                                        PacketType::Disconnect => {
                                            info!("Received DISCONNECT");
                                            return;
                                        }
                                        _ => debug!("Ignored control packet: {:?}", packet_type),
                                    }
                                }
                            }
                            Err(e) => {
                                error!("TLS read error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Use select! to wait for either task to finish/error
        tokio::select! {
            _ = task1 => { info!("Tunnel Task 1 finished"); },
            _ = task2 => { info!("Tunnel Task 2 finished"); },
        }

        Ok(())
    }
}
