use crate::vpn::cstp::{CstpPacket, PacketType, CSTP_HEADER_LEN};
use crate::vpn::tun_device::TunDevice;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct VpnTunnel<IO> {
    io: IO,
    tun: TunDevice,
    /// Optional receiver for DTLS packets to write to TUN
    dtls_rx: Option<mpsc::Receiver<Bytes>>,
    /// Optional receiver for DTLS readiness signal (socket, addr)
    dtls_signal_rx: Option<mpsc::Receiver<(Arc<tokio::net::UdpSocket>, std::net::SocketAddr)>>,
    /// Channel to send outgoing packets to DTLS session task
    dtls_out_tx: Option<mpsc::Sender<Bytes>>,
    // Configurable performance parameters
    buffer_size: usize,
    channel_capacity: usize,
}

impl<IO> VpnTunnel<IO>
where
    IO: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    pub fn new(io: IO, tun: TunDevice, buffer_size: usize, channel_capacity: usize) -> Self {
        Self {
            io,
            tun,
            dtls_rx: None,
            dtls_signal_rx: None,
            dtls_out_tx: None,
            buffer_size,
            channel_capacity,
        }
    }

    /// Create a new tunnel with DTLS support
    pub fn with_dtls(
        io: IO,
        tun: TunDevice,
        dtls_rx: mpsc::Receiver<Bytes>,
        dtls_signal_rx: mpsc::Receiver<(Arc<tokio::net::UdpSocket>, std::net::SocketAddr)>,
        dtls_out_tx: mpsc::Sender<Bytes>,
        buffer_size: usize,
        channel_capacity: usize,
    ) -> Self {
        Self {
            io,
            tun,
            dtls_rx: Some(dtls_rx),
            dtls_signal_rx: Some(dtls_signal_rx),
            dtls_out_tx: Some(dtls_out_tx),
            buffer_size,
            channel_capacity,
        }
    }

    pub async fn run(self) -> Result<()> {
        info!("VPN Tunnel loop started for interface: {}", self.tun.name());

        let (mut tls_r, mut tls_w) = tokio::io::split(self.io);
        let (mut tun_r, mut tun_w) = self.tun.split();

        // Shared state for DTLS availability
        let use_dtls = Arc::new(AtomicBool::new(false));

        // INTERNAL CHANNELS:
        // 1. Control Packets: Task 2 (TLS Read) -> Task 1 (TLS Write)
        // Used for DPD Responses, KeepAlives, etc. Small capacity is sufficient.
        let (control_tx, mut control_rx) = mpsc::channel::<Bytes>(64);

        // 2. TUN Writes: DTLS Reader -> Task 2 (TUN Writer)
        // Since we have multiple sources for TUN (TLS & DTLS), and we own the Writer in Task 2.
        let (tun_write_tx, mut tun_write_rx) = mpsc::channel::<Bytes>(self.channel_capacity);

        // OPTIMIZATION: Signal Monitor Task (Low Overhead)
        // Updates AtomicBool so the hot path doesn't need to select! on the signal channel.
        if let Some(mut signal_rx) = self.dtls_signal_rx {
            let use_dtls_signal = use_dtls.clone();
            tokio::spawn(async move {
                while let Some((_socket, _addr)) = signal_rx.recv().await {
                    info!("VPN Tunnel: DTLS enabled via signal");
                    use_dtls_signal.store(true, Ordering::Relaxed);
                }
                // If channel closes, we assume DTLS is disabled? Or just stop updating?
                // Usually indicates shutdown, but let's be safe.
                use_dtls_signal.store(false, Ordering::Relaxed);
            });
        }

        // TASK 1: TUN Reader & TLS Writer (+ Incoming Control Packets)
        // - Reads IP packets from TUN
        // - Encodes them (CSTP)
        // - Batches them logic (Latency-aware: Flush on full or timeout)
        // - Writes to TLS
        // - Also handles high-priority Control packets from Task 2
        let dtls_out_tx = self.dtls_out_tx.clone();
        let use_dtls_t1 = use_dtls.clone();
        let buffer_size = self.buffer_size;

        let task1 = tokio::spawn(async move {
            info!("TUN Reader / TLS Writer task started");
            let mut tun_buf = vec![0u8; buffer_size];
            let mut tls_batch = BytesMut::with_capacity(64 * 1024);
            let mut batch_deadline: Option<tokio::time::Instant> = None;

            loop {
                // Prepare timeout future for batch flushing
                let timeout_fut = async {
                    if let Some(deadline) = batch_deadline {
                        tokio::time::sleep_until(deadline).await;
                        true
                    } else {
                        std::future::pending::<bool>().await;
                        false
                    }
                };

                tokio::select! {
                     // Priority 1: Batch Flush Timeout
                     _ = timeout_fut, if batch_deadline.is_some() => {
                         if !tls_batch.is_empty() {
                             if let Err(e) = tls_w.write_all(&tls_batch).await {
                                 error!("TLS write error (flush): {}", e);
                                 break;
                             }
                             if let Err(e) = tls_w.flush().await {
                                 error!("TLS flush error: {}", e);
                                 break;
                             }
                             tls_batch.clear();
                             batch_deadline = None;
                         }
                     }

                     // Priority 2: Control Packets (from Other Task)
                     // Must be flushed immediately (low latency)
                     res = control_rx.recv() => {
                         match res {
                             Some(msg) => {
                                 // Flush existing batch first to maintain order (and clear buffer)
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
                                     batch_deadline = None;
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
                             None => break, // Control channel closed
                         }
                     }

                     // Priority 3: TUN Read
                     res = tun_r.read(&mut tun_buf) => {
                         match res {
                             Ok(0) => break, // EOF
                             Ok(n) => {
                                 let payload = &tun_buf[..n];

                                 // OPTIMIZATION: DTLS Fast Path
                                 // If enabled, try to send via DTLS first.
                                 let mut sent_via_dtls = false;
                                 if use_dtls_t1.load(Ordering::Relaxed) {
                                     if let Some(tx) = &dtls_out_tx {
                                         // We must copy here because we are sending to another task/socket
                                         let bytes = Bytes::copy_from_slice(payload);
                                         // Use try_send to avoid blocking TUN reader
                                         match tx.try_send(bytes) {
                                             Ok(_) => {
                                                 sent_via_dtls = true;
                                             }
                                             Err(_) => {
                                                 // Drop or Fallback?
                                                 // Common strategy: Fallback to TLS if DTLS is full/congested
                                                 // warn!("DTLS channel full, falling back to TLS");
                                             }
                                         }
                                     }
                                 }

                                 if !sent_via_dtls {
                                     // TLS Path: Zero-Copy Encode info Batch (serving as temp buffer)
                                     CstpPacket::write_packet(PacketType::Data, payload, &mut tls_batch);

                                     // Disable Batching for stability: Flush immediately
                                     if let Err(e) = tls_w.write_all(&tls_batch).await {
                                         error!("TLS write error: {}", e);
                                         break;
                                     }
                                     if let Err(e) = tls_w.flush().await {
                                         error!("TLS flush error: {}", e);
                                         break;
                                     }
                                     tls_batch.clear();
                                     batch_deadline = None;
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
            debug!("TUN Reader / TLS Writer task finished");
        });

        // TASK 2: TLS Reader & TUN Writer (+ DTLS Incoming)
        // - Reads CSTP packets from TLS
        // - Writes DATA payload to TUN
        // - Sends CONTROL payload to Task 1
        // - Also accepts Decrypted DTLS packets and writes to TUN
        let tun_write_tx_dtls = tun_write_tx.clone();

        let task2 = tokio::spawn(async move {
            info!("TLS Reader / TUN Writer task started");
            let mut tls_in_buf = BytesMut::with_capacity(8192);

            loop {
                tokio::select! {
                    // 1. Incoming DTLS Packets (Decrypted) -> Write to TUN
                    res = tun_write_rx.recv() => {
                        match res {
                            Some(packet) => {
                                if let Err(e) = tun_w.write_all(&packet).await {
                                    error!("TUN write error (DTLS): {}", e);
                                    break;
                                }
                            }
                            None => {
                                // Channel should stay open unless DTLS task dies?
                                // We keep running for TLS.
                            }
                        }
                    }

                    // 2. Incoming TLS Data -> Parse -> Write to TUN / Send Control to Task 1
                    res = tls_r.read_buf(&mut tls_in_buf) => {
                        match res {
                            Ok(0) => {
                                info!("TLS Connection Closed (EOF)");
                                break;
                            }
                            Ok(_) => {
                                // Parse Loop (process all complete packets in buffer)
                                loop {
                                    // 1. Check Header
                                    if tls_in_buf.len() < CSTP_HEADER_LEN {
                                        break; // Need more data
                                    }

                                    let len_result = {
                                        let h = &tls_in_buf[..CSTP_HEADER_LEN];
                                        CstpPacket::parse_header(h)
                                    };

                                    match len_result {
                                        Ok((packet_type, payload_len)) => {
                                            let total_len = CSTP_HEADER_LEN + payload_len;
                                            if tls_in_buf.len() < total_len {
                                                // Ensure capacity for the full packet relative to current buffer content
                                                if tls_in_buf.capacity() < total_len {
                                                    tls_in_buf.reserve(total_len - tls_in_buf.len());
                                                }
                                                break; // Wait for body
                                            }

                                            // Extract Packet
                                            let packet_data = tls_in_buf.split_to(total_len);
                                            let payload = &packet_data[CSTP_HEADER_LEN..];

                                            // Handle Packet
                                            match packet_type {
                                                PacketType::Data => {
                                                    if let Err(e) = tun_w.write_all(&payload).await {
                                                        error!("TUN write error (TLS): {}", e);
                                                        return;
                                                    }
                                                }
                                                PacketType::DpdReq => {
                                                    debug!("Received DPD-REQ");
                                                    let resp = CstpPacket::new(PacketType::DpdResp, Bytes::copy_from_slice(payload));
                                                    let _ = control_tx.send(resp.encode()).await;
                                                }
                                                PacketType::KeepAlive => {
                                                    let resp = CstpPacket::new(PacketType::KeepAlive, Bytes::new());
                                                    let _ = control_tx.send(resp.encode()).await;
                                                }
                                                PacketType::Disconnect => {
                                                    let reason = String::from_utf8_lossy(&payload);
                                                    info!("Received DISCONNECT: {}", reason);
                                                    return;
                                                }
                                                _ => {
                                                    warn!("Unhandled packet type: {:?}", packet_type);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("CSTP Header Parse Error: {}", e);
                                            return; // Fatal protocol error
                                        }
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
            debug!("TLS Reader / TUN Writer task finished");
        });

        // TASK 3: DTLS Reader (Legacy Adapter)
        // If DTLS is configured, we spawn a reader that simply forwards to Task 2
        if let Some(mut dtls_rx) = self.dtls_rx {
            tokio::spawn(async move {
                info!("DTLS Receiver task started");
                while let Some(packet) = dtls_rx.recv().await {
                    if let Err(_) = tun_write_tx_dtls.send(packet).await {
                        break;
                    }
                }
                debug!("DTLS Receiver task finished");
            });
        }

        // Wait for main tasks
        // If either Task 1 or Task 2 fails/finishes, we should probably stop the whole tunnel.
        tokio::select! {
            _ = task1 => {},
            _ = task2 => {},
        }

        Ok(())
    }
}
