use crate::vpn::cstp::{CstpPacket, PacketType, CSTP_HEADER_LEN};
use crate::vpn::tun_device::TunDevice;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
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

    pub async fn run(mut self) -> Result<()> {
        info!("VPN Tunnel loop started for interface: {}", self.tun.name());

        let (mut tls_r, mut tls_w) = tokio::io::split(self.io);
        let (mut tun_r, mut tun_w) = self.tun.split();

        // Channel for writing to TLS (Data from TUN + Control replies from Reader)
        // Use larger capacity to reduce backpressure
        let (tx_sender, mut tx_receiver) = mpsc::channel::<Bytes>(self.channel_capacity);

        // 1. TLS Writer Task: Receives packets from channel and writes to TLS stream
        let tls_writer_handle = tokio::spawn(async move {
            info!("TLS Writer task started");
            while let Some(packet) = tx_receiver.recv().await {
                if let Err(e) = tls_w.write_all(&packet).await {
                    error!("TLS write error: {}", e);
                    break;
                }
            }
            debug!("TLS Writer task finished");
        });

        // 2. TUN Reader Task: Reads IP packets from TUN, wraps in CSTP, sends to TLS Writer (or DTLS channel)
        let tx_sender_tun = tx_sender.clone();
        let mut dtls_signal_rx = self.dtls_signal_rx;
        let dtls_out_tx = self.dtls_out_tx.clone();

        let tun_reader_handle = tokio::spawn(async move {
            info!("TUN Reader task started");
            let mut buf = vec![0u8; self.buffer_size];
            let mut use_dtls = false;

            loop {
                tokio::select! {
                    // 1. Handle DTLS signal (if channel exists)
                    signal = async {
                        match dtls_signal_rx {
                            Some(ref mut rx) => rx.recv().await,
                            None => std::future::pending::<Option<(Arc<tokio::net::UdpSocket>, std::net::SocketAddr)>>().await,
                        }
                    }, if dtls_signal_rx.is_some() => {
                        match signal {
                            Some((_socket, _addr)) => {
                                info!("VPN Tunnel: Switched outgoing traffic to DTLS channel");
                                use_dtls = true;
                            },
                            None => {
                                // Channel closed, disable DTLS
                                use_dtls = false;
                                dtls_signal_rx = None; // Stop polling
                            }
                        }
                    }

                    // 2. Read from TUN
                    res = tun_r.read(&mut buf) => {
                        match res {
                            Ok(n) => {
                                if n == 0 {
                                    break; // EOF
                                }

                                let payload = bytes::Bytes::copy_from_slice(&buf[..n]);
                                let packet = CstpPacket::new(PacketType::Data, payload.clone());

                                // Optimization: Try sending via DTLS channel if enabled
                                let mut sent_via_dtls = false;
                                if use_dtls {
                                    if let Some(ref tx) = dtls_out_tx {
                                        // Send raw payload to dtls task (it will encrypt and frame it)
                                        if let Err(e) = tx.send(payload).await {
                                            warn!("DTLS channel full/closed (reverting to TLS): {}", e);
                                        } else {
                                            sent_via_dtls = true;
                                        }
                                    }
                                }

                                if !sent_via_dtls {
                                    if let Err(_) = tx_sender_tun.send(packet.encode()).await {
                                        break; // Channel closed
                                    }
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
            debug!("TUN Reader task finished");
        });

        // 2b. DTLS Reader Task: Reads decapsulated IP packets from DTLS, writes to TUN
        // Create a channel for TUN writes shared between TLS reader and DTLS reader
        let (tun_write_tx, mut tun_write_rx) = mpsc::channel::<Bytes>(self.channel_capacity);

        // Spawn TUN write task
        let tun_writer_handle = tokio::spawn(async move {
            while let Some(packet) = tun_write_rx.recv().await {
                if let Err(e) = tun_w.write_all(&packet).await {
                    error!("TUN write error: {}", e);
                    break;
                }
            }
            debug!("TUN Writer task finished");
        });

        // DTLS reader (if enabled)
        let dtls_reader_handle = if let Some(mut dtls_rx) = self.dtls_rx.take() {
            let tun_write_tx_dtls = tun_write_tx.clone();
            Some(tokio::spawn(async move {
                info!("DTLS Reader task started");
                while let Some(packet) = dtls_rx.recv().await {
                    // DTLS packets are already decapsulated IP packets (no CSTP header)
                    if let Err(_) = tun_write_tx_dtls.send(packet).await {
                        break;
                    }
                }
                debug!("DTLS Reader task finished");
            }))
        } else {
            None
        };

        // 3. TLS Reader Task: Reads CSTP packets, writes Data to TUN, sends Control replies to TLS Writer
        let mut buf = BytesMut::with_capacity(4096);
        let mut result = Ok(());

        loop {
            // Read CSTP Header
            let mut header = [0u8; CSTP_HEADER_LEN];
            match tls_r.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) => {
                    info!("Client disconnected (read error): {}", e);
                    break;
                }
            }

            // Parse Header
            let (packet_type, payload_len) = match CstpPacket::parse_header(&header) {
                Ok(res) => res,
                Err(e) => {
                    error!("Invalid CSTP header: {}", e);
                    result = Err(anyhow::anyhow!("Invalid CSTP header: {}", e));
                    break;
                }
            };

            // Read Payload
            buf.clear();
            if buf.capacity() < payload_len {
                buf.reserve(payload_len - buf.capacity());
            }
            buf.resize(payload_len, 0);
            if let Err(e) = tls_r.read_exact(&mut buf).await {
                error!("Failed to read payload: {}", e);
                break;
            }

            let payload_bytes = Bytes::copy_from_slice(&buf);

            // Process Packet
            match packet_type {
                PacketType::Data => {
                    // Decapsulate and send to TUN writer task
                    if let Err(_) = tun_write_tx.send(payload_bytes).await {
                        error!("TUN write channel closed");
                        break;
                    }
                }
                PacketType::DpdReq => {
                    debug!("Received DPD-REQ, replying");
                    let resp = CstpPacket::new(PacketType::DpdResp, payload_bytes);
                    let _ = tx_sender.send(resp.encode()).await;
                }
                PacketType::KeepAlive => {
                    // debug!("Received KeepAlive"); // Quiet
                    let resp = CstpPacket::new(PacketType::KeepAlive, Bytes::new());
                    let _ = tx_sender.send(resp.encode()).await;
                }
                PacketType::Disconnect => {
                    let reason = String::from_utf8_lossy(&payload_bytes);
                    info!("Received DISCONNECT from client. Reason: '{}'", reason);
                    // We can break the loop to close connection
                    break;
                }
                _ => {
                    warn!("Received unhandled packet type: {:?}", packet_type);
                }
            }
        }

        // Cleanup
        info!("Stopping VPN Tunnel...");
        // Abort background tasks
        tls_writer_handle.abort();
        tun_reader_handle.abort();
        tun_writer_handle.abort();
        if let Some(h) = dtls_reader_handle {
            h.abort();
        }

        result
    }
}
