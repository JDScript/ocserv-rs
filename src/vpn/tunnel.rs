use crate::vpn::cstp::{CstpPacket, PacketType, CSTP_HEADER_LEN};
use crate::vpn::tun_device::TunDevice;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct VpnTunnel<IO> {
    io: IO,
    tun: TunDevice,
}

impl<IO> VpnTunnel<IO>
where
    IO: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    pub fn new(io: IO, tun: TunDevice) -> Self {
        Self { io, tun }
    }

    pub async fn run(self) -> Result<()> {
        info!("VPN Tunnel loop started for interface: {}", self.tun.name());

        let (mut tls_r, mut tls_w) = tokio::io::split(self.io);
        let (mut tun_r, mut tun_w) = self.tun.split();

        // Channel for writing to TLS (Data from TUN + Control replies from Reader)
        let (tx_sender, mut tx_receiver) = mpsc::channel::<Bytes>(100);

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

        // 2. TUN Reader Task: Reads IP packets from TUN, wraps in CSTP, sends to TLS Writer
        let tx_sender_tun = tx_sender.clone();
        let tun_reader_handle = tokio::spawn(async move {
            info!("TUN Reader task started");
            let mut buf = vec![0u8; 2048]; // MTU is usually ~1400
            loop {
                match tun_r.read(&mut buf).await {
                    Ok(n) => {
                        if n == 0 {
                            break; // EOF
                        }

                        let payload = Bytes::copy_from_slice(&buf[..n]);

                        // Wrap in CSTP DATA packet
                        let packet = CstpPacket::new(PacketType::Data, payload);
                        if let Err(_) = tx_sender_tun.send(packet.encode()).await {
                            break; // Channel closed
                        }
                    }
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
            debug!("TUN Reader task finished");
        });

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
                    // Decapsulate and write to TUN
                    if let Err(e) = tun_w.write_all(&payload_bytes).await {
                        error!("TUN write error: {}", e);
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

        result
    }
}
