use crate::vpn::cstp::{CstpPacket, PacketType, CSTP_HEADER_LEN};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

pub struct VpnTunnel<IO> {
    io: IO,
    // future: rx/tx channels for TUN interface
}

impl<IO> VpnTunnel<IO>
where
    IO: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    pub fn new(io: IO) -> Self {
        Self { io }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("VPN Tunnel loop started");
        let mut buf = BytesMut::with_capacity(4096);

        loop {
            // 1. Read Header (8 bytes)
            // We need to read exactly 8 bytes to determine packet length
            let mut header = [0u8; CSTP_HEADER_LEN];
            match self.io.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) => {
                    info!("Client disconnected (read error): {}", e);
                    break;
                }
            }

            let (packet_type, payload_len) = match CstpPacket::parse_header(&header) {
                Ok(res) => res,
                Err(e) => {
                    error!("Invalid CSTP header received: {}", e);
                    return Err(e);
                }
            };

            // 2. Read Payload
            // Resize buffer to fit payload
            buf.clear();
            if buf.capacity() < payload_len {
                buf.reserve(payload_len - buf.capacity());
            }
            // unsafe is not needed if we just resize to create zeroed bytes or use `read_buf` if available.
            // simpler for now:
            let mut payload = vec![0u8; payload_len];
            self.io
                .read_exact(&mut payload)
                .await
                .context("Failed to read payload")?;
            let payload_bytes = Bytes::from(payload);

            match packet_type {
                PacketType::Data => {
                    debug!("Received DATA packet, len: {}", payload_len);
                    // TODO: Write to TUN interface
                }
                PacketType::DpdReq => {
                    debug!("Received DPD-REQ, replying with DPD-RESP");
                    let resp = CstpPacket::new(PacketType::DpdResp, payload_bytes);
                    self.io.write_all(&resp.encode()).await?;
                }
                PacketType::KeepAlive => {
                    debug!("Received KeepAlive, replying");
                    let resp = CstpPacket::new(PacketType::KeepAlive, Bytes::new());
                    self.io.write_all(&resp.encode()).await?;
                }
                PacketType::Disconnect => {
                    let reason = String::from_utf8_lossy(&payload_bytes);
                    info!("Received DISCONNECT from client. Reason: '{}'", reason);
                    break;
                }
                _ => {
                    warn!("Received unhandled packet type: {:?}", packet_type);
                }
            }
        }

        info!("VPN Tunnel loop ended");
        Ok(())
    }
}
