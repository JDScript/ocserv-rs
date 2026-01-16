use anyhow::{bail, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::fmt;

/// CSTP Header (8 bytes)
/// Byte 0: 0x53 ('S')
/// Byte 1: 0x54 ('T')
/// Byte 2: 0x46 ('F')
/// Byte 3: 0x01
/// Byte 4-5: Length (Big Endian)
/// Byte 6: Type
/// Byte 7: 0x00
pub const CSTP_HEADER_LEN: usize = 8;
const MAGIC: &[u8; 4] = b"STF\x01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Data,
    DpdReq,
    DpdResp,
    Disconnect,
    KeepAlive,
    CompressedData,
    Terminate,
    Unknown(u8),
}

impl From<u8> for PacketType {
    fn from(b: u8) -> Self {
        match b {
            0x00 => PacketType::Data,
            0x03 => PacketType::DpdReq,
            0x04 => PacketType::DpdResp,
            0x05 => PacketType::Disconnect,
            0x07 => PacketType::KeepAlive,
            0x08 => PacketType::CompressedData,
            0x09 => PacketType::Terminate,
            u => PacketType::Unknown(u),
        }
    }
}

impl From<PacketType> for u8 {
    fn from(t: PacketType) -> Self {
        match t {
            PacketType::Data => 0x00,
            PacketType::DpdReq => 0x03,
            PacketType::DpdResp => 0x04,
            PacketType::Disconnect => 0x05,
            PacketType::KeepAlive => 0x07,
            PacketType::CompressedData => 0x08,
            PacketType::Terminate => 0x09,
            PacketType::Unknown(u) => u,
        }
    }
}

pub struct CstpPacket {
    pub packet_type: PacketType,
    pub payload: Bytes,
}

impl fmt::Debug for CstpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CstpPacket")
            .field("type", &self.packet_type)
            .field("len", &self.payload.len())
            .finish()
    }
}

impl CstpPacket {
    pub fn new(packet_type: PacketType, payload: Bytes) -> Self {
        Self {
            packet_type,
            payload,
        }
    }

    /// Encode packet into bytes (Header + Payload)
    pub fn encode(&self) -> Bytes {
        let len = self.payload.len();
        let mut buf = BytesMut::with_capacity(CSTP_HEADER_LEN + len);

        // Header
        buf.put_slice(MAGIC);
        buf.put_u16(len as u16);
        buf.put_u8(self.packet_type.into());
        buf.put_u8(0x00);

        // Payload
        buf.put(self.payload.clone());

        buf.freeze()
    }

    /// Parse header from exactly 8 bytes
    pub fn parse_header(header: &[u8]) -> Result<(PacketType, usize)> {
        if header.len() != CSTP_HEADER_LEN {
            bail!("Invalid header length");
        }

        if &header[0..4] != MAGIC {
            bail!("Invalid magic bytes: {:?}", &header[0..4]);
        }

        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let packet_type = PacketType::from(header[6]);

        // packet type validation could go here

        Ok((packet_type, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let payload = Bytes::from("HELLO");
        let pkt = CstpPacket::new(PacketType::Data, payload.clone());
        let encoded = pkt.encode();

        assert_eq!(encoded.len(), 8 + 5);
        assert_eq!(&encoded[0..4], b"STF\x01");
        assert_eq!(encoded[6], 0x00); // Type DATA

        let (ptype, len) = CstpPacket::parse_header(&encoded[0..8]).unwrap();
        assert_eq!(ptype, PacketType::Data);
        assert_eq!(len, 5);
    }
}
