use wasm_bindgen::prelude::*;

pub const HEADER_SIZE: usize = 16;
pub const AEAD_TAIL_SIZE: usize = 28;
pub const ENCRYPTED_FLAG: u8 = 0x01;
pub const MAX_FORWARD_HOPS: u8 = 7;
const PACKET_TYPE_DATA: u8 = 1;
const PACKET_TYPE_PING: u8 = 4;
const PACKET_TYPE_PONG: u8 = 5;
const PACKET_TYPE_FOREIGN_NETWORK: u8 = 10;
const PACKET_TYPE_KCP_SRC: u8 = 11;
const PACKET_TYPE_KCP_DST: u8 = 12;
const PACKET_TYPE_QUIC_SRC: u8 = 16;
const PACKET_TYPE_QUIC_DST: u8 = 17;
const PACKET_TYPE_DATA_KCP_MODIFIED: u8 = 18;
const PACKET_TYPE_DATA_QUIC_MODIFIED: u8 = 19;
/// ForeignNetworkPacketHeader 固定前缀:header_len(u16) + dst_peer_id(u32)
/// + network_name_offset(u16) + network_name_len(u16)。
const FOREIGN_HEADER_MIN_LEN: usize = 10;

#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub from_peer_id: u32,
    pub to_peer_id: u32,
    pub packet_type: u8,
    pub flags: u8,
    pub forward_counter: u8,
    pub reserved: u8,
    pub len: u32,
}

impl PacketHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_SIZE {
            return Err(format!("header too short: {} < {}", bytes.len(), HEADER_SIZE));
        }
        let b = &bytes[..HEADER_SIZE];
        Ok(PacketHeader {
            from_peer_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            to_peer_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            packet_type: b[8],
            flags: b[9],
            forward_counter: b[10],
            reserved: b[11],
            len: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.from_peer_id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.to_peer_id.to_le_bytes());
        buf[8] = self.packet_type;
        buf[9] = self.flags;
        buf[10] = self.forward_counter;
        buf[11] = self.reserved;
        buf[12..16].copy_from_slice(&self.len.to_le_bytes());
        buf
    }
}

pub fn parse_packet(bytes: &[u8]) -> Result<PacketHeader, String> {
    let header = PacketHeader::from_bytes(bytes)?;
    let payload_len = bytes.len() - HEADER_SIZE;
    let expected_len = header.len as usize
        + if header.flags & ENCRYPTED_FLAG == 0 {
            0
        } else {
            AEAD_TAIL_SIZE
        };
    if payload_len != expected_len {
        return Err(format!(
            "payload length mismatch: {payload_len} != {expected_len}"
        ));
    }
    Ok(header)
}

#[wasm_bindgen]
pub fn inspect_packet(bytes: &[u8]) -> Result<Vec<u32>, JsValue> {
    let header = parse_packet(bytes).map_err(|message| JsValue::from_str(&message))?;
    Ok(vec![
        header.from_peer_id,
        header.to_peer_id,
        header.packet_type.into(),
        header.flags.into(),
        header.forward_counter.into(),
        header.reserved.into(),
        header.len,
    ])
}

#[wasm_bindgen]
pub fn build_packet(
    from_peer_id: u32,
    to_peer_id: u32,
    packet_type: u8,
    payload: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| JsValue::from_str("packet payload exceeds the EasyTier u32 length"))?;
    let mut bytes = PacketHeader {
        from_peer_id,
        to_peer_id,
        packet_type,
        flags: 0,
        forward_counter: 1,
        reserved: 0,
        len: payload_len,
    }
    .to_bytes();
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

#[wasm_bindgen]
pub fn prepare_forward(bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let header = parse_packet(bytes).map_err(|message| JsValue::from_str(&message))?;
    if header.forward_counter > MAX_FORWARD_HOPS {
        return Err(JsValue::from_str("EasyTier forwarding hop limit exceeded"));
    }
    let mut forwarded = bytes.to_vec();
    forwarded[10] = header.forward_counter + 1;
    Ok(forwarded)
}

#[wasm_bindgen]
pub fn prepare_pong(bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let header = parse_packet(bytes).map_err(|message| JsValue::from_str(&message))?;
    if header.packet_type != PACKET_TYPE_PING {
        return Err(JsValue::from_str("only an EasyTier Ping packet can become Pong"));
    }
    let mut pong = bytes.to_vec();
    pong[8] = PACKET_TYPE_PONG;
    Ok(pong)
}

/// 判断一个包是否属于"中继数据面",语义与上游 EasyTier 2.6.4 的
/// `PeerManager::is_relay_data_zc_packet` 保持一致:
/// - 纯数据包(Data / KCP / QUIC 及其 SrcModified 变体)属于数据面;
/// - ForeignNetworkPacket 需要检查内层包类型,内层无法解析时按数据面处理(保守丢弃);
/// - RPC、Ping/Pong、Noise 握手、RelayHandshake 等控制面一律不属于数据面。
fn is_data_plane_packet_type(packet_type: u8) -> bool {
    matches!(
        packet_type,
        PACKET_TYPE_DATA
            | PACKET_TYPE_KCP_SRC
            | PACKET_TYPE_KCP_DST
            | PACKET_TYPE_QUIC_SRC
            | PACKET_TYPE_QUIC_DST
            | PACKET_TYPE_DATA_KCP_MODIFIED
            | PACKET_TYPE_DATA_QUIC_MODIFIED
    )
}

fn foreign_network_inner_packet_type(bytes: &[u8]) -> Option<u8> {
    let payload = bytes.get(HEADER_SIZE..)?;
    let fixed = payload.get(..FOREIGN_HEADER_MIN_LEN)?;
    let header_len = u16::from_le_bytes([fixed[0], fixed[1]]) as usize;
    if header_len < FOREIGN_HEADER_MIN_LEN || header_len > payload.len() {
        return None;
    }
    let inner = payload.get(header_len..)?;
    let inner_header = inner.get(..HEADER_SIZE)?;
    Some(inner_header[8])
}

#[wasm_bindgen]
pub fn is_relay_data_packet(bytes: &[u8]) -> Result<bool, JsValue> {
    let header = PacketHeader::from_bytes(bytes).map_err(|message| JsValue::from_str(&message))?;
    if header.packet_type == PACKET_TYPE_FOREIGN_NETWORK {
        return Ok(
            foreign_network_inner_packet_type(bytes).map_or(true, is_data_plane_packet_type),
        );
    }
    Ok(is_data_plane_packet_type(header.packet_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(packet_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = PacketHeader {
            from_peer_id: 1,
            to_peer_id: 2,
            packet_type,
            flags: 0,
            forward_counter: 1,
            reserved: 0,
            len: payload.len() as u32,
        }
        .to_bytes();
        bytes.extend_from_slice(payload);
        bytes
    }

    fn foreign_frame(inner_packet_type: Option<u8>) -> Vec<u8> {
        let network_name = b"office";
        let header_len = (FOREIGN_HEADER_MIN_LEN + network_name.len()) as u16;
        let mut payload = Vec::new();
        payload.extend_from_slice(&header_len.to_le_bytes());
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(&(FOREIGN_HEADER_MIN_LEN as u16).to_le_bytes());
        payload.extend_from_slice(&(network_name.len() as u16).to_le_bytes());
        payload.extend_from_slice(network_name);
        if let Some(inner_packet_type) = inner_packet_type {
            payload.extend_from_slice(&frame(inner_packet_type, &[7])[..]);
        } else {
            payload.extend_from_slice(&[0xff; 4]);
        }
        frame(PACKET_TYPE_FOREIGN_NETWORK, &payload)
    }

    #[test]
    fn classifies_data_plane_packets_only() {
        for packet_type in [
            PACKET_TYPE_DATA,
            PACKET_TYPE_KCP_SRC,
            PACKET_TYPE_KCP_DST,
            PACKET_TYPE_QUIC_SRC,
            PACKET_TYPE_QUIC_DST,
            PACKET_TYPE_DATA_KCP_MODIFIED,
            PACKET_TYPE_DATA_QUIC_MODIFIED,
        ] {
            assert!(is_relay_data_packet(&frame(packet_type, &[9])).unwrap());
        }
        for packet_type in [2u8, PACKET_TYPE_PING, PACKET_TYPE_PONG, 8u8, 9u8, 13u8, 20u8, 21u8] {
            assert!(!is_relay_data_packet(&frame(packet_type, &[9])).unwrap());
        }
    }

    #[test]
    fn inspects_foreign_network_inner_packet_type() {
        // 内层是 RPC(控制面):不属于中继数据,允许转发。
        assert!(!is_relay_data_packet(&foreign_frame(Some(8))).unwrap());
        // 内层是 Data(数据面):属于中继数据。
        assert!(is_relay_data_packet(&foreign_frame(Some(PACKET_TYPE_DATA))).unwrap());
        // 内层无法解析:按数据面保守处理。
        assert!(is_relay_data_packet(&foreign_frame(None)).unwrap());
    }
}
