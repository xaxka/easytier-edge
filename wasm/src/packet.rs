use wasm_bindgen::prelude::*;

pub const HEADER_SIZE: usize = 16;
pub const AEAD_TAIL_SIZE: usize = 28;
pub const ENCRYPTED_FLAG: u8 = 0x01;
pub const MAX_FORWARD_HOPS: u8 = 7;
const PACKET_TYPE_PING: u8 = 4;
const PACKET_TYPE_PONG: u8 = 5;

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
