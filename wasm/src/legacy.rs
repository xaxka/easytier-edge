//! EasyTier 旧版(非安全模式)握手支持。
//!
//! 移植上游 EasyTier 2.6.4 `peer_conn.rs` 中的 legacy 握手:
//! 客户端发送 `PacketType::HandShake`(=2)帧,负载为 protobuf
//! `HandshakeRequest`;服务端校验 `network_name` 与
//! `network_secret_digest`(SipHash-1-3 分片摘要)后回发自身的
//! `HandshakeRequest`。该模式面向无法配置 secure mode 的客户端,
//! 传输层不加密,身份认证仅依赖 network_secret 摘要匹配。

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher as _;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use prost::Message as _;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::packet::{ENCRYPTED_FLAG, HEADER_SIZE, PacketHeader, parse_packet};
use crate::proto::peer_rpc::HandshakeRequest;

/// 上游 `PacketType::HandShake`。
const PACKET_TYPE_HANDSHAKE: u8 = 2;
/// 上游 `peer_conn.rs` 的 MAGIC / VERSION 常量。
const MAGIC: u32 = 0xd1e1a5e1;
const VERSION: u32 = 1;
/// `NetworkSecretDigest = [u8; 32]`。
const DIGEST_SIZE: usize = 32;

#[derive(Serialize)]
struct LegacyHandshakeInfo {
    peer_id: u32,
    network_name: String,
    network_secret_digest_base64: String,
}

/// 与上游 `tunnel::generate_digest_from_str` 完全一致的分片摘要:
/// `DefaultHasher` 即 SipHash-1-3(零密钥),每 8 字节输出一次,
/// 并把已生成的摘要前缀继续喂回哈希器。
fn generate_digest_from_str(network_name: &str, network_secret: &str) -> [u8; DIGEST_SIZE] {
    let mut hasher = DefaultHasher::new();
    hasher.write(network_name.as_bytes());
    hasher.write(network_secret.as_bytes());

    let mut digest = [0_u8; DIGEST_SIZE];
    let shard_count = DIGEST_SIZE / 8;
    for i in 0..shard_count {
        let shard = hasher.finish().to_be_bytes();
        digest[i * 8..(i + 1) * 8].copy_from_slice(&shard);
        hasher.write(&digest[..(i + 1) * 8]);
    }
    digest
}

/// 常数时间字节比较,避免通过响应时间逐字节探测摘要。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn encode_header(from: u32, to: u32, packet_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = PacketHeader {
        from_peer_id: from,
        to_peer_id: to,
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

fn decode_handshake_request(
    header: &PacketHeader,
    packet: &[u8],
) -> Result<HandshakeRequest, String> {
    let request = HandshakeRequest::decode(&packet[HEADER_SIZE..]).map_err(|_| {
        "legacy handshake payload is not a valid HandshakeRequest protobuf".to_string()
    })?;
    if request.magic != MAGIC {
        return Err("legacy handshake magic mismatch".to_string());
    }
    if request.version != VERSION {
        return Err("unsupported legacy handshake version".to_string());
    }
    if request.my_peer_id == 0 {
        return Err("legacy handshake my_peer_id must not be zero".to_string());
    }
    if request.my_peer_id != header.from_peer_id {
        return Err("legacy handshake peer id mismatch between header and payload".to_string());
    }
    if request.network_name.is_empty() || request.network_name.len() > 255 {
        return Err("legacy handshake network_name must be 1-255 bytes".to_string());
    }
    if request.network_secret_digest.len() != DIGEST_SIZE {
        return Err("legacy handshake network_secret_digest must be 32 bytes".to_string());
    }
    Ok(request)
}

/// 解析客户端发来的 legacy 握手帧(内部实现,返回 String 错误便于原生单测)。
pub(crate) fn parse_legacy_handshake_impl(packet: &[u8]) -> Result<LegacyHandshakeInfo, String> {
    let header = parse_packet(packet)?;
    if header.packet_type != PACKET_TYPE_HANDSHAKE {
        return Err("legacy handshake requires PacketType::HandShake".to_string());
    }
    if header.flags & ENCRYPTED_FLAG != 0 {
        return Err("legacy handshake must not set the encrypted flag".to_string());
    }
    let request = decode_handshake_request(&header, packet)?;
    Ok(LegacyHandshakeInfo {
        peer_id: request.my_peer_id,
        network_name: request.network_name,
        network_secret_digest_base64: BASE64_STANDARD.encode(&request.network_secret_digest),
    })
}

/// 解析客户端发来的 legacy 握手帧,返回
/// `{ peer_id, network_name, network_secret_digest_base64 }`。
/// 房间白名单与摘要匹配由 TypeScript 层结合配置完成。
#[wasm_bindgen]
pub fn parse_legacy_handshake(packet: &[u8]) -> Result<String, JsValue> {
    serde_json::to_string(&parse_legacy_handshake_impl(packet).map_err(js_error)?)
        .map_err(display_error)
}

/// 计算网络身份摘要(与上游 `generate_digest_from_str` 一致)。
#[wasm_bindgen]
pub fn network_secret_digest(network_name: &str, network_secret: &str) -> Result<Vec<u8>, JsValue> {
    if network_name.is_empty() {
        return Err(js_error("network_name must not be empty"));
    }
    Ok(generate_digest_from_str(network_name, network_secret).to_vec())
}

/// 常数时间校验客户端摘要是否等于 `(network_name, network_secret)` 的摘要。
#[wasm_bindgen]
pub fn verify_network_secret_digest(
    digest: &[u8],
    network_name: &str,
    network_secret: &str,
) -> Result<bool, JsValue> {
    if network_name.is_empty() {
        return Err(js_error("network_name must not be empty"));
    }
    if digest.len() != DIGEST_SIZE {
        return Ok(false);
    }
    Ok(constant_time_eq(
        digest,
        &generate_digest_from_str(network_name, network_secret),
    ))
}

/// 构造服务端 legacy 握手响应帧(内部实现)。
/// 头部 `from=server_peer_id, to=0`,类型 `HandShake`,
/// 负载为携带真实摘要的 `HandshakeRequest`。
/// 上游仅在客户端网络身份匹配时回发真实摘要,这里由调用方
/// 先通过 `verify_network_secret_digest` 鉴权,再构建响应。
pub(crate) fn build_legacy_handshake_response_impl(
    server_peer_id: u32,
    network_name: &str,
    network_secret: &str,
) -> Result<Vec<u8>, String> {
    if server_peer_id == 0 {
        return Err("server peer id must not be zero".to_string());
    }
    if network_name.is_empty() || network_name.len() > 255 {
        return Err("network_name must be 1-255 bytes".to_string());
    }
    if network_secret.is_empty() {
        return Err("network_secret must not be empty".to_string());
    }
    let response = HandshakeRequest {
        magic: MAGIC,
        my_peer_id: server_peer_id,
        version: VERSION,
        features: Vec::new(),
        network_name: network_name.to_string(),
        network_secret_digest: generate_digest_from_str(network_name, network_secret).to_vec(),
    };
    Ok(encode_header(
        server_peer_id,
        0,
        PACKET_TYPE_HANDSHAKE,
        &response.encode_to_vec(),
    ))
}

/// 构造服务端 legacy 握手响应帧并回给客户端。
#[wasm_bindgen]
pub fn build_legacy_handshake_response(
    server_peer_id: u32,
    network_name: &str,
    network_secret: &str,
) -> Result<Vec<u8>, JsValue> {
    build_legacy_handshake_response_impl(server_peer_id, network_name, network_secret)
        .map_err(js_error)
}

/// 供测试使用的客户端握手帧构造器(模拟上游 `send_handshake`)。
#[cfg(test)]
pub(crate) fn build_legacy_handshake_request(
    peer_id: u32,
    network_name: &str,
    network_secret: &str,
    send_digest: bool,
) -> Vec<u8> {
    let digest = if send_digest {
        generate_digest_from_str(network_name, network_secret).to_vec()
    } else {
        vec![0_u8; DIGEST_SIZE]
    };
    let request = HandshakeRequest {
        magic: MAGIC,
        my_peer_id: peer_id,
        version: VERSION,
        features: Vec::new(),
        network_name: network_name.to_string(),
        network_secret_digest: digest,
    };
    encode_header(peer_id, 0, PACKET_TYPE_HANDSHAKE, &request.encode_to_vec())
}

fn js_error(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}

fn display_error(error: impl std::fmt::Display) -> JsValue {
    js_error(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 参考摘要十六进制,由独立程序按上游 EasyTier 2.6.4
    /// `tunnel::generate_digest_from_str`(std DefaultHasher 分片循环)计算。
    const REFERENCE_OFFICE_SECRET123: &str =
        "e0550395e5208dc40b9cf65f66b87eea575a1844c833322e1a06b681c260e86b";
    const REFERENCE_OFFICE_LONG_SECRET: &str =
        "3bce164ed59009954fe9e9b14b9c24787fedb4ac10f74951308071d81ce3691e";
    const REFERENCE_DEFAULT_EMPTY: &str =
        "02e2bcd8739ae03985d61303fbec09210289c243231b1dcaa5bbb1f191f9b993";
    const REFERENCE_UTF8: &str = "7dfbb2b783193fb4c444f9097480a1c706bd041785f83d184ca43755834abb1a";

    // 参考向量由独立程序按上游 `tunnel::generate_digest_from_str`
    // (std DefaultHasher 分片循环)计算后硬编码,防止本模块重写引入偏差。
    #[test]
    fn digest_matches_reference_vectors() {
        assert_eq!(
            hex(&generate_digest_from_str("office", "secret123")),
            REFERENCE_OFFICE_SECRET123,
        );
        assert_eq!(
            hex(&generate_digest_from_str(
                "office",
                "use-a-long-random-secret"
            )),
            REFERENCE_OFFICE_LONG_SECRET,
        );
        assert_eq!(
            hex(&generate_digest_from_str("default", "")),
            REFERENCE_DEFAULT_EMPTY,
        );
        assert_eq!(
            hex(&generate_digest_from_str("测试网络", "密码")),
            REFERENCE_UTF8,
        );
    }

    #[test]
    fn digest_depends_on_name_and_secret() {
        let base = generate_digest_from_str("office", "secret123");
        assert_ne!(base, generate_digest_from_str("office2", "secret123"));
        assert_ne!(base, generate_digest_from_str("office", "secret124"));
        assert_eq!(base, generate_digest_from_str("office", "secret123"));
    }

    #[test]
    fn digest_has_32_bytes_and_differs_per_shard() {
        let digest = generate_digest_from_str("net", "s");
        assert_eq!(digest.len(), 32);
        assert_ne!(&digest[0..8], &digest[8..16]);
        assert_ne!(&digest[8..16], &digest[16..24]);
    }

    #[test]
    fn parses_a_valid_client_handshake() {
        let frame = build_legacy_handshake_request(123, "office", "secret123", true);
        let info = parse_legacy_handshake_impl(&frame).unwrap();
        assert_eq!(info.peer_id, 123);
        assert_eq!(info.network_name, "office");
        let digest = BASE64_STANDARD
            .decode(&info.network_secret_digest_base64)
            .unwrap();
        assert_eq!(
            digest,
            generate_digest_from_str("office", "secret123").to_vec()
        );
    }

    #[test]
    fn accepts_a_zero_digest_from_unauthenticated_clients() {
        // 上游客户端在不发送摘要时填充 32 字节全零,解析层必须放行,
        // 由摘要校验层决定是否拒绝。
        let frame = build_legacy_handshake_request(123, "office", "secret123", false);
        assert!(parse_legacy_handshake_impl(&frame).is_ok());
        assert!(!constant_time_eq(
            &[0u8; 32],
            &generate_digest_from_str("office", "secret123")
        ));
    }

    #[test]
    fn rejects_malformed_client_handshakes() {
        let frame = build_legacy_handshake_request(123, "office", "secret123", true);

        // 非握手类型(Ping)。
        let mut wrong_type = frame.clone();
        wrong_type[8] = 4;
        assert!(parse_legacy_handshake_impl(&wrong_type).is_err());

        // 加密标志置位。
        let mut encrypted = frame.clone();
        encrypted[9] |= ENCRYPTED_FLAG;
        assert!(parse_legacy_handshake_impl(&encrypted).is_err());

        // 坏魔数:改写 protobuf 首字段(magic varint)的值字节。
        let mut bad_magic = frame.clone();
        bad_magic[HEADER_SIZE + 1] ^= 0xff;
        assert!(parse_legacy_handshake_impl(&bad_magic).is_err());

        // 头部与负载 peer id 不一致。
        let mut id_mismatch = frame.clone();
        id_mismatch[0..4].copy_from_slice(&124u32.to_le_bytes());
        assert!(parse_legacy_handshake_impl(&id_mismatch).is_err());

        // 摘要长度错误。
        let short = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: 123,
            version: VERSION,
            features: Vec::new(),
            network_name: "office".to_string(),
            network_secret_digest: vec![0u8; 16],
        };
        let payload = short.encode_to_vec();
        let bytes = encode_header(123, 0, PACKET_TYPE_HANDSHAKE, &payload);
        assert!(parse_legacy_handshake_impl(&bytes).is_err());

        // 帧长与头部声明不符。
        let mut truncated = frame.clone();
        truncated.truncate(truncated.len() - 1);
        assert!(parse_legacy_handshake_impl(&truncated).is_err());
    }

    #[test]
    fn verifies_digest_correctness() {
        let digest = generate_digest_from_str("office", "secret123").to_vec();
        assert!(constant_time_eq(
            &digest,
            &generate_digest_from_str("office", "secret123")
        ));
        assert!(!constant_time_eq(
            &digest,
            &generate_digest_from_str("office", "wrong")
        ));
        assert!(!constant_time_eq(
            &digest,
            &generate_digest_from_str("other", "secret123")
        ));
        assert!(!constant_time_eq(
            &digest[..16],
            &generate_digest_from_str("office", "secret123")
        ));
    }

    #[test]
    fn builds_a_well_formed_server_response() {
        let response =
            build_legacy_handshake_response_impl(10_000_001, "office", "secret123").unwrap();
        let header = PacketHeader::from_bytes(&response).unwrap();
        assert_eq!(header.from_peer_id, 10_000_001);
        assert_eq!(header.to_peer_id, 0);
        assert_eq!(header.packet_type, PACKET_TYPE_HANDSHAKE);
        assert_eq!(header.flags, 0);
        assert_eq!(header.forward_counter, 1);
        assert_eq!(header.len as usize, response.len() - HEADER_SIZE);

        let request = HandshakeRequest::decode(&response[HEADER_SIZE..]).unwrap();
        assert_eq!(request.magic, MAGIC);
        assert_eq!(request.my_peer_id, 10_000_001);
        assert_eq!(request.version, VERSION);
        assert!(request.features.is_empty());
        assert_eq!(request.network_name, "office");
        assert_eq!(
            request.network_secret_digest,
            generate_digest_from_str("office", "secret123").to_vec()
        );
    }

    #[test]
    fn server_response_round_trips_through_client_parser() {
        // 客户端(上游 wait_handshake)校验响应类型与摘要长度,这里同样验证。
        let response =
            build_legacy_handshake_response_impl(10_000_001, "office", "secret123").unwrap();
        let header = PacketHeader::from_bytes(&response).unwrap();
        assert_eq!(header.packet_type, PACKET_TYPE_HANDSHAKE);
        let request = HandshakeRequest::decode(&response[HEADER_SIZE..]).unwrap();
        assert_eq!(request.network_secret_digest.len(), DIGEST_SIZE);
        assert_eq!(request.my_peer_id, 10_000_001);
    }

    #[test]
    fn build_response_rejects_invalid_arguments() {
        assert!(build_legacy_handshake_response_impl(0, "office", "s").is_err());
        assert!(build_legacy_handshake_response_impl(1, "", "s").is_err());
        assert!(build_legacy_handshake_response_impl(1, "office", "").is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
