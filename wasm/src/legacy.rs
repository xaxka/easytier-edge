//! EasyTier 旧版(非安全模式)握手与直达 RPC 加密支持。
//!
//! 移植上游 EasyTier 2.6.4 `peer_conn.rs` 中的 legacy 握手:
//! 客户端发送 `PacketType::HandShake`(=2)帧,负载为 protobuf
//! `HandshakeRequest`;服务端校验 `network_name` 与
//! `network_secret_digest`(SipHash-1-3 分片摘要)后回发自身的
//! `HandshakeRequest`。该模式面向无法配置 secure mode 的客户端。
//!
//! 重要:上游 `gen_default_flags()` 默认 `enable_encryption = true`,
//! `encryption_algorithm = "aes-gcm"`。即使客户端未启用 secure mode,
//! `RpcTransport::send` 仍会用 `derive_key_128(network_secret)` 派生的
//! AES-128-GCM 密钥加密直达 RPC 帧(对端尚未在 route 缓存里被标记为
//! public server 时一律加密,首个 route sync RPC 必然落入此路径)。
//! 本模块的 `LegacyCipher` 与上游 `tunnel::encrypt::{derive_key_128,
//! AesGcmCipher}` 完全一致,允许服务端解密 legacy 客户端直达 RPC,
//! 同时回程也用同一密钥加密,保持双向兼容。

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher as _;

use aes_gcm::{AeadInPlace as _, Aes128Gcm, KeyInit as _, Nonce, aead::generic_array::GenericArray};
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

/// 与上游 `tunnel::encrypt::derive_key_128` 完全一致的密钥派生。
///
/// 上游用 `std::collections::hash_map::DefaultHasher`(SipHash-1-3,零密钥)
/// 对 `network_secret` 哈希,然后做两轮反馈式扩展到 16 字节。
/// 此函数被 `LegacyCipher` 用作 AES-128-GCM 的对称密钥。
pub(crate) fn derive_key_128(secret: &str) -> [u8; 16] {
    let mut key = [0_u8; 16];
    let mut hasher = DefaultHasher::new();
    hasher.write(secret.as_bytes());
    key[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
    hasher.write(&key[0..8]);
    key[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
    hasher.write(&key);
    key
}

/// 上游 `StandardAeadTail = AeadTail<16, 12>`:16 字节 GCM tag + 12 字节 nonce。
pub const LEGACY_AEAD_TAG_SIZE: usize = 16;
pub const LEGACY_AEAD_NONCE_SIZE: usize = 12;
pub const LEGACY_AEAD_TAIL_SIZE: usize = LEGACY_AEAD_TAG_SIZE + LEGACY_AEAD_NONCE_SIZE;

/// 旧版 RPC 加密器:用 `derive_key_128(network_secret)` 派生的
/// AES-128-GCM 密钥加/解密 EasyTier 直达控制面帧。
///
/// 与上游 `tunnel::encrypt::AesGcmCipher` 行为一致:
/// - 加密:对 payload(不含 16 字节 peer-manager 头)做 AES-128-GCM,
///   追加 16 字节 tag + 12 字节随机 nonce,并在头 flags 中置 `ENCRYPTED_FLAG`。
/// - 解密:从帧尾截取 tag+nonce,对 payload 做反向 AEAD,清掉 `ENCRYPTED_FLAG`。
///
/// 服务端仅在 `CONNECTION_MODE=legacy` 时使用本加密器,与上游
/// `enable_encryption = true`(默认)、`encryption_algorithm = "aes-gcm"`(默认)
/// 的非 secure-mode 客户端互通。
#[wasm_bindgen]
pub struct LegacyCipher {
    key_128: [u8; 16],
}

impl LegacyCipher {
    /// 内部实现,返回 `Result<_, String>` 以便在 `cargo test`(非 wasm32 host)
    /// 下也能跑错误路径的断言。`#[wasm_bindgen]` 包装函数把 `String` 错误
    /// 转成 `JsValue`,避免在非 wasm 目标上构造 `JsValue` 时触发
    /// `function not implemented on non-wasm32 targets` 的 panic。
    pub(crate) fn encrypt_packet_impl(&self, packet: &[u8]) -> Result<Vec<u8>, String> {
        if packet.len() < HEADER_SIZE {
            return Err("legacy packet is shorter than the EasyTier header".to_string());
        }
        let mut output = packet.to_vec();
        let mut nonce_bytes = [0_u8; LEGACY_AEAD_NONCE_SIZE];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|err| format!("legacy nonce generation failed: {err}"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.key_128));
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut output[HEADER_SIZE..])
            .map_err(|_| "legacy AES-128-GCM encryption failed".to_string())?;
        output.extend_from_slice(tag.as_slice());
        output.extend_from_slice(&nonce_bytes);
        // 头 flags 字节置 ENCRYPTED_FLAG,其它位保留(便于上游 set_compressed 等
        // 控制位与加密共存,虽然 legacy 直达 RPC 路径目前不会同时压缩)。
        output[9] |= ENCRYPTED_FLAG;
        // peer-manager 头中的 len 字段仍指 payload 长度,与上游
        // `PeerManagerHeader::len` 语义一致(不含 tag+nonce)。这里不重写 len,
        // 让解析层依据 flags & ENCRYPTED_FLAG 判断需要 28 字节尾。
        Ok(output)
    }

    pub(crate) fn decrypt_packet_impl(&self, packet: &[u8]) -> Result<Vec<u8>, String> {
        if packet.len() < HEADER_SIZE {
            return Err("legacy encrypted packet is shorter than the EasyTier header".to_string());
        }
        let header = PacketHeader::from_bytes(packet)?;
        if header.flags & ENCRYPTED_FLAG == 0 {
            return Ok(packet.to_vec());
        }
        if packet.len() < HEADER_SIZE + LEGACY_AEAD_TAIL_SIZE {
            return Err("legacy encrypted packet is missing the AEAD tail".to_string());
        }
        let ciphertext_len = packet.len() - HEADER_SIZE - LEGACY_AEAD_TAIL_SIZE;
        // 上游 `PeerManagerHeader::len` 字段记录的是密文长度(不含 tag+nonce)。
        // 这里用包实际尺寸反推,不依赖 header.len 字段,容忍对端把 len 写成
        // 整包长度等同的变体实现。
        let tag_start = packet.len() - LEGACY_AEAD_NONCE_SIZE - LEGACY_AEAD_TAG_SIZE;
        let nonce_start = packet.len() - LEGACY_AEAD_NONCE_SIZE;
        let mut tag = [0_u8; LEGACY_AEAD_TAG_SIZE];
        tag.copy_from_slice(&packet[tag_start..tag_start + LEGACY_AEAD_TAG_SIZE]);
        let mut nonce_bytes = [0_u8; LEGACY_AEAD_NONCE_SIZE];
        nonce_bytes.copy_from_slice(&packet[nonce_start..]);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.key_128));

        let mut output = packet[..HEADER_SIZE + ciphertext_len].to_vec();
        cipher
            .decrypt_in_place_detached(
                nonce,
                &[],
                &mut output[HEADER_SIZE..],
                GenericArray::from_slice(&tag),
            )
            .map_err(|_| "legacy AES-128-GCM decryption failed".to_string())?;
        output[9] &= !ENCRYPTED_FLAG;
        Ok(output)
    }
}

#[wasm_bindgen]
impl LegacyCipher {
    /// 用 `network_secret` 派生 AES-128-GCM 密钥。
    #[wasm_bindgen(constructor)]
    pub fn new(network_secret: &str) -> Result<LegacyCipher, JsValue> {
        if network_secret.is_empty() {
            return Err(js_error("network_secret must not be empty"));
        }
        Ok(Self {
            key_128: derive_key_128(network_secret),
        })
    }

    /// 加密一帧未带 AEAD 尾的 EasyTier 包(16 字节头 + 明文 payload)。
    /// 返回 16 字节头(置 ENCRYPTED_FLAG) + 密文 + 16 字节 tag + 12 字节 nonce,
    /// 与上游 `AesGcmCipher::encrypt_with_nonce(None)` 一致。
    pub fn encrypt_packet(&self, packet: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.encrypt_packet_impl(packet).map_err(js_error)
    }

    /// 解密一帧带 AEAD 尾的 EasyTier 包(16 字节头 + 密文 + 16 字节 tag +
    /// 12 字节 nonce)。返回 16 字节头(清 ENCRYPTED_FLAG) + 明文 payload。
    /// 若包未置 ENCRYPTED_FLAG 则原样返回,便于调用方在两种 flag 路径间统一。
    pub fn decrypt_packet(&self, packet: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.decrypt_packet_impl(packet).map_err(js_error)
    }
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

    #[test]
    fn derive_key_128_matches_upstream_reference_vector() {
        // 与上游 `easytier-core/src/tunnel/encrypt/mod.rs` 的
        // `network_secret_key_derivation_is_stable` 单测共用同一参考向量,
        // 防止本模块重写派生算法时悄悄偏离上游 AES-128-GCM 密钥。
        let expected = [
            86u8, 90, 25, 219, 78, 240, 193, 33, 168, 172, 88, 14, 218, 248, 78, 166,
        ];
        assert_eq!(derive_key_128("secret"), expected);
    }

    #[test]
    fn legacy_cipher_round_trips_an_arbitrary_packet() {
        // 构造一个 RpcReq 控制面帧:16 字节头 + 8 字节负载。
        let payload = [0xab; 8];
        let frame = encode_header(123, 10_000_001, 8, &payload);
        assert_eq!(frame[9], 0);

        // `LegacyCipher::new(non_empty_secret)` 的 Ok 路径不构造 JsValue,
        // 可以在非 wasm32 host 上调用。错误路径(空 secret)只通过 TS 单测覆盖。
        let cipher = LegacyCipher::new("et.xiaoyu").unwrap();
        let encrypted = cipher.encrypt_packet_impl(&frame).unwrap();
        assert_eq!(encrypted.len(), frame.len() + LEGACY_AEAD_TAIL_SIZE);
        assert_ne!(&encrypted[HEADER_SIZE..frame.len()], &payload[..]);
        assert_eq!(encrypted[9] & ENCRYPTED_FLAG, ENCRYPTED_FLAG);

        let decrypted = cipher.decrypt_packet_impl(&encrypted).unwrap();
        assert_eq!(decrypted, frame);
        assert_eq!(decrypted[9] & ENCRYPTED_FLAG, 0);
    }

    #[test]
    fn legacy_cipher_returns_input_when_not_encrypted() {
        // 上游 secure-mode 客户端、Ping/Pong 等不带 ENCRYPTED_FLAG 的帧
        // 经过 decrypt_packet 时原样返回,方便服务端在混合路径上调用。
        let payload = [0xcd; 4];
        let frame = encode_header(7, 10_000_001, 4, &payload);
        let cipher = LegacyCipher::new("et.xiaoyu").unwrap();
        let decrypted = cipher.decrypt_packet_impl(&frame).unwrap();
        assert_eq!(decrypted, frame);
    }

    #[test]
    fn legacy_cipher_rejects_wrong_secret_or_tampered_ciphertext() {
        let payload = [0x77; 16];
        let frame = encode_header(42, 10_000_001, 8, &payload);

        let cipher_a = LegacyCipher::new("secret-a").unwrap();
        let cipher_b = LegacyCipher::new("secret-b").unwrap();
        let encrypted = cipher_a.encrypt_packet_impl(&frame).unwrap();

        // 用错误的 network_secret 派生的密钥无法解密。
        assert!(cipher_b.decrypt_packet_impl(&encrypted).is_err());

        // 翻转密文一字节也应导致 AEAD tag 校验失败。
        let mut tampered = encrypted.clone();
        tampered[HEADER_SIZE] ^= 0xff;
        assert!(cipher_a.decrypt_packet_impl(&tampered).is_err());
    }

    #[test]
    fn legacy_cipher_rejects_short_packets() {
        let cipher = LegacyCipher::new("et.xiaoyu").unwrap();
        assert!(cipher.encrypt_packet_impl(&[]).is_err());
        assert!(cipher.decrypt_packet_impl(&[]).is_err());
        // 仅有头部、无 AEAD 尾且 ENCRYPTED_FLAG 已置位的包也要拒绝。
        let mut head_only = vec![0u8; HEADER_SIZE];
        head_only[9] |= ENCRYPTED_FLAG;
        assert!(cipher.decrypt_packet_impl(&head_only).is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
