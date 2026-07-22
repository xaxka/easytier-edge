//! EasyTier 安全节点连接握手与数据报保护。
//!
//! 本模块移植 `peer_conn.rs` 与 `secure_datagram.rs` 中可在 WebAssembly 运行的部分：
//! Noise XX 认证、网络密钥证明和分代流量密钥。WebSocket 句柄由 Workers 运行时持有，
//! 因此连接生命周期保留在 TypeScript 层。

use std::{cell::RefCell, collections::HashMap};

use aes_gcm::{
    AeadInPlace as _, Aes128Gcm, Aes256Gcm, KeyInit as _, Nonce,
    aead::generic_array::GenericArray,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac as _};
use prost::Message as _;
use serde::Serialize;
use sha2::Sha256;
use snow::{Builder, HandshakeState, params::NoiseParams};
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    packet::{AEAD_TAIL_SIZE, ENCRYPTED_FLAG, HEADER_SIZE, PacketHeader, parse_packet},
    proto::{
        common::Uuid,
        peer_rpc::{
            PeerConnNoiseMsg1Pb, PeerConnNoiseMsg2Pb, PeerConnNoiseMsg3Pb,
            PeerConnSessionActionPb,
        },
    },
};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const NOISE_PROLOGUE: &[u8] = b"easytier-peerconn-noise";
const EASYTIER_PROTOCOL_VERSION: u32 = 1;
const SERVER_ENCRYPTION_ALGORITHM: &str = "aes-gcm";
const PACKET_NOISE_MSG1: u8 = 13;
const PACKET_NOISE_MSG2: u8 = 14;
const AEAD_TAG_SIZE: usize = 16;
const AEAD_NONCE_SIZE: usize = 12;
const RX_EPOCH_IDLE_MS: u64 = 30_000;
const ROTATE_AFTER_PACKETS: u64 = 1_000_000;
const ROTATE_AFTER_MS: u64 = 10 * 60 * 1_000;
const MAX_ACCEPTED_RX_EPOCH_AHEAD: u32 = 3;
const DECRYPT_FAIL_THRESHOLD: u32 = 10;
const SYNC_RX_GRACE_AFTER_MS: u64 = 5_000;
const SESSION_IDLE_MS: u64 = 60_000;
const MAX_STORED_SESSIONS: usize = 2_048;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SessionKey {
    network_name: String,
    peer_id: u32,
    server_peer_id: u32,
    server_public_key: [u8; 32],
}

#[derive(Debug, Clone)]
struct StoredSession {
    root_key: [u8; 32],
    generation: u32,
    next_epoch: u32,
    send_seq: [u64; 2],
    send_epoch_started_ms: u64,
    send_packets_since_epoch: u64,
    rx_slots: [[EpochRxSlot; 2]; 2],
    sync_rx_grace: SyncRxGrace,
    decrypt_fail_count: u32,
    client_algorithm: String,
    remote_public_key: Option<[u8; 32]>,
    last_touch_ms: u64,
    attachments: u32,
}

struct SessionSelection {
    action: i32,
    generation: u32,
    root_key_for_peer: Option<[u8; 32]>,
    session_root_key: [u8; 32],
    initial_epoch: u32,
}

thread_local! {
    static SESSION_STORE: RefCell<HashMap<SessionKey, StoredSession>> = RefCell::new(HashMap::new());
}

#[derive(Debug, Clone, Copy, Default)]
struct ReplayWindow256 {
    max_seq: u64,
    bitmap: [u8; 32],
    valid: bool,
}

impl ReplayWindow256 {
    fn clear(&mut self) {
        self.max_seq = 0;
        self.bitmap.fill(0);
        self.valid = false;
    }

    fn test_bit(&self, idx: usize) -> bool {
        let byte = idx / 8;
        let bit = idx % 8;
        (self.bitmap[byte] >> bit) & 1 == 1
    }

    fn set_bit(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bitmap[byte] |= 1_u8 << bit;
    }

    fn shift_right(&mut self, shift: usize) {
        if shift == 0 {
            return;
        }
        if shift >= 256 {
            self.bitmap.fill(0);
            return;
        }

        let byte_shift = shift / 8;
        let bit_shift = shift % 8;
        if byte_shift > 0 {
            for i in (0..self.bitmap.len()).rev() {
                self.bitmap[i] = if i >= byte_shift {
                    self.bitmap[i - byte_shift]
                } else {
                    0
                };
            }
        }
        if bit_shift > 0 {
            let mut carry = 0_u8;
            for byte in &mut self.bitmap {
                let next_carry = *byte >> (8 - bit_shift);
                *byte = (*byte << bit_shift) | carry;
                carry = next_carry;
            }
        }
    }

    fn can_accept(&self, seq: u64) -> bool {
        if !self.valid || seq > self.max_seq {
            return true;
        }
        let delta = (self.max_seq - seq) as usize;
        delta < 256 && !self.test_bit(delta)
    }

    fn accept(&mut self, seq: u64) -> bool {
        if !self.valid {
            self.valid = true;
            self.max_seq = seq;
            self.set_bit(0);
            return true;
        }
        if seq > self.max_seq {
            self.shift_right((seq - self.max_seq) as usize);
            self.max_seq = seq;
            self.set_bit(0);
            return true;
        }

        let delta = (self.max_seq - seq) as usize;
        if delta >= 256 || self.test_bit(delta) {
            return false;
        }
        self.set_bit(delta);
        true
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct EpochRxSlot {
    epoch: u32,
    window: ReplayWindow256,
    last_rx_ms: u64,
    valid: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct SyncRxGrace {
    slots: [[EpochRxSlot; 2]; 2],
    expires_at_ms: u64,
    valid: bool,
}

impl EpochRxSlot {
    fn clear(&mut self) {
        self.epoch = 0;
        self.window.clear();
        self.last_rx_ms = 0;
        self.valid = false;
    }
}

#[derive(Serialize)]
struct Msg1Info {
    peer_id: u32,
    network_name: String,
    client_encryption_algorithm: String,
}

#[derive(Serialize)]
struct AuthInfo {
    peer_id: u32,
    network_name: String,
    remote_public_key_base64: String,
    auth_level: &'static str,
}

#[wasm_bindgen]
pub struct SecurePeer {
    local_private: [u8; 32],
    local_public: [u8; 32],
    server_peer_id: u32,
    peer_id: Option<u32>,
    network_name: Option<String>,
    client_algorithm: Option<String>,
    a_session_generation: Option<u32>,
    a_conn_id: Option<Uuid>,
    b_conn_id: Option<Uuid>,
    handshake: Option<HandshakeState>,
    proof_challenge: Option<Vec<u8>>,
    network_secret: Option<Vec<u8>>,
    root_key: Option<[u8; 32]>,
    session_key: Option<SessionKey>,
    session_attached: bool,
    send_epoch: u32,
    send_seq: [u64; 2],
    send_epoch_started_ms: u64,
    send_packets_since_epoch: u64,
    rx_slots: [[EpochRxSlot; 2]; 2],
    sync_rx_grace: SyncRxGrace,
    decrypt_fail_count: u32,
    authenticated: bool,
}

#[wasm_bindgen]
impl SecurePeer {
    #[wasm_bindgen(constructor)]
    pub fn new(
        local_private_key_base64: &str,
        local_public_key_base64: &str,
        server_peer_id: u32,
    ) -> Result<SecurePeer, JsValue> {
        if server_peer_id == 0 {
            return Err(js_error("server peer id must not be zero"));
        }
        let private = decode_key(local_private_key_base64, "private")?;
        let configured_public = decode_key(local_public_key_base64, "public")?;
        let derived_public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        if derived_public != configured_public {
            return Err(js_error("local_public_key does not match local_private_key"));
        }

        Ok(Self {
            local_private: private,
            local_public: configured_public,
            server_peer_id,
            peer_id: None,
            network_name: None,
            client_algorithm: None,
            a_session_generation: None,
            a_conn_id: None,
            b_conn_id: None,
            handshake: None,
            proof_challenge: None,
            network_secret: None,
            root_key: None,
            session_key: None,
            session_attached: false,
            send_epoch: 0,
            send_seq: [0, 0],
            send_epoch_started_ms: now_ms(),
            send_packets_since_epoch: 0,
            rx_slots: [[EpochRxSlot::default(); 2]; 2],
            sync_rx_grace: SyncRxGrace::default(),
            decrypt_fail_count: 0,
            authenticated: false,
        })
    }

    /// 解析 EasyTier Noise 消息一并返回连接请求的网络。
    /// 网络密钥必须在此步骤之后由 TypeScript 房间白名单选择。
    pub fn read_msg1(&mut self, packet: &[u8]) -> Result<String, JsValue> {
        if self.handshake.is_some() || self.authenticated {
            return Err(js_error("handshake already started"));
        }
        let (header, payload) = split_packet(packet)?;
        if header.packet_type != PACKET_NOISE_MSG1 || header.flags & ENCRYPTED_FLAG != 0 {
            return Err(js_error("secure mode requires an unencrypted NoiseHandshakeMsg1"));
        }
        if header.from_peer_id == 0 || header.from_peer_id == self.server_peer_id {
            return Err(js_error("invalid or conflicting client peer id"));
        }

        let params: NoiseParams = NOISE_PATTERN.parse().map_err(display_error)?;
        let mut handshake = Builder::new(params)
            .prologue(NOISE_PROLOGUE)
            .map_err(display_error)?
            .local_private_key(&self.local_private)
            .map_err(display_error)?
            .build_responder()
            .map_err(display_error)?;
        let mut decoded = vec![0_u8; 4096];
        let decoded_len = handshake
            .read_message(payload, &mut decoded)
            .map_err(display_error)?;
        let message = PeerConnNoiseMsg1Pb::decode(&decoded[..decoded_len]).map_err(display_error)?;
        if message.version != EASYTIER_PROTOCOL_VERSION {
            return Err(js_error("unsupported EasyTier secure handshake version"));
        }
        if message.a_network_name.is_empty() || message.a_network_name.len() > 255 {
            return Err(js_error("invalid network_name"));
        }
        validate_algorithm(&message.client_encryption_algorithm)?;

        self.peer_id = Some(header.from_peer_id);
        self.network_name = Some(message.a_network_name.clone());
        self.client_algorithm = Some(message.client_encryption_algorithm.clone());
        self.a_session_generation = message.a_session_generation;
        self.a_conn_id = message.a_conn_id;
        self.handshake = Some(handshake);

        serde_json::to_string(&Msg1Info {
            peer_id: header.from_peer_id,
            network_name: message.a_network_name,
            client_encryption_algorithm: message.client_encryption_algorithm,
        })
        .map_err(display_error)
    }

    /// 为已明确配置的房间生成 EasyTier Noise 消息二。
    pub fn build_msg2(&mut self, network_secret: &str) -> Result<Vec<u8>, JsValue> {
        if network_secret.is_empty() {
            return Err(js_error("network_secret must not be empty"));
        }
        if self.session_key.is_some() {
            return Err(js_error("message 2 was already built"));
        }
        let peer_id = self.peer_id.ok_or_else(|| js_error("message 1 not received"))?;
        let network_name = self
            .network_name
            .clone()
            .ok_or_else(|| js_error("message 1 has no network"))?;
        let handshake = self
            .handshake
            .as_mut()
            .ok_or_else(|| js_error("message 1 not received"))?;

        let proof = secret_proof(network_secret.as_bytes(), handshake.get_handshake_hash())?;
        let session_key = SessionKey {
            network_name: network_name.clone(),
            peer_id,
            server_peer_id: self.server_peer_id,
            server_public_key: self.local_public,
        };
        let client_algorithm = self
            .client_algorithm
            .as_deref()
            .ok_or_else(|| js_error("message 1 has no encryption algorithm"))?;
        let session = upsert_session(
            &session_key,
            self.a_session_generation,
            client_algorithm,
        )?;
        let b_conn_id = random_uuid()?;
        let message = PeerConnNoiseMsg2Pb {
            b_network_name: network_name,
            role_hint: 1,
            action: session.action,
            b_session_generation: session.generation,
            root_key_32: session.root_key_for_peer.map(|key| key.to_vec()),
            initial_epoch: session.initial_epoch,
            b_conn_id: Some(b_conn_id.clone()),
            a_conn_id_echo: self.a_conn_id.clone(),
            secret_proof_32: Some(proof),
            server_encryption_algorithm: SERVER_ENCRYPTION_ALGORITHM.to_string(),
        };
        let mut noise_message = vec![0_u8; 4096];
        let len = handshake
            .write_message(&message.encode_to_vec(), &mut noise_message)
            .map_err(display_error)?;
        noise_message.truncate(len);

        self.proof_challenge = Some(handshake.get_handshake_hash().to_vec());
        self.network_secret = Some(network_secret.as_bytes().to_vec());
        self.root_key = Some(session.session_root_key);
        self.session_key = Some(session_key);
        self.attach_session()?;
        self.load_session_state()?;
        self.b_conn_id = Some(b_conn_id);

        Ok(wrap_packet(
            self.server_peer_id,
            peer_id,
            PACKET_NOISE_MSG2,
            0,
            &noise_message,
        ))
    }

    /// 完成 Noise XX 交换并验证客户端对房间密钥的 HMAC 证明。
    /// 连接在此步骤成功前不可参与路由。
    pub fn finish_msg3(&mut self, packet: &[u8]) -> Result<String, JsValue> {
        let (header, payload) = split_packet(packet)?;
        let peer_id = self.peer_id.ok_or_else(|| js_error("message 1 not received"))?;
        if header.packet_type != 15
            || header.from_peer_id != peer_id
            || header.to_peer_id != self.server_peer_id
            || header.flags & ENCRYPTED_FLAG != 0
        {
            return Err(js_error("invalid NoiseHandshakeMsg3 envelope"));
        }
        let mut handshake = self
            .handshake
            .take()
            .ok_or_else(|| js_error("message 2 not sent"))?;
        let mut decoded = vec![0_u8; 4096];
        let decoded_len = handshake
            .read_message(payload, &mut decoded)
            .map_err(display_error)?;
        let message = PeerConnNoiseMsg3Pb::decode(&decoded[..decoded_len]).map_err(display_error)?;
        if message.a_conn_id_echo != self.a_conn_id || message.b_conn_id_echo != self.b_conn_id {
            return Err(js_error("Noise connection id echo mismatch"));
        }
        let proof = message
            .secret_proof_32
            .as_deref()
            .ok_or_else(|| js_error("client did not provide a network-secret proof"))?;
        let secret = self
            .network_secret
            .as_deref()
            .ok_or_else(|| js_error("network secret is not selected"))?;
        let challenge = self
            .proof_challenge
            .as_deref()
            .ok_or_else(|| js_error("proof challenge is missing"))?;
        let mut verifier = <HmacSha256 as hmac::Mac>::new_from_slice(secret).map_err(display_error)?;
        verifier.update(b"easytier secret proof");
        verifier.update(challenge);
        verifier
            .verify_slice(proof)
            .map_err(|_| js_error("network-secret proof verification failed"))?;

        let remote_public = handshake
            .get_remote_static()
            .filter(|key| key.len() == 32)
            .ok_or_else(|| js_error("client Noise static public key is missing"))?;
        let remote_public_key: [u8; 32] = remote_public
            .try_into()
            .map_err(|_| js_error("client Noise static public key must be 32 bytes"))?;
        let session_key = self
            .session_key
            .as_ref()
            .ok_or_else(|| js_error("secure session key is missing"))?;
        confirm_session_public_key(session_key, remote_public_key)?;
        self.authenticated = true;

        serde_json::to_string(&AuthInfo {
            peer_id,
            network_name: self.network_name.clone().unwrap_or_default(),
            remote_public_key_base64: BASE64_STANDARD.encode(remote_public),
            auth_level: "NetworkSecretConfirmed",
        })
        .map_err(display_error)
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// 使用 EasyTier 分代流量密钥解密节点直达服务器的数据包。
    /// 节点间转发包必须绕过此方法并保持原始密文。
    pub fn decrypt_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.ensure_authenticated()?;
        self.load_session_state()?;
        let (header, payload) = split_packet(packet)?;
        let peer_id = self.peer_id.unwrap();
        if header.from_peer_id != peer_id || header.to_peer_id != self.server_peer_id {
            return Err(js_error("packet is not addressed over this direct session"));
        }
        if header.flags & ENCRYPTED_FLAG == 0 {
            return Ok(packet.to_vec());
        }
        let algorithm = self
            .client_algorithm
            .clone()
            .unwrap_or_else(|| "aes-gcm".to_string());
        let direction = direction_index(header.from_peer_id, header.to_peer_id);
        let result = self.decrypt_payload(&algorithm, direction, payload);
        self.persist_session_state()?;
        let Some(plaintext) = result? else {
            return Ok(Vec::new());
        };
        let mut clear_header = header;
        clear_header.flags &= !ENCRYPTED_FLAG;
        Ok(join_header_payload(clear_header, &plaintext))
    }

    /// 加密服务器发往节点的控制包。Ping、Pong 和 Noise 帧由 TypeScript 直接发送。
    pub fn encrypt_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.ensure_authenticated()?;
        self.load_session_state()?;
        let (header, payload) = split_packet(packet)?;
        let peer_id = self.peer_id.unwrap();
        if header.from_peer_id != self.server_peer_id || header.to_peer_id != peer_id {
            return Err(js_error("packet is not addressed over this direct session"));
        }
        if header.flags & ENCRYPTED_FLAG != 0 {
            return Err(js_error("packet is already encrypted"));
        }
        let direction = direction_index(header.from_peer_id, header.to_peer_id);
        let result = self.encrypt_payload(SERVER_ENCRYPTION_ALGORITHM, direction, payload);
        self.persist_session_state()?;
        let encrypted = result?;
        let mut encrypted_header = header;
        encrypted_header.flags |= ENCRYPTED_FLAG;
        Ok(join_header_payload(encrypted_header, &encrypted))
    }
}

impl SecurePeer {
    fn attach_session(&mut self) -> Result<(), JsValue> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| js_error("secure session key is missing"))?;
        SESSION_STORE.with(|store| -> Result<(), JsValue> {
            let mut sessions = store.borrow_mut();
            let session = sessions
                .get_mut(key)
                .ok_or_else(|| js_error("secure session disappeared while attaching connection"))?;
            session.attachments = session
                .attachments
                .checked_add(1)
                .ok_or_else(|| js_error("secure session attachment count exhausted"))?;
            session.last_touch_ms = now_ms();
            Ok(())
        })?;
        self.session_attached = true;
        Ok(())
    }

    fn load_session_state(&mut self) -> Result<(), JsValue> {
        let key = self
            .session_key
            .clone()
            .ok_or_else(|| js_error("secure session key is missing"))?;
        SESSION_STORE.with(|store| {
            let sessions = store.borrow();
            let session = sessions
                .get(&key)
                .ok_or_else(|| js_error("secure session disappeared while loading state"))?;
            self.root_key = Some(session.root_key);
            self.send_epoch = session.next_epoch;
            self.send_seq = session.send_seq;
            self.send_epoch_started_ms = session.send_epoch_started_ms;
            self.send_packets_since_epoch = session.send_packets_since_epoch;
            self.rx_slots = session.rx_slots;
            self.sync_rx_grace = session.sync_rx_grace;
            self.decrypt_fail_count = session.decrypt_fail_count;
            Ok(())
        })
    }

    fn persist_session_state(&self) -> Result<(), JsValue> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| js_error("secure session key is missing"))?;
        SESSION_STORE.with(|store| {
            let mut sessions = store.borrow_mut();
            let session = sessions
                .get_mut(key)
                .ok_or_else(|| js_error("secure session disappeared while saving state"))?;
            session.next_epoch = self.send_epoch;
            session.send_seq = self.send_seq;
            session.send_epoch_started_ms = self.send_epoch_started_ms;
            session.send_packets_since_epoch = self.send_packets_since_epoch;
            session.rx_slots = self.rx_slots;
            session.sync_rx_grace = self.sync_rx_grace;
            session.decrypt_fail_count = self.decrypt_fail_count;
            session.last_touch_ms = now_ms();
            Ok(())
        })
    }

    fn ensure_authenticated(&self) -> Result<(), JsValue> {
        if self.authenticated && self.root_key.is_some() {
            Ok(())
        } else {
            Err(js_error("secure session is not authenticated"))
        }
    }

    fn traffic_key(&self, epoch: u32, direction: usize) -> Result<[u8; 32], JsValue> {
        let root_key = self.root_key.ok_or_else(|| js_error("root key is missing"))?;
        let mut extract = <HmacSha256 as hmac::Mac>::new_from_slice(&[0_u8; 32])
            .map_err(display_error)?;
        extract.update(&root_key);
        let prk = extract.finalize().into_bytes();
        let mut expand = <HmacSha256 as hmac::Mac>::new_from_slice(&prk).map_err(display_error)?;
        expand.update(b"et-traffic");
        expand.update(&epoch.to_be_bytes());
        expand.update(&[direction as u8]);
        expand.update(&[1]);
        let bytes = expand.finalize().into_bytes();
        let mut key = [0_u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    fn encrypt_payload(
        &mut self,
        algorithm: &str,
        direction: usize,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        self.maybe_rotate_epoch();
        let epoch = self.send_epoch;
        let sequence = self.send_seq[direction];
        self.send_seq[direction] = sequence
            .checked_add(1)
            .ok_or_else(|| js_error("secure packet sequence exhausted"))?;
        let mut nonce_bytes = [0_u8; AEAD_NONCE_SIZE];
        nonce_bytes[..4].copy_from_slice(&epoch.to_be_bytes());
        nonce_bytes[4..].copy_from_slice(&sequence.to_be_bytes());
        let key = self.traffic_key(epoch, direction)?;
        let (ciphertext, tag) = seal(algorithm, &key, &nonce_bytes, plaintext)?;
        let mut output = ciphertext;
        output.extend_from_slice(&tag);
        output.extend_from_slice(&nonce_bytes);
        Ok(output)
    }

    fn decrypt_payload(
        &mut self,
        algorithm: &str,
        direction: usize,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, JsValue> {
        if payload.len() < AEAD_TAIL_SIZE {
            return Err(js_error("encrypted EasyTier payload is too short"));
        }
        let text_len = payload.len() - AEAD_TAIL_SIZE;
        let tag: [u8; AEAD_TAG_SIZE] = payload[text_len..text_len + AEAD_TAG_SIZE]
            .try_into()
            .map_err(|_| js_error("invalid AEAD tag"))?;
        let nonce: [u8; AEAD_NONCE_SIZE] = payload[text_len + AEAD_TAG_SIZE..]
            .try_into()
            .map_err(|_| js_error("invalid AEAD nonce"))?;
        let epoch = u32::from_be_bytes(nonce[..4].try_into().unwrap());
        let sequence = u64::from_be_bytes(nonce[4..].try_into().unwrap());
        let received_at_ms = now_ms();
        self.evict_old_rx_slots(received_at_ms);
        if !self.precheck_replay(epoch, sequence, direction) {
            return Ok(None);
        }
        let key = self.traffic_key(epoch, direction)?;
        let plaintext = match open(algorithm, &key, &nonce, &payload[..text_len], &tag) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                self.decrypt_fail_count = self.decrypt_fail_count.saturating_add(1);
                if self.decrypt_fail_count >= DECRYPT_FAIL_THRESHOLD {
                    return Err(error);
                }
                return Ok(None);
            }
        };
        self.decrypt_fail_count = 0;
        if !self.commit_replay(epoch, sequence, direction, received_at_ms) {
            return Ok(None);
        }
        Ok(Some(plaintext))
    }

    fn maybe_rotate_epoch(&mut self) {
        let current_ms = now_ms();
        self.send_packets_since_epoch = self.send_packets_since_epoch.saturating_add(1);
        if self.send_packets_since_epoch < ROTATE_AFTER_PACKETS
            && current_ms.saturating_sub(self.send_epoch_started_ms) < ROTATE_AFTER_MS
        {
            return;
        }
        self.send_epoch = self.send_epoch.wrapping_add(1);
        self.send_epoch_started_ms = current_ms;
        self.send_packets_since_epoch = 0;
    }

    fn evict_old_rx_slots(&mut self, current_ms: u64) {
        Self::evict_slots(&mut self.rx_slots, current_ms);
        if self.sync_rx_grace.valid && current_ms >= self.sync_rx_grace.expires_at_ms {
            self.sync_rx_grace = SyncRxGrace::default();
        } else if self.sync_rx_grace.valid {
            Self::evict_slots(&mut self.sync_rx_grace.slots, current_ms);
        }
    }

    fn evict_slots(slots: &mut [[EpochRxSlot; 2]; 2], current_ms: u64) {
        for direction_slots in slots {
            for slot in direction_slots {
                if slot.valid
                    && slot.last_rx_ms != 0
                    && current_ms.saturating_sub(slot.last_rx_ms) > RX_EPOCH_IDLE_MS
                {
                    slot.clear();
                }
            }
        }
    }

    fn precheck_replay(&self, epoch: u32, sequence: u64, direction: usize) -> bool {
        if self.sync_rx_grace.valid {
            for slot in &self.sync_rx_grace.slots[direction] {
                if slot.valid && slot.epoch == epoch {
                    return slot.window.can_accept(sequence);
                }
            }
        }
        let slots = &self.rx_slots[direction];
        if !slots[0].valid {
            return true;
        }
        if slots[0].epoch == epoch {
            return slots[0].window.can_accept(sequence);
        }
        if slots[1].valid && slots[1].epoch == epoch {
            return slots[1].window.can_accept(sequence);
        }
        if epoch > slots[0].epoch {
            let mut baseline_epoch = self.send_epoch.max(slots[0].epoch);
            if slots[1].valid {
                baseline_epoch = baseline_epoch.max(slots[1].epoch);
            }
            return epoch <= baseline_epoch.saturating_add(MAX_ACCEPTED_RX_EPOCH_AHEAD);
        }
        false
    }

    fn commit_replay(
        &mut self,
        epoch: u32,
        sequence: u64,
        direction: usize,
        received_at_ms: u64,
    ) -> bool {
        if self.sync_rx_grace.valid {
            for slot in &mut self.sync_rx_grace.slots[direction] {
                if slot.valid && slot.epoch == epoch {
                    slot.last_rx_ms = received_at_ms;
                    return slot.window.accept(sequence);
                }
            }
        }
        let slots = &mut self.rx_slots[direction];
        if !slots[0].valid {
            slots[0] = EpochRxSlot {
                epoch,
                window: ReplayWindow256::default(),
                last_rx_ms: received_at_ms,
                valid: true,
            };
        }
        if slots[0].epoch == epoch {
            slots[0].last_rx_ms = received_at_ms;
            return slots[0].window.accept(sequence);
        }
        if slots[1].valid && slots[1].epoch == epoch {
            slots[1].last_rx_ms = received_at_ms;
            return slots[1].window.accept(sequence);
        }
        if epoch > slots[0].epoch {
            slots[1] = slots[0];
            slots[0] = EpochRxSlot {
                epoch,
                window: ReplayWindow256::default(),
                last_rx_ms: received_at_ms,
                valid: true,
            };
            return slots[0].window.accept(sequence);
        }
        false
    }
}

impl Drop for SecurePeer {
    fn drop(&mut self) {
        if !self.session_attached {
            return;
        }
        let Some(key) = self.session_key.as_ref() else {
            return;
        };
        SESSION_STORE.with(|store| {
            if let Some(session) = store.borrow_mut().get_mut(key) {
                session.attachments = session.attachments.saturating_sub(1);
                session.last_touch_ms = now_ms();
            }
        });
    }
}

fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

fn seal(
    algorithm: &str,
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), JsValue> {
    let mut output = plaintext.to_vec();
    let nonce = Nonce::from_slice(nonce);
    let tag = match normalized_algorithm(algorithm)? {
        "aes-gcm" => Aes128Gcm::new(GenericArray::from_slice(&key[..16]))
            .encrypt_in_place_detached(nonce, &[], &mut output)
            .map_err(|_| js_error("AES-128-GCM encryption failed"))?,
        "aes-256-gcm" => Aes256Gcm::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(nonce, &[], &mut output)
            .map_err(|_| js_error("AES-256-GCM encryption failed"))?,
        "chacha20" => ChaCha20Poly1305::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(nonce, &[], &mut output)
            .map_err(|_| js_error("ChaCha20-Poly1305 encryption failed"))?,
        _ => unreachable!(),
    };
    Ok((output, tag.into()))
}

fn open(
    algorithm: &str,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, JsValue> {
    let mut output = ciphertext.to_vec();
    let nonce = Nonce::from_slice(nonce);
    let tag = GenericArray::from_slice(tag);
    let result = match normalized_algorithm(algorithm)? {
        "aes-gcm" => Aes128Gcm::new(GenericArray::from_slice(&key[..16]))
            .decrypt_in_place_detached(nonce, &[], &mut output, tag),
        "aes-256-gcm" => Aes256Gcm::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(nonce, &[], &mut output, tag),
        "chacha20" => ChaCha20Poly1305::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(nonce, &[], &mut output, tag),
        _ => unreachable!(),
    };
    result.map_err(|_| js_error("EasyTier session decryption failed"))?;
    Ok(output)
}

fn normalized_algorithm(value: &str) -> Result<&'static str, JsValue> {
    if value.eq_ignore_ascii_case("aes-gcm") {
        Ok("aes-gcm")
    } else if value.eq_ignore_ascii_case("aes-256-gcm") {
        Ok("aes-256-gcm")
    } else if value.eq_ignore_ascii_case("chacha20")
        || value.eq_ignore_ascii_case("chacha20-poly1305")
    {
        Ok("chacha20")
    } else {
        Err(js_error("unsupported EasyTier encryption algorithm"))
    }
}

fn validate_algorithm(value: &str) -> Result<(), JsValue> {
    normalized_algorithm(value).map(|_| ())
}

fn direction_index(sender: u32, receiver: u32) -> usize {
    usize::from(sender >= receiver)
}

fn secret_proof(secret: &[u8], challenge: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(secret).map_err(display_error)?;
    mac.update(b"easytier secret proof");
    mac.update(challenge);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn upsert_session(
    key: &SessionKey,
    a_session_generation: Option<u32>,
    client_algorithm: &str,
) -> Result<SessionSelection, JsValue> {
    let current_ms = now_ms();
    let (existing, session_count) = SESSION_STORE.with(|store| {
        let mut sessions = store.borrow_mut();
        sessions.retain(|_, session| {
            session.attachments > 0
                || current_ms.saturating_sub(session.last_touch_ms) < SESSION_IDLE_MS
        });
        (sessions.get(key).cloned(), sessions.len())
    });

    if let Some(mut session) = existing {
        if session.client_algorithm != client_algorithm {
            return Err(js_error(
                "reconnecting peer changed its secure-session encryption algorithm",
            ));
        }
        if a_session_generation == Some(session.generation) {
            session.last_touch_ms = current_ms;
            let root_key = session.root_key;
            let generation = session.generation;
            SESSION_STORE.with(|store| {
                store.borrow_mut().insert(key.clone(), session);
            });
            return Ok(SessionSelection {
                action: PeerConnSessionActionPb::Join as i32,
                generation,
                root_key_for_peer: None,
                session_root_key: root_key,
                initial_epoch: 0,
            });
        }

        let mut sync_epoch = session.next_epoch;
        for direction_slots in session.rx_slots {
            for slot in direction_slots {
                if slot.valid {
                    sync_epoch = sync_epoch.max(slot.epoch);
                }
            }
        }
        session.next_epoch = sync_epoch.wrapping_add(1);
        session.send_seq = [0, 0];
        session.send_epoch_started_ms = current_ms;
        session.send_packets_since_epoch = 0;
        session.sync_rx_grace = SyncRxGrace {
            slots: session.rx_slots,
            expires_at_ms: current_ms.saturating_add(SYNC_RX_GRACE_AFTER_MS),
            valid: true,
        };
        session.rx_slots = [[EpochRxSlot::default(); 2]; 2];
        session.decrypt_fail_count = 0;
        session.last_touch_ms = current_ms;
        SESSION_STORE.with(|store| {
            store.borrow_mut().insert(key.clone(), session.clone());
        });
        return Ok(SessionSelection {
            action: PeerConnSessionActionPb::Sync as i32,
            generation: session.generation,
            root_key_for_peer: Some(session.root_key),
            session_root_key: session.root_key,
            initial_epoch: session.next_epoch,
        });
    }

    if session_count >= MAX_STORED_SESSIONS {
        return Err(js_error("secure peer session capacity exceeded"));
    }

    let root_key = random_32()?;
    let session = StoredSession {
        root_key,
        generation: 1,
        next_epoch: 0,
        send_seq: [0, 0],
        send_epoch_started_ms: current_ms,
        send_packets_since_epoch: 0,
        rx_slots: [[EpochRxSlot::default(); 2]; 2],
        sync_rx_grace: SyncRxGrace::default(),
        decrypt_fail_count: 0,
        client_algorithm: client_algorithm.to_string(),
        remote_public_key: None,
        last_touch_ms: current_ms,
        attachments: 0,
    };
    SESSION_STORE.with(|store| {
        store.borrow_mut().insert(key.clone(), session);
    });
    Ok(SessionSelection {
        action: PeerConnSessionActionPb::Create as i32,
        generation: 1,
        root_key_for_peer: Some(root_key),
        session_root_key: root_key,
        initial_epoch: 0,
    })
}

fn confirm_session_public_key(
    key: &SessionKey,
    remote_public_key: [u8; 32],
) -> Result<(), JsValue> {
    SESSION_STORE.with(|store| {
        let mut sessions = store.borrow_mut();
        let session = sessions
            .get_mut(key)
            .ok_or_else(|| js_error("secure session disappeared during authentication"))?;
        if session
            .remote_public_key
            .is_some_and(|current| current != remote_public_key)
        {
            return Err(js_error(
                "reconnecting peer changed its Noise static public key",
            ));
        }
        session.remote_public_key = Some(remote_public_key);
        session.last_touch_ms = now_ms();
        Ok(())
    })
}

fn random_32() -> Result<[u8; 32], JsValue> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(display_error)?;
    Ok(bytes)
}

fn random_uuid() -> Result<Uuid, JsValue> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(display_error)?;
    Ok(Uuid {
        part1: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
        part2: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
        part3: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
        part4: u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
    })
}

fn decode_key(value: &str, label: &str) -> Result<[u8; 32], JsValue> {
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| js_error(&format!("local_{label}_key is not valid base64")))?;
    decoded
        .try_into()
        .map_err(|bytes: Vec<u8>| js_error(&format!("local_{label}_key must decode to 32 bytes, got {}", bytes.len())))
}

fn split_packet(bytes: &[u8]) -> Result<(PacketHeader, &[u8]), JsValue> {
    let header = parse_packet(bytes).map_err(|message| js_error(&message))?;
    let payload = &bytes[HEADER_SIZE..];
    Ok((header, payload))
}

fn wrap_packet(from: u32, to: u32, packet_type: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    join_header_payload(
        PacketHeader {
            from_peer_id: from,
            to_peer_id: to,
            packet_type,
            flags,
            forward_counter: 1,
            reserved: 0,
            len: payload.len() as u32,
        },
        payload,
    )
}

fn join_header_payload(header: PacketHeader, payload: &[u8]) -> Vec<u8> {
    let mut output = header.to_bytes();
    output.extend_from_slice(payload);
    output
}

fn js_error(message: &str) -> JsValue {
    JsValue::from_str(message)
}

fn display_error(error: impl std::fmt::Display) -> JsValue {
    js_error(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_direction_is_stable() {
        assert_eq!(direction_index(1, 2), 0);
        assert_eq!(direction_index(2, 1), 1);
    }
}
