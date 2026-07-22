use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};

use prost::Message;
use wasm_bindgen::JsValue;

use crate::proto::peer_rpc::{
    DirectConnectedPeerInfo, GetGlobalPeerMapRequest, GetGlobalPeerMapResponse,
    PeerInfoForGlobalMap, ReportPeersRequest, ReportPeersResponse,
};

pub type Digest = u64;
pub type PeerId = u32;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SrcDstPeerPair {
    src: PeerId,
    dst: PeerId,
}

#[derive(Debug, Clone)]
struct PeerCenterInfoEntry {
    info: DirectConnectedPeerInfo,
    update_time_ms: u64,
}

#[derive(Default, Clone)]
struct PeerCenterGroupData {
    global_peer_map: HashMap<SrcDstPeerPair, PeerCenterInfoEntry>,
    peer_report_time: HashMap<PeerId, u64>,
    digest: Digest,
}

/// EasyTier PeerCenter 状态管理器，逻辑移植自 peer_center/server.rs。
pub(crate) struct PeerCenter {
    groups: HashMap<String, PeerCenterGroupData>,
}

impl PeerCenter {
    pub(crate) fn new() -> Self {
        PeerCenter {
            groups: HashMap::new(),
        }
    }

    fn group_mut(&mut self, group_key: &str) -> &mut PeerCenterGroupData {
        self.groups
            .entry(group_key.to_string())
            .or_default()
    }

    fn calc_digest_internal(data: &PeerCenterGroupData) -> Digest {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let mut keys: Vec<_> = data.global_peer_map.keys().collect();
        keys.sort();
        for key in keys {
            key.hash(&mut hasher);
            data.global_peer_map[key].info.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// 上报指定房间的节点。
    /// `report_bytes` 是 protobuf 编码的 `ReportPeersRequest`。
    /// 返回编码后的 `ReportPeersResponse`。
    pub(crate) fn report_peers(
        &mut self,
        group_key: &str,
        authenticated_peer_id: PeerId,
        report_bytes: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let req = ReportPeersRequest::decode(report_bytes)
            .map_err(|e| JsValue::from_str(&format!("decode ReportPeersRequest failed: {}", e)))?;

        let my_peer_id = req.my_peer_id;
        if my_peer_id != authenticated_peer_id {
            return Err(JsValue::from_str(
                "ReportPeersRequest peer id does not match the authenticated connection",
            ));
        }
        let peers = req.peer_infos.unwrap_or_default();
        let now_ms = js_sys::Date::now() as u64;

        let data = self.group_mut(group_key);
        data.peer_report_time.insert(my_peer_id, now_ms);

        for (peer_id, peer_info) in peers.direct_peers {
            let pair = SrcDstPeerPair {
                src: my_peer_id,
                dst: peer_id,
            };
            let entry = PeerCenterInfoEntry {
                info: peer_info,
                update_time_ms: now_ms,
            };
            data.global_peer_map.insert(pair, entry);
        }

        data.digest = Self::calc_digest_internal(data);

        let resp = ReportPeersResponse::default();
        let mut buf = Vec::new();
        prost::Message::encode(&resp, &mut buf)
            .map_err(|e| JsValue::from_str(&format!("encode ReportPeersResponse failed: {}", e)))?;
        Ok(buf)
    }

    pub(crate) fn remove_peer(&mut self, group_key: &str, peer_id: PeerId) {
        let mut remove_group = false;
        if let Some(data) = self.groups.get_mut(group_key) {
            data.peer_report_time.remove(&peer_id);
            data.global_peer_map
                .retain(|pair, _| pair.src != peer_id && pair.dst != peer_id);
            data.digest = Self::calc_digest_internal(data);
            remove_group = data.global_peer_map.is_empty() && data.peer_report_time.is_empty();
        }
        if remove_group {
            self.groups.remove(group_key);
        }
    }

    /// 获取指定房间的全局节点映射。
    /// `request_bytes` 是编码后的 `GetGlobalPeerMapRequest`。
    /// 返回编码后的 `GetGlobalPeerMapResponse`。
    pub(crate) fn get_global_peer_map(
        &mut self,
        group_key: &str,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let req = GetGlobalPeerMapRequest::decode(request_bytes)
            .map_err(|e| {
                JsValue::from_str(&format!("decode GetGlobalPeerMapRequest failed: {}", e))
            })?;

        let data = self.group_mut(group_key);
        let digest = req.digest;

        if digest == data.digest && digest != 0 {
            let resp = GetGlobalPeerMapResponse::default();
            let mut buf = Vec::new();
            prost::Message::encode(&resp, &mut buf)
                .map_err(|e| {
                    JsValue::from_str(&format!("encode GetGlobalPeerMapResponse failed: {}", e))
                })?;
            return Ok(buf);
        }

        let mut global_peer_map: BTreeMap<u32, PeerInfoForGlobalMap> = BTreeMap::new();
        for (pair, entry) in &data.global_peer_map {
            global_peer_map
                .entry(pair.src)
                .or_insert_with(|| PeerInfoForGlobalMap {
                    direct_peers: Default::default(),
                })
                .direct_peers
                .insert(pair.dst, entry.info.clone());
        }

        let resp = GetGlobalPeerMapResponse {
            global_peer_map,
            digest: Some(data.digest),
        };
        let mut buf = Vec::new();
        prost::Message::encode(&resp, &mut buf)
            .map_err(|e| {
                JsValue::from_str(&format!("encode GetGlobalPeerMapResponse failed: {}", e))
            })?;
        Ok(buf)
    }

    /// 删除超过 `ttl_sec` 秒未更新的条目。
    pub(crate) fn clean_outdated(&mut self, ttl_sec: u64) {
        let now_ms = js_sys::Date::now() as u64;
        let ttl_ms = ttl_sec.saturating_mul(1000);
        for data in self.groups.values_mut() {
            data.peer_report_time
                .retain(|_, value| now_ms.saturating_sub(*value) < ttl_ms);
            data.global_peer_map
                .retain(|_, value| now_ms.saturating_sub(value.update_time_ms) < ttl_ms);
            data.digest = Self::calc_digest_internal(data);
        }
        self.groups.retain(|_, data| {
            !data.global_peer_map.is_empty() || !data.peer_report_time.is_empty()
        });
    }
}
