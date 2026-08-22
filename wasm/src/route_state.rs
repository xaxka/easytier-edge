use std::collections::{BTreeSet, HashMap};

use prost::Message;

use crate::proto::peer_rpc::{
    PeerIdVersion, RouteConnBitmap, RouteConnPeerList, RoutePeerInfo, SyncRouteInfoRequest,
    SyncRouteInfoResponse, route_conn_peer_list, sync_route_info_request::ConnInfo,
};

pub type PeerId = u32;
pub type Version = u32;
pub type SessionId = u64;

/// 校验路由信息中上报的 Noise 公钥,必要时完成首次绑定。
///
/// - secure 握手节点:绑定的 32 字节公钥必须与上报值逐字节一致。
/// - legacy 握手节点:握手时无法获得公钥,绑定为空键。上游客户端
///   即使未启用加密也总会生成 X25519 密钥对并在 `RoutePeerInfo` 中
///   上报真实公钥,因此空键在首次路由同步时绑定上报值,后续必须一致,
///   防止同一连接内身份漂移。
fn validate_or_bind_reported_key(
    authenticated: &mut Vec<u8>,
    reported: &[u8],
) -> Result<(), String> {
    if !reported.is_empty() && reported.len() != 32 {
        return Err("RoutePeerInfo public key must be empty or 32 bytes".to_string());
    }
    if authenticated.is_empty() {
        if !reported.is_empty() {
            authenticated.extend_from_slice(reported);
        }
        return Ok(());
    }
    if reported != authenticated.as_slice() {
        return Err(
            "RoutePeerInfo public key does not match the authenticated Noise identity".to_string(),
        );
    }
    Ok(())
}

pub(crate) struct RouteSyncOutcome {
    pub(crate) response: Vec<u8>,
    pub(crate) route_changed: bool,
    pub(crate) session_changed: bool,
}

pub(crate) struct RouteUpdate {
    pub(crate) payload: Vec<u8>,
    pub(crate) peer_info_versions: Vec<(PeerId, Version)>,
    pub(crate) topology_version: Option<u64>,
}

const EASYTIER_VERSION: &str = "2.6.4-8428a89d-edge";
const MAX_LEGACY_BITMAP_PEERS: usize = 8_192;
const SAVED_ROUTE_VERSION_TTL_MS: u64 = 60_000;
/// 单个网络分组允许的链式接入(经网关转发的第三方)节点数上限,
/// 防止已认证节点用伪造路由撑爆内存。
const MAX_RELAYED_PEERS: usize = 4_096;

#[derive(Debug, Clone, Copy, Default)]
struct SavedVersion {
    version: Version,
    touched_at_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct SessionState {
    my_session_id: Option<SessionId>,
    dst_session_id: Option<SessionId>,
    we_are_initiator: bool,
    peer_info_ver_map: HashMap<PeerId, SavedVersion>,
    foreign_net_ver: u32,
    last_touch_ms: u64,
    last_topology_version: u64,
    last_topology_touch_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct RouteGroupData {
    peers: BTreeSet<PeerId>, // 房间内已知的节点标识
    peer_infos: HashMap<PeerId, RoutePeerInfo>,
    // 第三方路由信息的原始 protobuf 字节,转播时原样下发,避免重编码丢失未知字段。
    raw_peer_infos: HashMap<PeerId, Vec<u8>>,
    // 直连节点上报的自身链路:网关 -> 其连接的节点集合(含链式接入的第三方节点)。
    // 对应上游 peer_ospf_route 的 update_conn_info / allow_relay 语义。
    gateway_links: HashMap<PeerId, BTreeSet<PeerId>>,
    authenticated_peer_keys: HashMap<PeerId, Vec<u8>>,
    sessions: HashMap<PeerId, SessionState>,
    peer_conn_versions: HashMap<PeerId, Version>,
    topology_version: u64,
    cached_conn_bitmap: Option<(u64, RouteConnBitmap)>,
    cached_conn_peer_list: Option<(u64, RouteConnPeerList)>,
    my_info: RoutePeerInfo,
    my_info_version: Version,
}

/// EasyTier 路由状态管理器，逻辑移植自 peer_ospf_route.rs。
///
/// 除星型直连外还支持链式接入:节点 C 不直连本中继,而是经直连节点 B
/// (网关)转发路由信息接入网络。网关必须是通过 Noise/legacy 握手的
/// 已认证成员;其代发的第三方条目会绑定公钥防漂移,且不得冒充直连
/// 节点或本中继。网关断开后,失去所有网关链路的第三方节点被清除。
pub(crate) struct RouteState {
    groups: HashMap<String, RouteGroupData>,
    my_peer_id: PeerId,
}

impl RouteState {
    pub(crate) fn new(my_peer_id: PeerId) -> Self {
        RouteState {
            groups: HashMap::new(),
            my_peer_id,
        }
    }

    fn random_u32() -> u32 {
        // 会话 ID / UUID / 拓扑版本使用 CSPRNG:经 getrandom 0.3 的 wasm_js
        // 特性在 Worker 中映射到 crypto.getRandomValues,宿主机测试用系统熵。
        let mut bytes = [0u8; 4];
        if getrandom::fill(&mut bytes).is_ok() {
            return u32::from_le_bytes(bytes);
        }
        // 理论上不可达的兜底路径:Workers 运行时始终暴露 crypto.getRandomValues。
        (js_sys::Math::random() * (u32::MAX as f64)) as u32
    }

    fn random_u64() -> u64 {
        let hi = Self::random_u32() as u64;
        let lo = Self::random_u32() as u64;
        (hi << 32) | lo
    }

    fn random_uuid() -> crate::proto::common::Uuid {
        crate::proto::common::Uuid {
            part1: Self::random_u32(),
            part2: Self::random_u32(),
            part3: Self::random_u32(),
            part4: Self::random_u32(),
        }
    }

    fn ensure_group(&mut self, group_key: &str) -> &mut RouteGroupData {
        let my_peer_id = self.my_peer_id;
        self.groups.entry(group_key.to_string()).or_insert_with(|| {
            let mut my_info = RoutePeerInfo::default();
            my_info.peer_id = my_peer_id;
            my_info.inst_id = Some(Self::random_uuid());
            my_info.cost = 0;
            my_info.version = 1;
            my_info.network_length = 24;
            my_info.easytier_version = EASYTIER_VERSION.to_string();
            my_info.hostname = Some("edge".to_string());
            my_info.peer_route_id = Self::random_u64();
            my_info.feature_flag = Some(crate::proto::common::PeerFeatureFlag {
                is_public_server: true,
                // 本节点是实际后备中继，而非仅用于发现的节点。
                // 客户端仍可建立成本更低的点对点链路并迁移流量。
                avoid_relay_data: false,
                kcp_input: false,
                no_relay_kcp: false,
                support_conn_list_sync: true,
                disable_p2p: true,
                ..Default::default()
            });
            RouteGroupData {
                peers: BTreeSet::new(),
                peer_infos: HashMap::new(),
                raw_peer_infos: HashMap::new(),
                gateway_links: HashMap::new(),
                authenticated_peer_keys: HashMap::new(),
                sessions: HashMap::new(),
                peer_conn_versions: HashMap::new(),
                topology_version: 1,
                cached_conn_bitmap: None,
                cached_conn_peer_list: None,
                my_info,
                my_info_version: 1,
            }
        })
    }

    pub(crate) fn add_peer(
        &mut self,
        group_key: &str,
        peer_id: PeerId,
        public_key: &[u8],
    ) -> Result<(), String> {
        // legacy 握手的节点没有 Noise 静态公钥,以空键表示;
        // secure 模式节点必须提供 32 字节公钥。
        if !public_key.is_empty() && public_key.len() != 32 {
            return Err(
                "authenticated peer public key must be 32 bytes or empty for legacy peers"
                    .to_string(),
            );
        }
        let public_key = public_key.to_vec();
        let my_peer_id = self.my_peer_id;
        let g = self.ensure_group(group_key);
        if g.authenticated_peer_keys
            .get(&peer_id)
            .is_some_and(|current| current.as_slice() != public_key.as_slice())
        {
            return Err("peer id is already bound to another authenticated public key".to_string());
        }
        g.authenticated_peer_keys.insert(peer_id, public_key);
        let is_new = g.peers.insert(peer_id);
        if is_new {
            Self::bump_all_conn_versions(g, my_peer_id);
        }
        Ok(())
    }

    pub(crate) fn remove_peer(&mut self, group_key: &str, peer_id: PeerId) {
        let my_peer_id = self.my_peer_id;
        let g = self.ensure_group(group_key);
        let was_present = g.peers.remove(&peer_id);
        let had_info = g.peer_infos.remove(&peer_id).is_some();
        let had_raw = g.raw_peer_infos.remove(&peer_id).is_some();
        let had_links = g.gateway_links.remove(&peer_id).is_some();
        g.authenticated_peer_keys.remove(&peer_id);
        g.sessions.remove(&peer_id);
        g.peer_conn_versions.remove(&peer_id);
        for session in g.sessions.values_mut() {
            session.peer_info_ver_map.remove(&peer_id);
            session.last_topology_version = 0;
        }
        // 网关断开后,清除不再被任何在线网关链路支撑的第三方节点。
        let still_linked: BTreeSet<PeerId> = g
            .gateway_links
            .iter()
            .filter(|(gateway, _)| g.peers.contains(gateway))
            .flat_map(|(_, links)| links.iter().copied())
            .collect();
        let orphaned: Vec<PeerId> = g
            .peer_infos
            .keys()
            .filter(|pid| !g.peers.contains(pid) && !still_linked.contains(pid))
            .copied()
            .collect();
        let purged = !orphaned.is_empty();
        for pid in &orphaned {
            g.peer_infos.remove(pid);
            g.raw_peer_infos.remove(pid);
            g.authenticated_peer_keys.remove(pid);
            g.peer_conn_versions.remove(pid);
            for session in g.sessions.values_mut() {
                session.peer_info_ver_map.remove(pid);
                session.last_topology_version = 0;
            }
        }
        if was_present || had_info || had_raw || had_links || purged {
            Self::bump_all_conn_versions(g, my_peer_id);
        }
    }

    /// 查询到达目标节点的下一跳。直连节点返回自身;链式接入的第三方
    /// 节点返回与其保持链路的最小直连网关;未知节点返回 None。
    pub(crate) fn get_next_hop(&self, group_key: &str, target_peer_id: PeerId) -> Option<PeerId> {
        let g = self.groups.get(group_key)?;
        if g.peers.contains(&target_peer_id) {
            return Some(target_peer_id);
        }
        g.gateway_links
            .iter()
            .filter(|(gateway, links)| g.peers.contains(gateway) && links.contains(&target_peer_id))
            .map(|(gateway, _)| *gateway)
            .min()
    }

    pub(crate) fn on_route_session_ack(
        &mut self,
        group_key: &str,
        peer_id: PeerId,
        their_session_id: SessionId,
        we_are_initiator: bool,
        now_ms: u64,
    ) {
        let g = self.ensure_group(group_key);
        let s = g.sessions.entry(peer_id).or_default();
        if s.dst_session_id != Some(their_session_id) {
            s.peer_info_ver_map.clear();
            s.foreign_net_ver = 0;
            s.last_topology_version = 0;
        }
        s.dst_session_id = Some(their_session_id);
        s.we_are_initiator = we_are_initiator;
        s.last_touch_ms = now_ms;
    }

    pub(crate) fn commit_route_update(
        &mut self,
        group_key: &str,
        peer_id: PeerId,
        peer_info_versions: &[(PeerId, Version)],
        topology_version: Option<u64>,
        now_ms: u64,
    ) {
        let g = self.ensure_group(group_key);
        let session = g.sessions.entry(peer_id).or_default();
        for (sent_peer_id, version) in peer_info_versions {
            session
                .peer_info_ver_map
                .entry(*sent_peer_id)
                .and_modify(|saved| {
                    saved.version = saved.version.max(*version);
                    saved.touched_at_ms = now_ms;
                })
                .or_insert(SavedVersion {
                    version: *version,
                    touched_at_ms: now_ms,
                });
        }
        if let Some(version) = topology_version {
            session.last_topology_version = session.last_topology_version.max(version);
            session.last_topology_touch_ms = now_ms;
        }
        session.last_touch_ms = now_ms;
    }

    pub(crate) fn set_my_info_field(
        &mut self,
        group_key: &str,
        field: &str,
        value: &str,
    ) -> Result<(), String> {
        let g = self.ensure_group(group_key);
        match field {
            "hostname" => g.my_info.hostname = Some(value.to_string()),
            "network_length" => {
                g.my_info.network_length = value
                    .parse()
                    .map_err(|_| "invalid network_length".to_string())?;
            }
            "ipv4_addr" => {
                let addr: u32 = value
                    .parse()
                    .map_err(|_| "invalid ipv4_addr".to_string())?;
                g.my_info.ipv4_addr = Some(crate::proto::common::Ipv4Addr { addr });
            }
            _ => return Err("unknown field".to_string()),
        }
        g.my_info_version += 1;
        g.my_info.version = g.my_info_version;
        Ok(())
    }

    /// 在 OSPF 路由信息中发布稳定的安全模式公钥，供节点固定中继身份并建立端到端会话。
    pub(crate) fn set_my_noise_public_key(
        &mut self,
        group_key: &str,
        public_key: &[u8],
    ) -> Result<(), String> {
        if public_key.len() != 32 {
            return Err("Noise public key must be 32 bytes".to_string());
        }
        let g = self.ensure_group(group_key);
        g.my_info.noise_static_pubkey = public_key.to_vec();
        g.my_info_version += 1;
        g.my_info.version = g.my_info_version;
        Ok(())
    }

    /// 在 OSPF 路由信息中发布 `avoid_relay_data` 特性标志,
    /// 通知所有节点:本中继只参与控制面,请勿将数据面流量路由经过本节点。
    pub(crate) fn set_my_avoid_relay_data(
        &mut self,
        group_key: &str,
        enabled: bool,
    ) -> Result<(), String> {
        let g = self.ensure_group(group_key);
        let feature_flag = g
            .my_info
            .feature_flag
            .get_or_insert_with(crate::proto::common::PeerFeatureFlag::default);
        if feature_flag.avoid_relay_data == enabled {
            return Ok(());
        }
        feature_flag.avoid_relay_data = enabled;
        g.my_info_version += 1;
        g.my_info.version = g.my_info_version;
        Ok(())
    }

    /// 生成发往目标节点的 SyncRouteInfoRequest 负载。
    pub(crate) fn build_sync_route_info_request(
        &mut self,
        group_key: &str,
        target_peer_id: PeerId,
        server_session_id: SessionId,
        we_are_initiator: bool,
        force_full: bool,
        now_ms: u64,
    ) -> Result<RouteUpdate, String> {
        let my_peer_id = self.my_peer_id;
        let g = self.ensure_group(group_key);

        // 先更新会话，避免与后续可变借用冲突。
        {
            let session = g.sessions.entry(target_peer_id).or_default();
            session.my_session_id = Some(server_session_id);
            session.last_touch_ms = now_ms;
        }

        let force_full_local = {
            let session = g.sessions.get(&target_peer_id);
            force_full || session.map(|s| s.dst_session_id.is_none()).unwrap_or(true)
        };

        let mut all_peers: BTreeSet<PeerId> = g.peers.clone();
        // 链式接入:包含经网关转发的第三方节点,让全网都能学到其路由。
        all_peers.extend(g.peer_infos.keys().copied());
        all_peers.insert(my_peer_id);
        all_peers.insert(target_peer_id);
        let relevant_peers: Vec<PeerId> = all_peers.into_iter().collect();

        let mut typed_items: Vec<RoutePeerInfo> = Vec::new();
        let mut raw_items: Vec<Vec<u8>> = Vec::new();
        let mut peer_info_versions = Vec::new();
        {
            let session = g.sessions.entry(target_peer_id).or_default();
            for pid in &relevant_peers {
                if *pid == target_peer_id {
                    continue;
                }
                let info = if *pid == my_peer_id {
                    Some(&g.my_info)
                } else {
                    g.peer_infos.get(pid)
                };
                let Some(info) = info else {
                    continue;
                };
                let version = info.version.max(1);
                let prev = if force_full_local {
                    0
                } else {
                    session
                        .peer_info_ver_map
                        .get(pid)
                        .filter(|saved| {
                            now_ms.saturating_sub(saved.touched_at_ms) < SAVED_ROUTE_VERSION_TTL_MS
                        })
                        .map_or(0, |saved| saved.version)
                };
                if force_full_local || version > prev {
                    peer_info_versions.push((*pid, version));
                    if *pid == my_peer_id {
                        typed_items.push(g.my_info.clone());
                    } else if let Some(raw) = g.raw_peer_infos.get(pid) {
                        // 第三方路由用原始字节转播,未知字段原样保留。
                        raw_items.push(raw.clone());
                    } else {
                        typed_items.push(info.clone());
                    }
                }
            }
        }

        let supports_conn_list = g
            .peer_infos
            .get(&target_peer_id)
            .and_then(|info| info.feature_flag.as_ref())
            .is_some_and(|flag| flag.support_conn_list_sync);
        let conn_info = Self::build_conn_info(
            g,
            &relevant_peers,
            target_peer_id,
            supports_conn_list,
            my_peer_id,
            now_ms,
        )?;
        let topology_version = conn_info.as_ref().map(|_| g.topology_version);

        // 每个房间都是独立的 EasyTier 网络。ForeignNetworkRouteInfo 仅用于公共共享节点互联，
        // 在此发布会破坏房间的强隔离边界。
        let foreign_network_infos = None;

        let req = SyncRouteInfoRequest {
            my_peer_id,
            my_session_id: server_session_id,
            is_initiator: we_are_initiator,
            peer_infos: None,
            conn_info,
            foreign_network_infos,
        };
        let mut payload = req.encode_to_vec();
        if !typed_items.is_empty() || !raw_items.is_empty() {
            // peer_infos(字段 4)手工编码,使原始字节条目与本中继自身条目混排;
            // protobuf 字段顺序无关,上游 prost 解码不受影响。
            let mut field = Vec::new();
            for info in &typed_items {
                push_len_delimited(&mut field, 1, &info.encode_to_vec());
            }
            for raw in &raw_items {
                push_len_delimited(&mut field, 1, raw);
            }
            push_len_delimited(&mut payload, 4, &field);
        }

        Ok(RouteUpdate {
            payload,
            peer_info_versions,
            topology_version,
        })
    }

    /// 处理收到的 SyncRouteInfoRequest 并生成 SyncRouteInfoResponse。
    pub(crate) fn handle_sync_route_info_request(
        &mut self,
        group_key: &str,
        from_peer_id: PeerId,
        request_bytes: &[u8],
        now_ms: u64,
    ) -> Result<RouteSyncOutcome, String> {
        let my_peer_id = self.my_peer_id;
        let req = SyncRouteInfoRequest::decode(request_bytes)
            .map_err(|e| format!("decode SyncRouteInfoRequest failed: {}", e))?;
        if req.my_peer_id != from_peer_id {
            return Err(
                "SyncRouteInfoRequest peer id does not match the authenticated connection"
                    .to_string(),
            );
        }

        // 与解码结果同序的原始条目字节,用于第三方路由的保真转播。
        let raw_items = extract_route_peer_info_items(request_bytes);

        let g = self.ensure_group(group_key);

        let session_changed = {
            let session = g.sessions.entry(from_peer_id).or_default();
            session.last_touch_ms = now_ms;
            let sid = req.my_session_id;
            let changed = session.dst_session_id != Some(sid);
            if changed {
                session.peer_info_ver_map.clear();
                session.foreign_net_ver = 0;
                session.last_topology_version = 0;
            }
            session.dst_session_id = Some(sid);
            session.we_are_initiator = !req.is_initiator;
            changed
        };

        let mut route_changed = false;
        let mut topology_changed = false;
        let mut need_bump = false;
        if let Some(infos) = &req.peer_infos {
            for (index, info) in infos.items.iter().enumerate() {
                let is_self = info.peer_id == from_peer_id;
                if !is_self {
                    // 链式接入的第三方条目:仅接受已认证网关代发、
                    // 且不冒充直连节点或本中继的条目。
                    if info.peer_id == 0
                        || info.peer_id == my_peer_id
                        || g.peers.contains(&info.peer_id)
                    {
                        continue;
                    }
                    if !g.peer_infos.contains_key(&info.peer_id)
                        && Self::relayed_peer_count(g) >= MAX_RELAYED_PEERS
                    {
                        return Err("relayed route capacity exceeded".to_string());
                    }
                }
                if is_self {
                    let authenticated_key = g
                        .authenticated_peer_keys
                        .get_mut(&from_peer_id)
                        .ok_or_else(|| {
                            "route peer has no authenticated public key".to_string()
                        })?;
                    validate_or_bind_reported_key(
                        authenticated_key,
                        &info.noise_static_pubkey,
                    )?;
                } else {
                    Self::bind_third_party_key(g, info)?;
                }
                // 网关链路记录必须先于版本判断:同一第三方节点经多个网关
                // 接入时,后续网关的重复版本条目也要建立自己的链路。
                if !is_self
                    && g.gateway_links
                        .entry(from_peer_id)
                        .or_default()
                        .insert(info.peer_id)
                {
                    topology_changed = true;
                }
                let is_new = !g.peer_infos.contains_key(&info.peer_id);
                let instance_changed = g
                    .peer_infos
                    .get(&info.peer_id)
                    .is_some_and(|current| current.inst_id != info.inst_id);
                let should_update = instance_changed
                    || g
                        .peer_infos
                        .get(&info.peer_id)
                        .is_none_or(|current| info.version > current.version);
                if !should_update {
                    continue;
                }
                route_changed = true;
                if instance_changed {
                    for session in g.sessions.values_mut() {
                        session.peer_info_ver_map.remove(&info.peer_id);
                    }
                }
                let mut info = info.clone();
                info.last_update = Some(crate::proto::Timestamp {
                    seconds: (now_ms / 1000) as i64,
                    nanos: 0,
                });
                let entry_peer_id = info.peer_id;
                g.peer_infos.insert(entry_peer_id, info);
                if let Some(raw) = raw_items.get(index) {
                    g.raw_peer_infos.insert(entry_peer_id, raw.clone());
                }
                if is_new {
                    need_bump = true;
                }
            }
        }

        // 合并上报方 conn_info 中其自身的链路视图(仅取以上报方为一端的边),
        // 使 B--C 等链式链路进入全网拓扑。
        if let Some(conn) = &req.conn_info {
            if let Some(reported) = Self::links_reported_by(conn, from_peer_id) {
                let entry = g.gateway_links.entry(from_peer_id).or_default();
                let before = entry.clone();
                for pid in reported {
                    if pid == my_peer_id || pid == from_peer_id {
                        continue;
                    }
                    if g.peers.contains(&pid) || g.peer_infos.contains_key(&pid) {
                        entry.insert(pid);
                    }
                }
                if *entry != before {
                    topology_changed = true;
                }
                if entry.is_empty() {
                    g.gateway_links.remove(&from_peer_id);
                }
            }
        }

        if need_bump || topology_changed {
            Self::bump_all_conn_versions(g, my_peer_id);
        }
        if topology_changed {
            route_changed = true;
        }

        let server_session_id = {
            let session = g.sessions.get(&from_peer_id);
            session.and_then(|s| s.my_session_id).unwrap_or(1)
        };
        let resp = SyncRouteInfoResponse {
            is_initiator: !req.is_initiator,
            session_id: server_session_id,
            error: None,
        };

        Ok(RouteSyncOutcome {
            response: prost::Message::encode_to_vec(&resp),
            route_changed,
            session_changed,
        })
    }

    // 辅助方法

    fn relayed_peer_count(g: &RouteGroupData) -> usize {
        g.peer_infos
            .keys()
            .filter(|pid| !g.peers.contains(pid))
            .count()
    }

    /// 绑定第三方节点的公钥。实例变更(节点重启换密钥)允许重新绑定,
    /// 同一实例内的密钥漂移视为身份攻击而被拒绝。
    fn bind_third_party_key(g: &mut RouteGroupData, info: &RoutePeerInfo) -> Result<(), String> {
        let binding = g
            .authenticated_peer_keys
            .entry(info.peer_id)
            .or_default();
        if validate_or_bind_reported_key(binding, &info.noise_static_pubkey).is_err() {
            let instance_changed = g
                .peer_infos
                .get(&info.peer_id)
                .is_some_and(|current| current.inst_id != info.inst_id);
            if !instance_changed {
                return Err(
                    "relayed RoutePeerInfo public key does not match the bound Noise identity"
                        .to_string(),
                );
            }
            g.authenticated_peer_keys.insert(info.peer_id, Vec::new());
            let binding = g
                .authenticated_peer_keys
                .get_mut(&info.peer_id)
                .expect("rebinding entry was just inserted");
            validate_or_bind_reported_key(binding, &info.noise_static_pubkey)?;
        }
        Ok(())
    }

    /// 提取 conn_info 中以上报方为一端的链路集合。
    fn links_reported_by(conn: &ConnInfo, from_peer_id: PeerId) -> Option<BTreeSet<PeerId>> {
        match conn {
            ConnInfo::ConnPeerList(list) => list
                .peer_conn_infos
                .iter()
                .find(|row| {
                    row.peer_id
                        .as_ref()
                        .is_some_and(|pv| pv.peer_id == from_peer_id)
                })
                .map(|row| row.connected_peer_ids.iter().copied().collect()),
            ConnInfo::ConnBitmap(bitmap) => {
                let idx = bitmap
                    .peer_ids
                    .iter()
                    .position(|pv| pv.peer_id == from_peer_id)?;
                let n = bitmap.peer_ids.len();
                let mut set = BTreeSet::new();
                for (j, pv) in bitmap.peer_ids.iter().enumerate() {
                    if j == idx {
                        continue;
                    }
                    let bit = idx * n + j;
                    let byte = *bitmap.bitmap.get(bit / 8)?;
                    if byte & (1 << (bit % 8)) != 0 {
                        set.insert(pv.peer_id);
                    }
                }
                Some(set)
            }
        }
    }

    fn bump_all_conn_versions(g: &mut RouteGroupData, my_peer_id: PeerId) {
        let all: BTreeSet<PeerId> = g.peers.iter().chain(g.peer_infos.keys()).copied().collect();
        for pid in all {
            let v = g.peer_conn_versions.get(&pid).copied().unwrap_or(1);
            g.peer_conn_versions.insert(pid, v + 1);
        }
        g.peer_conn_versions
            .entry(my_peer_id)
            .and_modify(|v| *v += 1)
            .or_insert(2);
        g.topology_version = g.topology_version.wrapping_add(1).max(1);
        g.cached_conn_bitmap = None;
        g.cached_conn_peer_list = None;
    }

    /// 计算节点的邻接集合:
    /// - 本中继: 所有直连节点(不包含链式接入的第三方)。
    /// - 直连节点: 本中继 + 其上报链路中的已知节点。
    /// - 第三方节点: 与其保持链路的在线网关集合。
    fn connected_peers(
        g: &RouteGroupData,
        relevant_peers: &[PeerId],
        pid: PeerId,
        my_peer_id: PeerId,
    ) -> BTreeSet<PeerId> {
        let mut set = BTreeSet::new();
        if pid == my_peer_id {
            for p in relevant_peers {
                if *p != my_peer_id && g.peers.contains(p) {
                    set.insert(*p);
                }
            }
        } else if g.peers.contains(&pid) {
            set.insert(my_peer_id);
            if let Some(links) = g.gateway_links.get(&pid) {
                for link in links {
                    if relevant_peers.contains(link) {
                        set.insert(*link);
                    }
                }
            }
        } else {
            for (gateway, links) in &g.gateway_links {
                if links.contains(&pid)
                    && *gateway != pid
                    && g.peers.contains(gateway)
                    && relevant_peers.contains(gateway)
                {
                    set.insert(*gateway);
                }
            }
        }
        set
    }

    fn build_conn_info(
        g: &mut RouteGroupData,
        relevant_peers: &[PeerId],
        target_peer_id: PeerId,
        supports_conn_list: bool,
        my_peer_id: PeerId,
        now_ms: u64,
    ) -> Result<Option<ConnInfo>, String> {
        if relevant_peers.is_empty() {
            return Ok(None);
        }

        let topology_version = g.topology_version;
        if g.sessions.get(&target_peer_id).is_some_and(|session| {
            session.last_topology_version == topology_version
                && now_ms.saturating_sub(session.last_topology_touch_ms)
                    < SAVED_ROUTE_VERSION_TTL_MS
        }) {
            return Ok(None);
        }

        if supports_conn_list {
            if let Some((cached_version, cached)) = &g.cached_conn_peer_list {
                if *cached_version == topology_version {
                    return Ok(Some(ConnInfo::ConnPeerList(cached.clone())));
                }
            }
        } else if let Some((cached_version, cached)) = &g.cached_conn_bitmap {
            if *cached_version == topology_version {
                return Ok(Some(ConnInfo::ConnBitmap(cached.clone())));
            }
        }

        let n = relevant_peers.len();
        let peer_id_versions: Vec<PeerIdVersion> = relevant_peers
            .iter()
            .map(|pid| PeerIdVersion {
                peer_id: *pid,
                version: g.peer_conn_versions.get(pid).copied().unwrap_or(1),
            })
            .collect();

        if supports_conn_list {
            let peer_conn_infos = peer_id_versions
                .iter()
                .map(|pv| {
                    let connected =
                        Self::connected_peers(g, relevant_peers, pv.peer_id, my_peer_id);
                    route_conn_peer_list::PeerConnInfo {
                        peer_id: Some(pv.clone()),
                        connected_peer_ids: connected.into_iter().collect(),
                    }
                })
                .collect();
            let result = RouteConnPeerList { peer_conn_infos };
            g.cached_conn_peer_list = Some((topology_version, result.clone()));
            return Ok(Some(ConnInfo::ConnPeerList(result)));
        }

        if n > MAX_LEGACY_BITMAP_PEERS {
            return Err(
                "peer does not support sparse route synchronization and the legacy bitmap limit was exceeded"
                    .to_string(),
            );
        }
        let bitmap_size = (n * n + 7) / 8;
        let mut bitmap = vec![0u8; bitmap_size];

        let idx_by_peer: HashMap<PeerId, usize> = relevant_peers
            .iter()
            .enumerate()
            .map(|(i, p)| (*p, i))
            .collect();

        let set_bit = |bitmap: &mut [u8], row: usize, col: usize| {
            let idx = row * n + col;
            bitmap[idx / 8] |= 1 << (idx % 8);
        };

        for (i, pid) in relevant_peers.iter().enumerate() {
            set_bit(&mut bitmap, i, i);
            for link in Self::connected_peers(g, relevant_peers, *pid, my_peer_id) {
                if let Some(&j) = idx_by_peer.get(&link) {
                    set_bit(&mut bitmap, i, j);
                    set_bit(&mut bitmap, j, i);
                }
            }
        }

        let result = RouteConnBitmap {
            peer_ids: peer_id_versions,
            bitmap,
        };
        g.cached_conn_bitmap = Some((topology_version, result.clone()));
        Ok(Some(ConnInfo::ConnBitmap(result)))
    }
}

fn read_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*pos)?;
        *pos += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn push_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn push_len_delimited(buf: &mut Vec<u8>, field_no: u32, bytes: &[u8]) {
    push_varint(buf, ((field_no as u64) << 3) | 2);
    push_varint(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

/// 遍历 protobuf wire format 的顶层字段,对每个长度限定字段调用 visit。
/// 解析失败时静默停止:调用方应先经 prost 成功解码,这里仅做保真提取。
fn for_each_len_delimited<'a>(buf: &'a [u8], mut visit: impl FnMut(u32, &'a [u8])) {
    let mut pos = 0usize;
    while pos < buf.len() {
        let Some(tag) = read_varint(buf, &mut pos) else {
            break;
        };
        let field_no = (tag >> 3) as u32;
        match (tag & 7) as u32 {
            0 => {
                if read_varint(buf, &mut pos).is_none() {
                    break;
                }
            }
            1 => pos = pos.saturating_add(8),
            5 => pos = pos.saturating_add(4),
            2 => {
                let Some(len) = read_varint(buf, &mut pos) else {
                    break;
                };
                let len = len as usize;
                let Some(payload) = buf.get(pos..pos.saturating_add(len)) else {
                    break;
                };
                pos += len;
                visit(field_no, payload);
            }
            _ => break,
        }
    }
}

/// 提取 SyncRouteInfoRequest 中 peer_infos.items 的原始字节,
/// 顺序与 prost 解码出的 items 一致。
fn extract_route_peer_info_items(request_bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut items: Vec<Vec<u8>> = Vec::new();
    for_each_len_delimited(request_bytes, |field, payload| {
        if field == 4 {
            for_each_len_delimited(payload, |inner_field, item| {
                if inner_field == 1 {
                    items.push(item.to_vec());
                }
            });
        }
    });
    items
}

#[cfg(test)]
mod tests {
    use super::{
        ConnInfo, PeerId, PeerIdVersion, RouteConnPeerList, RoutePeerInfo, RouteState,
        SyncRouteInfoRequest, extract_route_peer_info_items, push_len_delimited, push_varint,
        read_varint, route_conn_peer_list, validate_or_bind_reported_key,
    };
    use crate::proto::peer_rpc::RoutePeerInfos;
    use prost::Message;

    const KEY_A: [u8; 32] = [0x11; 32];
    const KEY_B: [u8; 32] = [0x22; 32];
    const SERVER_ID: PeerId = 1;
    const GATEWAY_B: PeerId = 2;
    const CHAINED_C: PeerId = 3;
    const PEER_A: PeerId = 4;
    const GATEWAY_D: PeerId = 5;

    fn key(i: u8) -> Vec<u8> {
        vec![i; 32]
    }

    fn uuid(i: u32) -> crate::proto::common::Uuid {
        crate::proto::common::Uuid {
            part1: i,
            part2: i,
            part3: i,
            part4: i,
        }
    }

    fn peer_info(pid: PeerId, version: u32, key: &[u8], inst: u32) -> RoutePeerInfo {
        RoutePeerInfo {
            peer_id: pid,
            inst_id: Some(uuid(inst)),
            version,
            cost: 1,
            hostname: Some(format!("peer-{pid}")),
            noise_static_pubkey: key.to_vec(),
            ..Default::default()
        }
    }

    fn conn_list_peer_info(pid: PeerId, version: u32, key: &[u8], inst: u32) -> RoutePeerInfo {
        let mut info = peer_info(pid, version, key, inst);
        info.feature_flag = Some(crate::proto::common::PeerFeatureFlag {
            support_conn_list_sync: true,
            ..Default::default()
        });
        info
    }

    fn sync_req(from: PeerId, items: Vec<RoutePeerInfo>, conn: Option<ConnInfo>) -> Vec<u8> {
        SyncRouteInfoRequest {
            my_peer_id: from,
            my_session_id: 7,
            is_initiator: false,
            peer_infos: if items.is_empty() {
                None
            } else {
                Some(RoutePeerInfos { items })
            },
            conn_info: conn,
            foreign_network_infos: None,
        }
        .encode_to_vec()
    }

    fn conn_row(pid: PeerId, connected: &[PeerId]) -> route_conn_peer_list::PeerConnInfo {
        route_conn_peer_list::PeerConnInfo {
            peer_id: Some(PeerIdVersion {
                peer_id: pid,
                version: 1,
            }),
            connected_peer_ids: connected.to_vec(),
        }
    }

    #[test]
    fn secure_peer_requires_exact_key_match() {
        let mut bound = KEY_A.to_vec();
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_A).is_ok());
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_B).is_err());
        // secure 节点上报空键视为不匹配。
        assert!(validate_or_bind_reported_key(&mut bound, &[]).is_err());
        assert_eq!(bound, KEY_A.to_vec());
    }

    #[test]
    fn legacy_peer_binds_reported_key_on_first_sync() {
        // legacy 握手绑定为空键;上游客户端即使未启用加密也会在
        // RoutePeerInfo 中上报真实 X25519 公钥,首次同步必须放行并绑定。
        let mut bound = Vec::new();
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_A).is_ok());
        assert_eq!(bound, KEY_A.to_vec());
        // 绑定后同一连接内换公钥被拒绝。
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_B).is_err());
        // 重复上报同一公钥保持通过。
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_A).is_ok());
    }

    #[test]
    fn legacy_peer_may_stay_keyless() {
        // 极老客户端可能不上报公钥,保持空绑定时空对空放行。
        let mut bound = Vec::new();
        assert!(validate_or_bind_reported_key(&mut bound, &[]).is_ok());
        assert!(bound.is_empty());
    }

    #[test]
    fn rejects_malformed_key_lengths() {
        let mut empty = Vec::new();
        assert!(validate_or_bind_reported_key(&mut empty, &[1u8; 16]).is_err());
        let mut bound = KEY_A.to_vec();
        assert!(validate_or_bind_reported_key(&mut bound, &[1u8; 33]).is_err());
    }

    #[test]
    fn gateway_relays_third_party_route() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &key(0x22)).unwrap();
        let req = sync_req(GATEWAY_B, vec![peer_info(CHAINED_C, 1, &key(0x33), 1)], None);
        let outcome = s
            .handle_sync_route_info_request("net", GATEWAY_B, &req, 1_000)
            .unwrap();
        assert!(outcome.route_changed);
        let g = s.groups.get("net").unwrap();
        assert!(g.peer_infos.contains_key(&CHAINED_C));
        assert!(g.raw_peer_infos.contains_key(&CHAINED_C));
        assert!(g
            .authenticated_peer_keys
            .get(&CHAINED_C)
            .is_some_and(|k| k == &key(0x33)));
        assert_eq!(s.get_next_hop("net", CHAINED_C), Some(GATEWAY_B));
    }

    #[test]
    fn relayed_info_for_direct_peer_is_ignored() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[]).unwrap();
        s.add_peer("net", PEER_A, &[]).unwrap();
        let req = sync_req(
            GATEWAY_B,
            vec![peer_info(PEER_A, 99, &key(0x44), 1)],
            None,
        );
        s.handle_sync_route_info_request("net", GATEWAY_B, &req, 1_000)
            .unwrap();
        // 直连节点的一手信息优先,代发条目不得创建路由。
        let g = s.groups.get("net").unwrap();
        assert!(!g.peer_infos.contains_key(&PEER_A));
        assert_eq!(s.get_next_hop("net", PEER_A), Some(PEER_A));
    }

    #[test]
    fn relayed_info_for_server_identity_is_ignored() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[]).unwrap();
        let req = sync_req(
            GATEWAY_B,
            vec![peer_info(SERVER_ID, 1, &key(0x11), 1)],
            None,
        );
        s.handle_sync_route_info_request("net", GATEWAY_B, &req, 1_000)
            .unwrap();
        let g = s.groups.get("net").unwrap();
        assert!(!g.gateway_links.contains_key(&GATEWAY_B));
    }

    #[test]
    fn third_party_key_drift_is_rejected() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[]).unwrap();
        let first = sync_req(
            GATEWAY_B,
            vec![peer_info(CHAINED_C, 1, &key(0x33), 1)],
            None,
        );
        s.handle_sync_route_info_request("net", GATEWAY_B, &first, 1_000)
            .unwrap();
        let drift = sync_req(
            GATEWAY_B,
            vec![peer_info(CHAINED_C, 2, &key(0x99), 1)],
            None,
        );
        assert!(s
            .handle_sync_route_info_request("net", GATEWAY_B, &drift, 2_000)
            .is_err());
    }

    #[test]
    fn instance_change_rebinds_third_party_key() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[]).unwrap();
        let first = sync_req(
            GATEWAY_B,
            vec![peer_info(CHAINED_C, 1, &key(0x33), 1)],
            None,
        );
        s.handle_sync_route_info_request("net", GATEWAY_B, &first, 1_000)
            .unwrap();
        // 同一 peer_id 换实例(重启换密钥)允许重新绑定。
        let rotated = sync_req(
            GATEWAY_B,
            vec![peer_info(CHAINED_C, 5, &key(0x77), 2)],
            None,
        );
        s.handle_sync_route_info_request("net", GATEWAY_B, &rotated, 2_000)
            .unwrap();
        let g = s.groups.get("net").unwrap();
        assert!(g
            .authenticated_peer_keys
            .get(&CHAINED_C)
            .is_some_and(|k| k == &key(0x77)));
    }

    #[test]
    fn gateway_disconnect_purges_orphaned_third_party() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[]).unwrap();
        s.add_peer("net", GATEWAY_D, &[]).unwrap();
        let via_b = sync_req(
            GATEWAY_B,
            vec![peer_info(CHAINED_C, 1, &key(0x33), 1)],
            None,
        );
        s.handle_sync_route_info_request("net", GATEWAY_B, &via_b, 1_000)
            .unwrap();
        // 同一第三方节点经第二个网关接入:版本不变也要建立链路。
        let via_d = sync_req(
            GATEWAY_D,
            vec![peer_info(CHAINED_C, 1, &key(0x33), 1)],
            None,
        );
        s.handle_sync_route_info_request("net", GATEWAY_D, &via_d, 1_100)
            .unwrap();
        s.remove_peer("net", GATEWAY_B);
        assert_eq!(s.get_next_hop("net", CHAINED_C), Some(GATEWAY_D));
        let g = s.groups.get("net").unwrap();
        assert!(g.peer_infos.contains_key(&CHAINED_C));
        s.remove_peer("net", GATEWAY_D);
        // 所有网关断开后第三方节点被整体清除。
        assert_eq!(s.get_next_hop("net", CHAINED_C), None);
        let g = s.groups.get("net").unwrap();
        assert!(!g.peer_infos.contains_key(&CHAINED_C));
        assert!(!g.raw_peer_infos.contains_key(&CHAINED_C));
        assert!(!g.authenticated_peer_keys.contains_key(&CHAINED_C));
    }

    #[test]
    fn get_next_hop_unknown_peer_is_none() {
        let s = RouteState::new(SERVER_ID);
        assert_eq!(s.get_next_hop("net", 4242), None);
        assert_eq!(s.get_next_hop("missing", 1), None);
    }

    #[test]
    fn outgoing_sync_preserves_raw_third_party_bytes() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[]).unwrap();
        // 构造带未知字段(field 99)的 C 条目原始字节,模拟更新的客户端版本。
        let mut raw_c = peer_info(CHAINED_C, 1, &key(0x33), 1).encode_to_vec();
        push_varint(&mut raw_c, (99 << 3) as u64);
        push_varint(&mut raw_c, 0x2a);
        // 手工编码请求:field 1 = my_peer_id, field 2 = session, field 4 = items。
        let mut items = Vec::new();
        push_len_delimited(&mut items, 1, &raw_c);
        let mut body = Vec::new();
        fn put_varint_field(buf: &mut Vec<u8>, field: u32, value: u64) {
            push_varint(buf, (field as u64) << 3);
            push_varint(buf, value);
        }
        put_varint_field(&mut body, 1, GATEWAY_B as u64);
        put_varint_field(&mut body, 2, 7);
        push_len_delimited(&mut body, 4, &items);

        s.handle_sync_route_info_request("net", GATEWAY_B, &body, 1_000)
            .unwrap();
        s.add_peer("net", PEER_A, &[]).unwrap();
        let update = s
            .build_sync_route_info_request("net", PEER_A, 9, true, false, 2_000)
            .unwrap();
        // prost 能整体解码,且字段顺序无关。
        let decoded = SyncRouteInfoRequest::decode(update.payload.as_slice()).unwrap();
        assert_eq!(decoded.my_peer_id, SERVER_ID);
        assert_eq!(decoded.peer_infos.as_ref().unwrap().items.len(), 2);
        // 原始字节(含未知字段)被原样转播。
        let outgoing = extract_route_peer_info_items(&update.payload);
        assert!(outgoing.iter().any(|bytes| bytes == &raw_c));
    }

    #[test]
    fn conn_info_reports_gateway_links() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[]).unwrap();
        s.add_peer("net", PEER_A, &[]).unwrap();
        let conn = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![
                conn_row(SERVER_ID, &[GATEWAY_B]),
                conn_row(GATEWAY_B, &[SERVER_ID, CHAINED_C]),
                conn_row(CHAINED_C, &[GATEWAY_B]),
            ],
        });
        let req = sync_req(
            GATEWAY_B,
            vec![peer_info(CHAINED_C, 1, &key(0x33), 1)],
            Some(conn),
        );
        s.handle_sync_route_info_request("net", GATEWAY_B, &req, 1_000)
            .unwrap();
        // A 上报自身信息以声明 support_conn_list_sync。
        let req_a = sync_req(PEER_A, vec![conn_list_peer_info(PEER_A, 1, &key(0x44), 9)], None);
        s.handle_sync_route_info_request("net", PEER_A, &req_a, 1_100)
            .unwrap();
        let update = s
            .build_sync_route_info_request("net", PEER_A, 11, true, false, 2_000)
            .unwrap();
        let decoded = SyncRouteInfoRequest::decode(update.payload.as_slice()).unwrap();
        let ConnInfo::ConnPeerList(list) = decoded.conn_info.unwrap() else {
            panic!("expected conn peer list");
        };
        let row = |pid: PeerId| {
            list.peer_conn_infos
                .iter()
                .find(|row| row.peer_id.as_ref().is_some_and(|pv| pv.peer_id == pid))
                .unwrap()
                .connected_peer_ids
                .clone()
        };
        // B--C 链式链路进入拓扑;本中继不直连 C。
        assert!(row(GATEWAY_B).contains(&CHAINED_C));
        assert!(row(CHAINED_C).contains(&GATEWAY_B));
        assert!(row(SERVER_ID).contains(&GATEWAY_B));
        assert!(row(SERVER_ID).contains(&PEER_A));
        assert!(!row(SERVER_ID).contains(&CHAINED_C));
    }

    #[test]
    fn bitmap_conn_info_includes_gateway_edges() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[]).unwrap();
        s.add_peer("net", PEER_A, &[]).unwrap();
        let req = sync_req(
            GATEWAY_B,
            vec![peer_info(CHAINED_C, 1, &key(0x33), 1)],
            None,
        );
        s.handle_sync_route_info_request("net", GATEWAY_B, &req, 1_000)
            .unwrap();
        // A 从未上报信息,走 legacy bitmap 路径。
        let update = s
            .build_sync_route_info_request("net", PEER_A, 11, true, false, 2_000)
            .unwrap();
        let decoded = SyncRouteInfoRequest::decode(update.payload.as_slice()).unwrap();
        let ConnInfo::ConnBitmap(bitmap) = decoded.conn_info.unwrap() else {
            panic!("expected conn bitmap");
        };
        let n = bitmap.peer_ids.len();
        let idx = |pid: PeerId| {
            bitmap
                .peer_ids
                .iter()
                .position(|pv| pv.peer_id == pid)
                .unwrap()
        };
        let linked = |a: PeerId, b: PeerId| {
            let bit = idx(a) * n + idx(b);
            bitmap.bitmap[bit / 8] & (1 << (bit % 8)) != 0
        };
        // 星型边 + 网关边 + 自环;本中继不直连 C。
        assert!(linked(SERVER_ID, GATEWAY_B));
        assert!(linked(GATEWAY_B, SERVER_ID));
        assert!(linked(SERVER_ID, PEER_A));
        assert!(linked(GATEWAY_B, CHAINED_C));
        assert!(linked(CHAINED_C, GATEWAY_B));
        assert!(!linked(SERVER_ID, CHAINED_C));
        assert!(!linked(PEER_A, CHAINED_C));
        for pv in &bitmap.peer_ids {
            assert!(linked(pv.peer_id, pv.peer_id));
        }
    }

    #[test]
    fn wire_helpers_round_trip() {
        for value in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            push_varint(&mut buf, value);
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos), Some(value));
            assert_eq!(pos, buf.len());
        }
        // 截断的 varint 解析失败。
        let mut buf = Vec::new();
        push_varint(&mut buf, u64::MAX);
        assert!(read_varint(&buf[..buf.len() - 1], &mut 0).is_none());
    }
}
