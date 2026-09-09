use std::collections::{BTreeSet, HashMap};

use prost::Message;

use crate::proto::peer_rpc::{
    PeerIdVersion, RouteConnBitmap, RouteConnPeerList, RoutePeerInfo, SyncRouteInfoRequest,
    SyncRouteInfoResponse, route_conn_peer_list, sync_route_info_request::ConnInfo,
};

pub type PeerId = u32;
pub type Version = u32;
pub type SessionId = u64;

/// 在路由信息中记录上报的 Noise 公钥(信息性首见绑定,非鉴权)。
///
/// 上游 EasyTier 的路由同步(`update_peer_infos`)只比较版本号,不做
/// 任何密钥绑定校验——密钥身份完全由传输层(Noise 会话/legacy 握手的
/// secret 摘要)强制,路由层不重复校验。且上游非 secure-mode 客户端在
/// `RoutePeerInfo` 中上报的是**空**公钥(`unwrap_or_default()`),
/// “上游客户端总是上报真实公钥”是错误前提。
///
/// 因此本函数仅在绑定尚为空且上报值为合法 32 字节公钥时完成首见绑定
/// (供诊断与转播参考),任何长度异常或不匹配都**容忍并放行**,绝不
/// 因此拒绝路由更新——错误的路由条目最多影响转播内容,而拒绝会让
/// 客户端进入重连死循环。
fn validate_or_bind_reported_key(
    authenticated: &mut Vec<u8>,
    reported: &[u8],
) -> Result<(), String> {
    if reported.len() != 32 {
        // 空公钥(非 secure-mode 客户端)或异常长度:不做任何绑定,也不拒绝。
        return Ok(());
    }
    if authenticated.is_empty() {
        authenticated.extend_from_slice(reported);
    }
    // 已有绑定时报文与绑定不一致:保留首个绑定,容忍放行(对齐上游)。
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

/// 过期清理结果:route_changed_networks 列出路由表发生变化的网络(应触发重发),
/// dead_direct_peers 是会话静默超时的半开直连节点("网络\u{1f}peer_id"),
/// 宿主应关闭其 WebSocket 连接。
pub(crate) struct SweepOutcome {
    pub(crate) route_changed_networks: Vec<String>,
    pub(crate) dead_direct_peers: Vec<String>,
}

const EASYTIER_VERSION: &str = "2.6.4-8428a89d-edge";
const MAX_LEGACY_BITMAP_PEERS: usize = 8_192;
const SAVED_ROUTE_VERSION_TTL_MS: u64 = 60_000;
/// 上游 REMOVE_UNREACHABLE_PEER_INFO_AFTER(90s):直连会话停止同步
/// 且信息超过此时限的条目被回收,覆盖对端异常掉线而 close 事件丢失、
/// remove_peer 未被触发的场景。
const REMOVE_UNREACHABLE_PEER_INFO_AFTER_MS: u64 = 90_000;
/// 上游 REMOVE_DEAD_PEER_INFO_AFTER(3660s):超过一个
/// UPDATE_PEER_INFO_PERIOD(3600s)未发生版本续期的条目无条件回收,
/// 防止僵尸条目长期滞留并污染路由。
const REMOVE_DEAD_PEER_INFO_AFTER_MS: u64 = 3_660_000;

/// 单个节点的连接行:该节点直连的邻居集合与它自己维护的版本号。
/// 语义对齐上游 RouteConnInfo:版本仅由行所有者在自身连接集合变化时
/// +1,中继方原样转发,接收方以 version > current 门槛接受。
/// 中继绝不能代为递增客户端行版本:虚高的版本会把中继掌握的过期视图
/// 强加给全网,把已建立的 p2p 边从快照中挤掉,引发流量在中继与 p2p
/// 之间来回震荡。
#[derive(Debug, Clone, Default)]
struct ConnRow {
    version: Version,
    connected: BTreeSet<PeerId>,
}

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
    authenticated_peer_keys: HashMap<PeerId, Vec<u8>>,
    sessions: HashMap<PeerId, SessionState>,
    conn_rows: HashMap<PeerId, ConnRow>,
    topology_version: u64,
    cached_conn_bitmap: Option<(u64, RouteConnBitmap)>,
    cached_conn_peer_list: Option<(u64, RouteConnPeerList)>,
    my_info: RoutePeerInfo,
    my_info_version: Version,
}

/// EasyTier 路由状态管理器，逻辑移植自 peer_ospf_route.rs。
///
/// 信令服务器拓扑:所有节点直连本中继,路由信息只能由条目所有者
/// 本人上报;服务端重启后客户端回传的缓存第三方路由一律拒收,
/// 网关代发(链式接入)能力已移除。
///
/// 错误处理哲学对齐上游:路由层校验失败一律作为可容忍的数据问题
/// 返回给调用方(由 RPC 层写入 `SyncRouteInfoResponse.error`),
/// 绝不升级为断开连接。
pub(crate) struct RouteState {
    groups: HashMap<String, RouteGroupData>,
    my_peer_id: PeerId,
    // DO 重启后由宿主注入的持久化 peer_route_id,分组创建时优先于随机值。
    route_id_overrides: HashMap<String, u64>,
}

impl RouteState {
    pub(crate) fn new(my_peer_id: PeerId) -> Self {
        RouteState {
            groups: HashMap::new(),
            route_id_overrides: HashMap::new(),
            my_peer_id,
        }
    }

    /// 注入持久化的 peer_route_id(宿主在 DO 启动时从 storage 恢复)。
    /// 分组已存在则直接改写,否则在分组创建时优先使用。
    pub(crate) fn set_persisted_route_id(&mut self, group_key: &str, route_id: u64) {
        if let Some(g) = self.groups.get_mut(group_key) {
            g.my_info.peer_route_id = route_id;
        } else {
            self.route_id_overrides
                .insert(group_key.to_string(), route_id);
        }
    }

    /// 读取(必要时创建分组并生成本中继在该网络的 peer_route_id。
    /// 宿主负责把首次生成的值持久化到 DO storage,以便 DO 被平台驱逐
    /// 重启后复用同一 route_id——上游服务进程长驻、route_id 天然稳定,
    /// 客户端会拿它区分服务端路由条目实例,反复变化会与新实例冲突。
    pub(crate) fn my_peer_route_id(&mut self, group_key: &str) -> u64 {
        let g = self.ensure_group(group_key);
        g.my_info.peer_route_id
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
        let persisted_route_id = self.route_id_overrides.remove(group_key);
        self.groups.entry(group_key.to_string()).or_insert_with(|| {
            let mut my_info = RoutePeerInfo::default();
            my_info.peer_id = my_peer_id;
            my_info.inst_id = Some(Self::random_uuid());
            my_info.cost = 0;
            my_info.version = 1;
            my_info.network_length = 24;
            my_info.easytier_version = EASYTIER_VERSION.to_string();
            my_info.hostname = Some("edge".to_string());
            my_info.peer_route_id = persisted_route_id.unwrap_or_else(Self::random_u64);
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
                authenticated_peer_keys: HashMap::new(),
                sessions: HashMap::new(),
                conn_rows: HashMap::new(),
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
        now_ms: u64,
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
        // 重连基线:会话活跃度以“收到对端数据”为准,新连接建立即重置
        // liveness 计时起点,避免刚重连的节点被 sweep 误判为半开连接。
        g.sessions.entry(peer_id).or_default().last_touch_ms = now_ms;
        // 重复 peer_id 携新密钥(节点重启换钥后重连)时直接覆盖旧绑定:
        // 新连接已通过传输层鉴权,旧绑定只是残留状态。上游从不因密钥
        // 漂移拒绝连接,此处拒绝会让重连进入死循环。
        g.authenticated_peer_keys.insert(peer_id, public_key);
        let is_new = g.peers.insert(peer_id);
        if is_new {
            // 新设备加入只改变中继自身的连接行,版本仅在中继行上递增;
            // 客户端行版本由客户端自己维护,服务端不虚抬。
            Self::update_my_conn_row(g, my_peer_id);
            Self::note_topology_change(g);
        }
        Ok(())
    }

    pub(crate) fn remove_peer(&mut self, group_key: &str, peer_id: PeerId) {
        let my_peer_id = self.my_peer_id;
        let g = self.ensure_group(group_key);
        let was_present = g.peers.remove(&peer_id);
        let had_info = g.peer_infos.remove(&peer_id).is_some();
        g.authenticated_peer_keys.remove(&peer_id);
        g.sessions.remove(&peer_id);
        g.conn_rows.remove(&peer_id);
        for session in g.sessions.values_mut() {
            session.peer_info_ver_map.remove(&peer_id);
            session.last_topology_version = 0;
        }
        if was_present || had_info {
            Self::update_my_conn_row(g, my_peer_id);
            Self::note_topology_change(g);
        }
    }

    /// 定期回收过期路由信息(对齐上游 clear_expired_peer):
    /// - 半开直连节点:会话超过 REMOVE_UNREACHABLE_PEER_INFO_AFTER_MS
    ///   (90s)没有任何同步活动时,执行完整 remove_peer 语义(覆盖
    ///   WebSocket close 事件丢失、remove_peer 未被调用的异常掉线),
    ///   并上报给宿主关闭对应连接;
    /// - 直连节点的路由条目:条目过期且会话已超时(90s)时回收;
    /// - 任何条目超过 REMOVE_DEAD_PEER_INFO_AFTER_MS(3660s)
    ///   无条件回收(正常节点每 3600s 至少版本续期一次)。
    pub(crate) fn sweep_expired_route_info(&mut self, now_ms: u64) -> SweepOutcome {
        let group_keys: Vec<String> = self.groups.keys().cloned().collect();
        let mut route_changed_networks: Vec<String> = Vec::new();
        let mut dead_direct_peers: Vec<String> = Vec::new();
        for group_key in group_keys {
            let mut group_changed = false;
            // Pass 1: 半开直连检测。会话 90s 无任何收包即视为半开连接,
            // 执行完整 remove_peer(含拓扑版本推进)。
            let dead_direct: Vec<PeerId> = {
                let g = self.groups.get(&group_key).expect("group exists");
                g.peers
                    .iter()
                    .copied()
                    .filter(|pid| {
                        !g.sessions.get(pid).is_some_and(|s| {
                            now_ms.saturating_sub(s.last_touch_ms)
                                <= REMOVE_UNREACHABLE_PEER_INFO_AFTER_MS
                        })
                    })
                    .collect()
            };
            for pid in dead_direct {
                self.remove_peer(&group_key, pid);
                // "网络\u{1f}peer_id":宿主据此关闭对应 WebSocket。
                dead_direct_peers.push(format!("{}\u{1f}{}", group_key, pid));
                group_changed = true;
            }
            let g = self.groups.get_mut(&group_key).expect("group exists");
            let age_ms = |info: &RoutePeerInfo| -> u64 {
                info.last_update
                    .as_ref()
                    .map(|ts| now_ms.saturating_sub((ts.seconds.max(0) as u64) * 1_000))
                    .unwrap_or(u64::MAX)
            };
            // Pass 2: 过期条目回收。直连节点的条目在"信息过期(90s)且
            // 会话已静默(90s)"时回收;任何条目超过 3660s 未续期则无条件
            // 回收。半开直连节点已由 Pass 1 的完整 remove_peer 处理。
            let purge: Vec<PeerId> = g
                .peer_infos
                .iter()
                .filter_map(|(pid, info)| {
                    let age = age_ms(info);
                    if age <= REMOVE_UNREACHABLE_PEER_INFO_AFTER_MS {
                        return None;
                    }
                    if age > REMOVE_DEAD_PEER_INFO_AFTER_MS {
                        return Some(*pid);
                    }
                    let reachable = g.sessions.get(pid).is_some_and(|s| {
                        now_ms.saturating_sub(s.last_touch_ms)
                            <= REMOVE_UNREACHABLE_PEER_INFO_AFTER_MS
                    });
                    (!reachable).then_some(*pid)
                })
                .collect();
            if !purge.is_empty() {
                for pid in &purge {
                    g.peer_infos.remove(pid);
                    g.authenticated_peer_keys.remove(pid);
                    g.conn_rows.remove(pid);
                    for session in g.sessions.values_mut() {
                        session.peer_info_ver_map.remove(pid);
                        session.last_topology_version = 0;
                    }
                }
                Self::note_topology_change(g);
                group_changed = true;
            }
            if group_changed {
                route_changed_networks.push(group_key.clone());
            }
        }
        SweepOutcome {
            route_changed_networks,
            dead_direct_peers,
        }
    }

    /// 查询到达目标节点的下一跳。信令服务器拓扑下所有节点直连,
    /// 已知节点返回自身,未知节点返回 None(宿主视为无路由)。
    pub(crate) fn get_next_hop(&self, group_key: &str, target_peer_id: PeerId) -> Option<PeerId> {
        let g = self.groups.get(group_key)?;
        if g.peers.contains(&target_peer_id) {
            return Some(target_peer_id);
        }
        None
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
        // 注意:这里绝不刷新 last_touch_ms——会话活跃度只能以"收到对端
        // 数据"(请求/响应/ack)为准;若发送侧也刷新,半开连接(close 事件
        // 丢失)会被服务端自己的周期重发永远保持"活跃",sweep 永远
        // 检测不到它。
        {
            let session = g.sessions.entry(target_peer_id).or_default();
            session.my_session_id = Some(server_session_id);
        }

        let force_full_local = {
            let session = g.sessions.get(&target_peer_id);
            force_full || session.map(|s| s.dst_session_id.is_none()).unwrap_or(true)
        };

        let mut all_peers: BTreeSet<PeerId> = g.peers.clone();
        // 持有路由条目与 conn 行的节点也要参与拓扑广播。
        all_peers.extend(g.peer_infos.keys().copied());
        // 持有 conn 行的节点(可能仅有行而无 peer_info)也要参与拓扑广播。
        all_peers.extend(g.conn_rows.keys().copied());
        all_peers.insert(my_peer_id);
        all_peers.insert(target_peer_id);
        let relevant_peers: Vec<PeerId> = all_peers.into_iter().collect();

        let mut typed_items: Vec<RoutePeerInfo> = Vec::new();
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
        if !typed_items.is_empty() {
            // peer_infos(字段 4)手工编码;protobuf 字段顺序无关,
            // 上游 prost 解码不受影响。
            let mut field = Vec::new();
            for info in &typed_items {
                push_len_delimited(&mut field, 1, &info.encode_to_vec());
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
        let mut need_bump = false;
        if let Some(infos) = &req.peer_infos {
            for info in infos.items.iter() {
                if info.peer_id != from_peer_id {
                    // 信令服务器拓扑:所有节点直连本中继。第三方条目在
                    // 此拓扑下没有合法来源,只能是服务端重启后客户端缓存
                    // 回传的陈旧路由(典型形态:携带早已离线节点的
                    // peer_infos),一律拒收。
                    continue;
                }
                // 信息性首见绑定:上报公钥与握手绑定不一致时容忍放行,
                // 身份由传输层(Noise 会话)强制,路由层不重复鉴权。
                let authenticated_key = g
                    .authenticated_peer_keys
                    .entry(from_peer_id)
                    .or_default();
                validate_or_bind_reported_key(
                    authenticated_key,
                    &info.noise_static_pubkey,
                )?;
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
                // 直连条目沿用服务端接收时间,使 sweep 的 90s/3660s
                // 过期判断以真实接收时间为准。
                info.last_update = Some(crate::proto::Timestamp {
                    seconds: (now_ms / 1000) as i64,
                    nanos: 0,
                });
                g.peer_infos.insert(info.peer_id, info);
                if is_new {
                    need_bump = true;
                }
            }
        }

        // 按所有者版本语义入库上报方自己的 conn 行,仅当上报版本更高
        // 时覆盖;其他节点的行一律拒收(防止已认证节点伪造他节点拓扑),
        // 行内未知邻居在入库前剥离(服务端重启后缓存回传的幽灵路由)。
        let conn_rows_changed =
            Self::store_conn_rows(g, req.conn_info.as_ref(), my_peer_id, from_peer_id);
        if need_bump || conn_rows_changed {
            Self::note_topology_change(g);
        }
        if conn_rows_changed {
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

    /// 中继自身的 conn 行:仅在直连节点集合真正变化时递增版本
    /// (上游 update_my_conn_info 语义,内容比较而非事件计数)。
    fn update_my_conn_row(g: &mut RouteGroupData, my_peer_id: PeerId) {
        let connected: BTreeSet<PeerId> = g.peers.iter().copied().collect();
        let row = g.conn_rows.entry(my_peer_id).or_default();
        if row.connected != connected {
            row.version += 1;
            row.connected = connected;
        }
    }

    /// 标记拓扑内容变化:递增内部拓扑版本并失效 conn 缓存。
    /// 注意这里不触碰任何 conn 行版本——行版本属于行所有者。
    fn note_topology_change(g: &mut RouteGroupData) {
        g.topology_version = g.topology_version.wrapping_add(1).max(1);
        g.cached_conn_bitmap = None;
        g.cached_conn_peer_list = None;
    }

    /// 按上游语义入库上报的 conn 行:
    /// - 行只能由所有者本人上报(pid == from_peer_id):信令服务器拓扑
    ///   下所有节点直连,每个节点都会自行上报自身行;接受代发的其他
    ///   节点行等于允许已认证节点伪造他节点拓扑(拉高版本覆盖真实
    ///   视图并全网广播);
    /// - 行版本由行所有者维护,仅当上报版本严格高于已存版本时覆盖;
    /// - 中继自身的行(以及 bitmap 中版本为 0 的引用占位)不入库;
    /// - 行内不被本中继认识的邻居 id 在入库前剥离(服务端重启后
    ///   客户端缓存回传的幽灵引用),其余内容原样保留。
    fn store_conn_rows(
        g: &mut RouteGroupData,
        conn: Option<&ConnInfo>,
        my_peer_id: PeerId,
        from_peer_id: PeerId,
    ) -> bool {
        let Some(conn) = conn else {
            return false;
        };
        let mut changed = false;
        let mut accept = |pid: PeerId, version: Version, connected: BTreeSet<PeerId>| {
            if pid != from_peer_id || pid == my_peer_id || version == 0 {
                return;
            }
            // 过滤上报行里不被本中继认识的邻居 id。服务端重启后状态清零,
            // 老节点会把重启前的缓存拓扑原样回传:其中对早已离线节点
            // (例如与其他节点已断开的半开 p2p 链路)的引用没有任何
            // peer_info 与 conn 行来源。若原样入库并转播,所有客户端都会
            // 为这些幽灵 id 创建空 peer_info 占位条目,污染路由表;幽灵
            // 的真实行版本也永远不会续期,只能靠 3660s 的死条目回收清理。
            // 只保留拓扑内已知成员(直连节点、已有路由条目的节点、本中继)。
            let known_neighbors: BTreeSet<PeerId> = {
                let peers = &g.peers;
                let peer_infos = &g.peer_infos;
                connected
                    .iter()
                    .copied()
                    .filter(|neighbor| {
                        *neighbor == my_peer_id
                            || peers.contains(neighbor)
                            || peer_infos.contains_key(neighbor)
                    })
                    .collect()
            };
            let entry = g.conn_rows.entry(pid).or_default();
            if version > entry.version {
                entry.version = version;
                entry.connected = known_neighbors;
                changed = true;
            }
        };
        match conn {
            ConnInfo::ConnPeerList(list) => {
                for row in &list.peer_conn_infos {
                    let Some(pv) = row.peer_id.as_ref() else {
                        continue;
                    };
                    let connected: BTreeSet<PeerId> =
                        row.connected_peer_ids.iter().copied().collect();
                    accept(pv.peer_id, pv.version, connected);
                }
            }
            ConnInfo::ConnBitmap(bitmap) => {
                let n = bitmap.peer_ids.len();
                for (i, pv) in bitmap.peer_ids.iter().enumerate() {
                    let mut connected = BTreeSet::new();
                    for (j, other) in bitmap.peer_ids.iter().enumerate() {
                        if i == j {
                            continue;
                        }
                        let bit = i * n + j;
                        if let Some(byte) = bitmap.bitmap.get(bit / 8) {
                            if byte & (1 << (bit % 8)) != 0 {
                                connected.insert(other.peer_id);
                            }
                        }
                    }
                    accept(pv.peer_id, pv.version, connected);
                }
            }
        }
        changed
    }

    /// 解析单个节点的 conn 行:
    /// - 有所有者上报的行: 原样使用其版本与邻居集合。
    /// - 无行的直连节点: 空行(版本 0)。与中继的边由中继自身行提供,
    ///   与其他节点的 p2p 边由对端上报的行提供。
    fn conn_row_for(g: &RouteGroupData, pid: PeerId) -> (Version, BTreeSet<PeerId>) {
        if let Some(row) = g.conn_rows.get(&pid) {
            return (row.version, row.connected.clone());
        }
        // 尚未上报自身行的直连节点:空行(版本 0)。与中继的边由
        // 中继自身行提供,与其他节点的 p2p 边由对端上报的行提供。
        (0, BTreeSet::new())
    }

    fn build_conn_info(
        g: &mut RouteGroupData,
        relevant_peers: &[PeerId],
        target_peer_id: PeerId,
        supports_conn_list: bool,
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
        // 先解析全部行(不可变借用),再写入缓存(可变借用)。
        let rows: Vec<(PeerId, Version, BTreeSet<PeerId>)> = relevant_peers
            .iter()
            .map(|pid| {
                let (version, connected) = Self::conn_row_for(g, *pid);
                (*pid, version, connected)
            })
            .collect();
        let peer_id_versions: Vec<PeerIdVersion> = rows
            .iter()
            .map(|(pid, version, _)| PeerIdVersion {
                peer_id: *pid,
                version: *version,
            })
            .collect();

        if supports_conn_list {
            let peer_conn_infos = rows
                .iter()
                .map(|(pid, version, connected)| route_conn_peer_list::PeerConnInfo {
                    peer_id: Some(PeerIdVersion {
                        peer_id: *pid,
                        version: *version,
                    }),
                    connected_peer_ids: connected.iter().copied().collect(),
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

        for (i, (_, _, connected)) in rows.iter().enumerate() {
            // 与上游一致只编码真实边,不置自环位:置位后客户端用
            // get_connected_peers 解码会把节点自己读进 connected 集合,
            // 属于编码语义偏差的脏数据。
            for link in connected {
                if let Some(&j) = idx_by_peer.get(link) {
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

#[cfg(test)]
mod tests {
    use super::{
        ConnInfo, PeerId, PeerIdVersion, REMOVE_DEAD_PEER_INFO_AFTER_MS,
        REMOVE_UNREACHABLE_PEER_INFO_AFTER_MS, RouteConnPeerList, RoutePeerInfo,
        RouteState, SyncRouteInfoRequest, push_len_delimited, push_varint, read_varint,
        route_conn_peer_list, validate_or_bind_reported_key,
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
    const PEER_B: PeerId = 6;

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
            last_update: Some(crate::proto::Timestamp {
                seconds: 1,
                nanos: 0,
            }),
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
        conn_row_v(pid, 1, connected)
    }

    fn conn_row_v(
        pid: PeerId,
        version: u32,
        connected: &[PeerId],
    ) -> route_conn_peer_list::PeerConnInfo {
        route_conn_peer_list::PeerConnInfo {
            peer_id: Some(PeerIdVersion { peer_id: pid, version }),
            connected_peer_ids: connected.to_vec(),
        }
    }

    #[test]
    fn key_mismatch_is_tolerated_not_rejected() {
        // 对齐上游:路由层不做密钥鉴权,不一致时保留首个绑定并放行。
        let mut bound = KEY_A.to_vec();
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_A).is_ok());
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_B).is_ok());
        assert!(validate_or_bind_reported_key(&mut bound, &[]).is_ok());
        assert_eq!(bound, KEY_A.to_vec());
    }

    #[test]
    fn legacy_peer_binds_reported_key_on_first_sync() {
        // legacy 握手绑定为空键;secure-mode 客户端会在 RoutePeerInfo
        // 中上报真实 X25519 公钥,首次同步时完成首见绑定。
        let mut bound = Vec::new();
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_A).is_ok());
        assert_eq!(bound, KEY_A.to_vec());
        // 绑定后同一连接内换公钥:保留首个绑定,容忍放行。
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_B).is_ok());
        assert_eq!(bound, KEY_A.to_vec());
        // 重复上报同一公钥保持通过。
        assert!(validate_or_bind_reported_key(&mut bound, &KEY_A).is_ok());
    }

    #[test]
    fn legacy_peer_may_stay_keyless() {
        // 上游非 secure-mode 客户端上报的是空公钥
        // (`unwrap_or_default()`),空对空放行且不做绑定。
        let mut bound = Vec::new();
        assert!(validate_or_bind_reported_key(&mut bound, &[]).is_ok());
        assert!(bound.is_empty());
    }

    #[test]
    fn malformed_key_lengths_are_ignored() {
        // 长度异常的上报值既不绑定也不拒绝。
        let mut empty = Vec::new();
        assert!(validate_or_bind_reported_key(&mut empty, &[1u8; 16]).is_ok());
        assert!(empty.is_empty());
        let mut bound = KEY_A.to_vec();
        assert!(validate_or_bind_reported_key(&mut bound, &[1u8; 33]).is_ok());
        assert_eq!(bound, KEY_A.to_vec());
    }

    #[test]
    fn peer_route_id_is_stable_across_restart() {
        // DO 重启后宿主注入持久化的 route_id,分组复用旧值,
        // 避免客户端缓存的服务端条目与新实例冲突。
        let mut s = RouteState::new(SERVER_ID);
        s.set_persisted_route_id("net", 0x00ff_00ff_00ff_00ff);
        s.add_peer("net", GATEWAY_B, &[], 1_000).unwrap();
        let route_id = s.my_peer_route_id("net");
        assert_eq!(route_id, 0x00ff_00ff_00ff_00ff);

        // 模拟 DO 重新实例化:新 RouteState + 相同持久化值。
        let mut s2 = RouteState::new(SERVER_ID);
        s2.set_persisted_route_id("net", route_id);
        s2.add_peer("net", GATEWAY_B, &[], 1_000).unwrap();
        assert_eq!(s2.my_peer_route_id("net"), route_id);
    }

    #[test]
    fn peer_route_id_defaults_to_random_when_not_persisted() {
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[], 1_000).unwrap();
        let route_id = s.my_peer_route_id("net");
        assert_ne!(route_id, 0);
        // 同一实例内保持稳定。
        assert_eq!(s.my_peer_route_id("net"), route_id);
        assert_eq!(s.my_peer_route_id("other"), s.my_peer_route_id("other"));
    }

    #[test]
    fn conn_rows_strip_unknown_neighbors_after_server_restart() {
        // 复现:服务端重启后状态清零,老节点重连时把重启前的缓存拓扑
        // 原样回传。其自身 conn 行可能仍引用早已离线的节点(例如与其他
        // 节点重启前实例的半开 p2p 链路)。这类未知邻居不得入库转播,
        // 否则全网客户端都会为幽灵 id 创建空 peer_info 占位条目。
        let ghost: PeerId = 972326755;
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", PEER_A, &[], 1_000).unwrap();
        s.add_peer("net", PEER_B, &[], 1_000).unwrap();
        // B 同步自身 info(使推送走 ConnPeerList,与真实客户端一致)。
        let req_b = sync_req(PEER_B, vec![conn_list_peer_info(PEER_B, 1, &key(0x55), 10)], None);
        s.handle_sync_route_info_request("net", PEER_B, &req_b, 1_000)
            .unwrap();
        // A 上报自身行:与中继相连,同时携带幽灵邻居(对端已消失)。
        let conn = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![conn_row_v(PEER_A, 5, &[SERVER_ID, ghost])],
        });
        let req = sync_req(
            PEER_A,
            vec![conn_list_peer_info(PEER_A, 1, &key(0x44), 9)],
            Some(conn),
        );
        let outcome = s.handle_sync_route_info_request("net", PEER_A, &req, 1_000).unwrap();
        assert!(outcome.route_changed);
        let g = s.groups.get("net").unwrap();
        let row = g.conn_rows.get(&PEER_A).unwrap();
        assert!(row.connected.contains(&SERVER_ID));
        assert!(
            !row.connected.contains(&ghost),
            "unknown neighbors must be stripped before storing"
        );
        // 转播给其他节点的行同样不得包含幽灵。
        let update = s
            .build_sync_route_info_request("net", PEER_B, 9, false, true, 2_000)
            .unwrap();
        let decoded = SyncRouteInfoRequest::decode(update.payload.as_slice()).unwrap();
        let ConnInfo::ConnPeerList(list) = decoded.conn_info.unwrap() else {
            panic!("expected conn peer list");
        };
        let row_a = list
            .peer_conn_infos
            .iter()
            .find(|r| r.peer_id.as_ref().is_some_and(|pv| pv.peer_id == PEER_A))
            .unwrap();
        assert!(row_a.connected_peer_ids.contains(&SERVER_ID));
        assert!(!row_a.connected_peer_ids.contains(&ghost));
    }

    #[test]
    fn reconnect_after_restart_learns_newly_joined_peer() {
        // 复现用户场景:服务端重启 → 老节点重连并回传缓存 → 新节点加入。
        // 老节点的下一次增量推送必须携带新节点的 peer_info,否则老节点
        // 无法为新节点路由 RPC 响应,双方打洞协调(get_ip_list 等)超时,
        // 表现为"新重启的节点和没重启的节点互相不能连接"。
        let old_peer = PEER_A;
        let new_peer = PEER_B;
        // 重启后:全新状态(重启前的内存路由表已丢失)。
        let mut s = RouteState::new(SERVER_ID);
        // 老节点重连,回传自身 info v6 与行 v16。
        s.add_peer("net", old_peer, &[], 10_000).unwrap();
        let lede_conn = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![conn_row_v(old_peer, 16, &[SERVER_ID])],
        });
        let lede_req = sync_req(
            old_peer,
            vec![conn_list_peer_info(old_peer, 6, &key(0x44), 9)],
            Some(lede_conn),
        );
        let outcome = s
            .handle_sync_route_info_request("net", old_peer, &lede_req, 10_100)
            .unwrap();
        assert!(outcome.session_changed);
        // 新节点加入,上报自身 info v3 与行 v2。
        s.add_peer("net", new_peer, &[], 12_000).unwrap();
        let new_conn = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![conn_row_v(new_peer, 2, &[SERVER_ID])],
        });
        let new_req = sync_req(
            new_peer,
            vec![conn_list_peer_info(new_peer, 3, &key(0x55), 10)],
            Some(new_conn),
        );
        s.handle_sync_route_info_request("net", new_peer, &new_req, 12_100)
            .unwrap();
        // 老节点的周期请求(空请求,保持会话活跃)。
        let empty = sync_req(old_peer, vec![], None);
        s.handle_sync_route_info_request("net", old_peer, &empty, 13_000)
            .unwrap();
        // 关键断言:推送给老节点的增量更新携带新节点的 peer_info。
        let update = s
            .build_sync_route_info_request("net", old_peer, 42, false, false, 14_000)
            .unwrap();
        let decoded = SyncRouteInfoRequest::decode(update.payload.as_slice()).unwrap();
        let items = decoded
            .peer_infos
            .as_ref()
            .map(|infos| infos.items.clone())
            .unwrap_or_default();
        assert!(
            items
                .iter()
                .any(|info| info.peer_id == new_peer && info.version == 3),
            "incremental push to the reconnected old node must carry the new peer's info, got: {items:?}"
        );
        // 且拓扑行必须体现新节点与中继的链路(老节点据此计算下一跳)。
        let ConnInfo::ConnPeerList(list) = decoded.conn_info.unwrap() else {
            panic!("expected conn peer list");
        };
        assert!(list
            .peer_conn_infos
            .iter()
            .any(|row| row.connected_peer_ids.contains(&new_peer)));
    }

    #[test]
    fn conn_row_versions_are_owner_controlled() {
        // 回归:新设备加入只递增中继自身的行版本;客户端行保留所有者
        // 版本与完整邻居集合,不再被服务端虚抬的过期视图覆盖
        // (p2p → 中继 → p2p 震荡的根因)。
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[], 1_000).unwrap();
        s.add_peer("net", PEER_A, &[], 1_000).unwrap();
        let req_a = sync_req(PEER_A, vec![conn_list_peer_info(PEER_A, 1, &key(0x44), 9)], None);
        s.handle_sync_route_info_request("net", PEER_A, &req_a, 1_000)
            .unwrap();
        // B 上报自身行(版本 5):与中继和 A 皆有连接(p2p)。
        let conn = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![conn_row_v(GATEWAY_B, 5, &[SERVER_ID, PEER_A])],
        });
        let req = sync_req(GATEWAY_B, vec![], Some(conn));
        s.handle_sync_route_info_request("net", GATEWAY_B, &req, 1_000)
            .unwrap();
        // 新设备 D 加入。
        s.add_peer("net", GATEWAY_D, &[], 1_000).unwrap();
        let update = s
            .build_sync_route_info_request("net", PEER_A, 9, true, false, 2_000)
            .unwrap();
        let decoded = SyncRouteInfoRequest::decode(update.payload.as_slice()).unwrap();
        let ConnInfo::ConnPeerList(list) = decoded.conn_info.unwrap() else {
            panic!("expected conn peer list");
        };
        let row = |pid: PeerId| {
            list.peer_conn_infos
                .iter()
                .find(|r| r.peer_id.as_ref().is_some_and(|pv| pv.peer_id == pid))
                .unwrap()
        };
        // B 的行仍是版本 5,p2p 边 B--A 完整保留。
        assert_eq!(row(GATEWAY_B).peer_id.as_ref().unwrap().version, 5);
        let connected = row(GATEWAY_B).connected_peer_ids.clone();
        assert!(connected.contains(&PEER_A));
        assert!(connected.contains(&SERVER_ID));
        // 中继行因 D 加入递增到 3(依次加入 B、A、D)。
        assert_eq!(row(SERVER_ID).peer_id.as_ref().unwrap().version, 3);
        assert!(row(SERVER_ID).connected_peer_ids.contains(&GATEWAY_D));
    }

    #[test]
    fn stale_conn_rows_are_ignored() {
        // 低版本的行上报(乱序/重放)不会覆盖已存的更高版本内容。
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[], 1_000).unwrap();
        s.add_peer("net", PEER_A, &[], 1_000).unwrap();
        let req_a = sync_req(PEER_A, vec![conn_list_peer_info(PEER_A, 1, &key(0x44), 9)], None);
        s.handle_sync_route_info_request("net", PEER_A, &req_a, 1_000)
            .unwrap();
        let fresh = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![conn_row_v(GATEWAY_B, 5, &[SERVER_ID, PEER_A])],
        });
        s.handle_sync_route_info_request("net", GATEWAY_B, &sync_req(GATEWAY_B, vec![], Some(fresh)), 1_000)
            .unwrap();
        let stale = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![conn_row_v(GATEWAY_B, 3, &[SERVER_ID])],
        });
        s.handle_sync_route_info_request("net", GATEWAY_B, &sync_req(GATEWAY_B, vec![], Some(stale)), 2_000)
            .unwrap();
        let g = s.groups.get("net").unwrap();
        let row = g.conn_rows.get(&GATEWAY_B).unwrap();
        assert_eq!(row.version, 5);
        assert!(row.connected.contains(&PEER_A));
    }

    #[test]
    fn get_next_hop_unknown_peer_is_none() {
        let s = RouteState::new(SERVER_ID);
        assert_eq!(s.get_next_hop("net", 4242), None);
        assert_eq!(s.get_next_hop("missing", 1), None);
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

    #[test]
    fn relay_disabled_rejects_third_party_entries() {
        // 信令服务器拓扑:服务端重启后客户端回传本地缓存的第三方路由,
        // 必须被整体拒收——不存 peer_infos、不做公钥绑定;
        // 上报方自身的直连信息不受影响。
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &key(0x22), 1_000).unwrap();
        let req = sync_req(
            GATEWAY_B,
            vec![
                peer_info(CHAINED_C, 1, &key(0x33), 1),
                peer_info(GATEWAY_B, 2, &key(0x22), 2),
            ],
            None,
        );
        let outcome = s
            .handle_sync_route_info_request("net", GATEWAY_B, &req, 1_000)
            .unwrap();
        assert!(outcome.route_changed);
        let g = s.groups.get("net").unwrap();
        assert!(!g.peer_infos.contains_key(&CHAINED_C));
        assert!(!g.authenticated_peer_keys.contains_key(&CHAINED_C));
        // 直连信息照常入库。
        assert!(g
            .peer_infos
            .get(&GATEWAY_B)
            .is_some_and(|info| info.version == 2));
        // 未知节点没有下一跳。
        assert_eq!(s.get_next_hop("net", CHAINED_C), None);
    }

    #[test]
    fn relay_disabled_rejects_third_party_conn_rows() {
        // 非所有者上报的 conn 行一律拒收(信令服务器拓扑下只有
        // 条目所有者本人可以上报自身行)。
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", GATEWAY_B, &[], 1_000).unwrap();
        let conn = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![conn_row_v(CHAINED_C, 9, &[GATEWAY_B])],
        });
        let req = sync_req(GATEWAY_B, vec![], Some(conn));
        s.handle_sync_route_info_request("net", GATEWAY_B, &req, 1_000)
            .unwrap();
        let g = s.groups.get("net").unwrap();
        assert!(!g.conn_rows.contains_key(&CHAINED_C));
    }

    #[test]
    fn half_open_direct_peer_is_reported_for_close() {
        // 半开直连(close 事件丢失)在 90s 静默后被完整移除并上报:
        // 上报格式为 "网络\u001fpeer_id",宿主据此关闭 WebSocket。
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", PEER_A, &key(0x44), 1_000).unwrap();
        let req = sync_req(PEER_A, vec![peer_info(PEER_A, 1, &key(0x44), 9)], None);
        s.handle_sync_route_info_request("net", PEER_A, &req, 1_000)
            .unwrap();
        // 89s:仍在宽限期内。
        let early = s.sweep_expired_route_info(REMOVE_UNREACHABLE_PEER_INFO_AFTER_MS - 1_000);
        assert!(early.dead_direct_peers.is_empty());
        // 91s:上报移除。注:会话 touch 时刻为 1_000,实际静默时长
        // 以 last_touch 为准,这里用足够大的时间差覆盖秒级截断。
        let late = s.sweep_expired_route_info(REMOVE_UNREACHABLE_PEER_INFO_AFTER_MS + 2_000);
        assert_eq!(late.dead_direct_peers, vec!["net\u{1f}4".to_string()]);
        assert!(!s.groups["net"].peers.contains(&PEER_A));
    }

    #[test]
    fn sweep_purges_silent_direct_peer_route_info() {
        // 直连节点异常掉线(close 事件丢失)且 90s 无任何同步活动时,
        // 其自身路由条目也应被回收,避免永久残留。
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", PEER_A, &key(0x44), 1_000).unwrap();
        let req = sync_req(PEER_A, vec![peer_info(PEER_A, 1, &key(0x44), 9)], None);
        s.handle_sync_route_info_request("net", PEER_A, &req, 1_000)
            .unwrap();
        assert!(s.groups["net"].peer_infos.contains_key(&PEER_A));
        // 预留秒截断余量。
        let t = REMOVE_UNREACHABLE_PEER_INFO_AFTER_MS + 2_000;
        let outcome = s.sweep_expired_route_info(t);
        // 直连节点整体移除并上报:g.peers 也不复存在(不再广播假边)。
        assert!(outcome.route_changed_networks.contains(&"net".to_string()));
        assert_eq!(outcome.dead_direct_peers.len(), 1);
        assert!(!s.groups["net"].peer_infos.contains_key(&PEER_A));
        assert!(!s.groups["net"].peers.contains(&PEER_A));
    }

    #[test]
    fn conn_rows_reject_forged_rows_from_other_peers() {
        // S1 修复:conn 行只能由所有者本人上报。已认证节点 A 尝试以更高
        // 版本替直连节点 B 伪造 conn 行,必须被拒收;B 随后自报的低版本
        // 行照常入库(所有者语义,不受伪造版本影响)。
        let mut s = RouteState::new(SERVER_ID);
        s.add_peer("net", PEER_A, &[], 1_000).unwrap();
        s.add_peer("net", PEER_B, &[], 1_000).unwrap();
        let info_a = sync_req(PEER_A, vec![peer_info(PEER_A, 1, &key(0x11), 1)], None);
        s.handle_sync_route_info_request("net", PEER_A, &info_a, 1_000)
            .unwrap();
        let info_b = sync_req(PEER_B, vec![peer_info(PEER_B, 1, &key(0x22), 2)], None);
        s.handle_sync_route_info_request("net", PEER_B, &info_b, 1_000)
            .unwrap();
        // A 替 B 上报一行(v99,声称 B 与 A 相连)。
        let forged = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![conn_row_v(PEER_B, 99, &[SERVER_ID, PEER_A])],
        });
        let req = sync_req(PEER_A, vec![], Some(forged));
        let outcome = s
            .handle_sync_route_info_request("net", PEER_A, &req, 2_000)
            .unwrap();
        assert!(!outcome.route_changed);
        let g = s.groups.get("net").unwrap();
        // B 的行尚未由 B 本人上报:伪造行不得入库。
        assert!(!g.conn_rows.contains_key(&PEER_B));
        // B 本人随后上报真实行(v5),照常接受。
        let honest = ConnInfo::ConnPeerList(RouteConnPeerList {
            peer_conn_infos: vec![conn_row_v(PEER_B, 5, &[SERVER_ID])],
        });
        let req = sync_req(PEER_B, vec![], Some(honest));
        s.handle_sync_route_info_request("net", PEER_B, &req, 3_000)
            .unwrap();
        let row = s
            .groups
            .get("net")
            .unwrap()
            .conn_rows
            .get(&PEER_B)
            .unwrap();
        assert_eq!(row.version, 5);
        assert!(row.connected.contains(&SERVER_ID));
        assert!(!row.connected.contains(&PEER_A));
    }
}
