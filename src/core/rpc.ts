import { WasmRpcCore } from "../wasm";
import { PacketType } from "./constants";
import { createPacket } from "./packet";

export interface RpcPeer {
	peerId: number;
	networkName: string;
	serverSessionId: bigint;
	remotePublicKey: Uint8Array;
	encrypt(packet: Uint8Array): Uint8Array;
	send(packet: Uint8Array): void;
}

interface RouteSyncState {
	peer: RpcPeer;
	inFlight: boolean;
	dirty: boolean;
	forceFull: boolean;
	sentAt: number;
	lastCompletedAt: number;
}

interface RouteSyncFailure {
	/** 只需网络与节点标识:宿主据此定位并关闭对应连接。 */
	peer: Pick<RpcPeer, "networkName" | "peerId">;
	error: Error;
}

const ROUTE_SYNC_TIMEOUT_MS = 3_000;
const ROUTE_MAINTENANCE_INTERVAL_MS = 10_000;

export class EasyTierRpc {
	private readonly core: WasmRpcCore;
	private readonly routeSyncStates = new Map<string, RouteSyncState>();
	private readonly serverPeerId: number;

	constructor(
		publicKey: Uint8Array,
		hostname: string,
		serverPeerId: number,
		disableRelayData = false,
	) {
		this.core = new WasmRpcCore(publicKey, hostname, serverPeerId);
		if (disableRelayData) this.core.set_avoid_relay_data(true);
		this.serverPeerId = serverPeerId;
	}

	addPeer(peer: RpcPeer): void {
		this.core.add_peer(
			peer.networkName,
			peer.peerId,
			peer.remotePublicKey,
			BigInt(Date.now()),
		);
		this.routeSyncStates.delete(routeSyncKey(peer));
	}

	removePeer(peer: RpcPeer): void {
		this.core.remove_peer(peer.networkName, peer.peerId);
		this.routeSyncStates.delete(routeSyncKey(peer));
	}

	/** 查询链式接入节点的下一跳网关;返回 0 表示不可达。 */
	getNextHop(networkName: string, peerId: number): number {
		return this.core.get_next_hop(networkName, peerId);
	}

	/** 恢复 DO storage 持久化的 peer_route_id,须早于 addPeer 调用。 */
	setPeerRouteId(networkName: string, routeId: string): void {
		this.core.set_peer_route_id(networkName, routeId);
	}

	/** 读取(必要时生成)网络的 peer_route_id,首次生成的值需持久化。 */
	getPeerRouteId(networkName: string): string {
		return this.core.get_peer_route_id(networkName);
	}

	cleanExpired(now: number): { routeChangedNetworks: string[]; failures: RouteSyncFailure[] } {
		const json = this.core.clean_expired(BigInt(now));
		const parsed = JSON.parse(json) as {
			route_changed_networks: string[];
			dead_direct_peers: string[];
		};
		const failures: RouteSyncFailure[] = [];
		for (const entry of parsed.dead_direct_peers) {
			// "网络\u001fpeer_id":会话 90s 静默的半开直连节点,
			// wasm 层已做完整 remove_peer,这里上报宿主关闭连接。
			const sep = entry.lastIndexOf("\u001f");
			if (sep <= 0) continue;
			failures.push({
				peer: {
					networkName: entry.slice(0, sep),
					peerId: Number(entry.slice(sep + 1)),
			},
				error: new Error("route synchronization timed out; stale connection purged"),
			});
		}
		for (const state of this.routeSyncStates.values()) {
			if (!state.inFlight || now - state.sentAt <= ROUTE_SYNC_TIMEOUT_MS) continue;
			state.inFlight = false;
			state.dirty = true;
			state.forceFull = true;
			try {
				this.flushRouteUpdate(state, now);
			} catch (error) {
				failures.push({
					peer: state.peer,
					error: error instanceof Error ? error : new Error(String(error)),
				});
			}
		}
		return { routeChangedNetworks: parsed.route_changed_networks, failures };
	}

	handleRequest(
		peer: RpcPeer,
		payload: Uint8Array,
	): "handled" | "route" | "route-session" | "pending" {
		const result = this.core.handle_request(
			peer.networkName,
			peer.peerId,
			payload,
			BigInt(Date.now()),
		);
		if (result[0] === 0) return "pending";
		if (result.length === 1) throw new Error("WASM RPC core returned an empty response");
		this.sendControl(peer, PacketType.RpcResp, result.subarray(1));
		if (result[0] === 2) {
			this.sendRouteUpdate(peer, false);
			return "route";
		}
		if (result[0] === 3) {
			this.sendRouteUpdate(peer, false);
			return "route-session";
		}
		if (result[0] !== 1) throw new Error(`WASM RPC core returned unknown result ${result[0]}`);
		return "handled";
	}

	handleResponse(peer: RpcPeer, payload: Uint8Array): void {
		const complete = this.core.handle_response(
			peer.networkName,
			peer.peerId,
			payload,
			BigInt(Date.now()),
		);
		if (!complete) return;
		const state = this.routeSyncStates.get(routeSyncKey(peer));
		if (!state) return;
		state.inFlight = false;
		state.sentAt = 0;
		state.lastCompletedAt = Date.now();
		if (state.dirty || state.forceFull) this.flushRouteUpdate(state, Date.now());
	}

	maintainPeer(peer: RpcPeer, now: number): void {
		const state = this.routeSyncStates.get(routeSyncKey(peer));
		if (
			state === undefined ||
			state.inFlight ||
			now - state.lastCompletedAt < ROUTE_MAINTENANCE_INTERVAL_MS
		) {
			return;
		}
		this.sendRouteUpdate(peer, false);
	}

	sendRouteUpdate(peer: RpcPeer, forceFull: boolean): void {
		const key = routeSyncKey(peer);
		let state = this.routeSyncStates.get(key);
		if (!state) {
			state = {
				peer,
				inFlight: false,
				dirty: false,
				forceFull: false,
				sentAt: 0,
				lastCompletedAt: 0,
			};
			this.routeSyncStates.set(key, state);
		}
		state.peer = peer;
		state.dirty = true;
		state.forceFull ||= forceFull;
		this.flushRouteUpdate(state, Date.now());
	}

	private flushRouteUpdate(state: RouteSyncState, now: number): void {
		if (state.inFlight || (!state.dirty && !state.forceFull)) return;
		const forceFull = state.forceFull;
		// 先构建路由更新包;若失败则保留 dirty/forceFull 标志,
		// 下次维护周期(10s)或 cleanExpired 重试时会重新发起。
		const packet = this.core.build_route_update(
			state.peer.networkName,
			state.peer.peerId,
			state.peer.serverSessionId,
			forceFull,
			BigInt(now),
		);
		state.dirty = false;
		state.forceFull = false;
		state.inFlight = true;
		state.sentAt = now;
		try {
			this.sendControl(state.peer, PacketType.RpcReq, packet);
		} catch (error) {
			state.inFlight = false;
			state.dirty = true;
			state.forceFull ||= forceFull;
			throw error;
		}
	}

	private sendControl(peer: RpcPeer, packetType: PacketType, payload: Uint8Array): void {
		const clear = createPacket(this.serverPeerId, peer.peerId, packetType, payload);
		peer.send(peer.encrypt(clear));
	}
}

function routeSyncKey(peer: RpcPeer): string {
	// peerId 恒为数字,不含 ':',因此 name:id 拼接无歧义,
	// 且比 JSON.stringify([name, id]) 少两次对象/数组分配。
	return `${peer.networkName}:${peer.peerId}`;
}
