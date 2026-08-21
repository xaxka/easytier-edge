import { DurableObject } from "cloudflare:workers";
import {
	SecurePeer,
	build_legacy_handshake_response,
	generate_keypair,
	parse_legacy_handshake,
	verify_network_secret_digest,
} from "./wasm";
import { ENCRYPTED_FLAG, PacketType, SERVER_PEER_ID } from "./core/constants";
import { type EasyTierEnv, type ServerConfig, readServerConfig } from "./core/config";
import {
	createPong,
	incrementForwardCounter,
	isRelayDataPacket,
	parsePacket,
	toUint8Array,
} from "./core/packet";
import { EasyTierRpc } from "./core/rpc";
import {
	type Connection,
	completeHandshake,
	createConnection,
	disposeConnection,
} from "./runtime/connection";
import { errorMessage } from "./runtime/errors";
import {
	parseAuthenticationInfo,
	parseGeneratedKeypair,
	parseHandshakeInfo,
	parseLegacyHandshakeInfo,
} from "./runtime/messages";
import { RoomRegistry } from "./runtime/rooms";

const MAX_CONNECTIONS = 2_048;
/**
 * 未完成 Noise 握手的连接配额:防止攻击者用大量裸 socket 占满
 * 2048 个连接槽,把真实节点挤成 503。握手超时(10s)保证配额会自动释放。
 * 单 IP 上限可通过 MAX_PENDING_PER_IP 配置(默认 17)。
 */
const MAX_PENDING_HANDSHAKES = 256;
const UNKNOWN_IP = "unknown";
const IDENTITY_STORAGE_KEY = "secure-identity-v1";

interface StoredIdentity {
	privateKey: string;
	publicKey: string;
}

export class EasyTierServer extends DurableObject<EasyTierEnv> {
	private readonly doState: DurableObjectState;
	private readonly config: ServerConfig;
	private rpc!: EasyTierRpc;
	private localPrivateKey = "";
	private localPublicKey = "";
	private identityReady: Promise<void> | null = null;
	private readonly connections = new Map<WebSocket, Connection>();
	private readonly rooms = new RoomRegistry();
	private pendingHandshakes = 0;
	private readonly pendingHandshakesByIp = new Map<string, number>();
	private maintenanceTimer: ReturnType<typeof setTimeout> | null = null;

	constructor(ctx: DurableObjectState, env: EasyTierEnv) {
		super(ctx, env);
		this.doState = ctx;
		this.config = readServerConfig(env);
	}

	/**
	 * 解析服务端 X25519 身份;并发请求共享同一次初始化,失败后允许重试。
	 */
	private ensureIdentity(): Promise<void> {
		this.identityReady ??= this.initIdentity().catch((error: unknown) => {
			this.identityReady = null;
			throw error;
		});
		return this.identityReady;
	}

	/**
	 * 未配置 LOCAL_PRIVATE_KEY / LOCAL_PUBLIC_KEY 时生成 X25519 身份并持久化到
	 * DO storage。此前每次 DO 重新实例化都会生成全新临时密钥:客户端在首次
	 * Noise XX 握手后会记住服务端静态公钥,DO 被平台驱逐重启后公钥改变,
	 * 所有客户端持续报 "peer static pubkey mismatch" 且无法自动恢复。
	 * 持久化后 DO 重启复用同一身份,已接入客户端无需任何改动。
	 */
	private async initIdentity(): Promise<void> {
		let privateKey = this.config.localPrivateKey;
		let publicKey = this.config.localPublicKey;
		if (!privateKey || !publicKey) {
			const stored = await this.doState.storage.get<StoredIdentity>(IDENTITY_STORAGE_KEY);
			if (stored && this.isValidKeypair(stored.privateKey, stored.publicKey)) {
				privateKey = stored.privateKey;
				publicKey = stored.publicKey;
			} else {
				const generated = parseGeneratedKeypair(generate_keypair());
				privateKey = generated.privateKey;
				publicKey = generated.publicKey;
				await this.doState.storage.put(IDENTITY_STORAGE_KEY, {
					privateKey,
					publicKey,
				} satisfies StoredIdentity);
			}
		}
		if (!privateKey || !publicKey) {
			throw new Error("failed to resolve the secure-mode X25519 keypair");
		}
		this.localPrivateKey = privateKey;
		this.localPublicKey = publicKey;
		this.rpc = new EasyTierRpc(
			this.config.localPublicKeyBytes ?? decodeBase64Key(publicKey),
			this.config.hostname,
			SERVER_PEER_ID,
			this.config.disableRelayData,
		);
	}

	private isValidKeypair(privateKey: unknown, publicKey: unknown): boolean {
		if (typeof privateKey !== "string" || typeof publicKey !== "string") return false;
		try {
			decodeBase64Key(privateKey);
			decodeBase64Key(publicKey);
			return true;
		} catch {
			return false;
		}
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname !== "/") return new Response("Not found", { status: 404 });
		if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
			return new Response("Expected a WebSocket upgrade", { status: 426 });
		}
		// 身份解析涉及 DO storage 读写,必须在返回 101 之前完成,
		// 保证消息回调触发时 rpc / 密钥对已就绪。
		try {
			await this.ensureIdentity();
		} catch (error) {
			console.error("EasyTier secure-mode identity init failed", {
				error: errorMessage(error),
			});
			return new Response("Server secure-mode configuration is invalid", { status: 503 });
		}
		// 限流只针对"未完成握手"的连接:认证后的节点可能共享 NAT 出口 IP
		// (例如家里手机和电脑),按 IP 限制已认证连接会误伤正常节点。
		const ipKey = request.headers.get("CF-Connecting-IP") ?? UNKNOWN_IP;
		if (
			this.connections.size >= MAX_CONNECTIONS ||
			this.pendingHandshakes >= MAX_PENDING_HANDSHAKES ||
			(this.pendingHandshakesByIp.get(ipKey) ?? 0) >= this.config.maxPendingPerIp
		) {
			return new Response("EasyTier connection capacity exceeded", { status: 503 });
		}

		let secure: SecurePeer;
		try {
			secure = new SecurePeer(
				this.localPrivateKey,
				this.localPublicKey,
				SERVER_PEER_ID,
			);
		} catch (error) {
			console.error("EasyTier secure-mode key validation failed", {
				error: errorMessage(error),
			});
			return new Response("Server secure-mode configuration is invalid", { status: 503 });
		}

		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];
		server.binaryType = "arraybuffer";
		server.accept();

		const connection = createConnection(server, secure, ipKey, (expired) => {
			this.close(expired, 4408, "secure handshake timeout");
		});
		this.connections.set(server, connection);
		this.pendingHandshakes += 1;
		this.pendingHandshakesByIp.set(ipKey, (this.pendingHandshakesByIp.get(ipKey) ?? 0) + 1);
		this.scheduleMaintenance();
		server.addEventListener("message", (event) => {
			try {
				this.handleMessage(connection, event.data);
			} catch (error) {
				this.failConnection(connection, error);
			}
		});
		server.addEventListener("close", () => this.removeConnection(connection));
		server.addEventListener("error", () => this.removeConnection(connection));

		return new Response(null, { status: 101, webSocket: client });
	}

	private handleMessage(connection: Connection, data: string | ArrayBuffer): void {
		const frame = toUint8Array(data);
		if (frame.byteLength > this.config.maxFrameBytes) {
			throw new Error("EasyTier frame exceeds MAX_FRAME_BYTES");
		}
		const packet = parsePacket(frame);
		switch (connection.phase) {
			case "msg1":
				// 首包类型决定握手方式:HandShake(2) 走旧版明文握手,
				// NoiseHandshakeMsg1(13) 走 Noise XX 安全握手。
				if (packet.header.packetType === PacketType.Handshake) {
					this.handleLegacyHandshake(connection, frame, packet.header);
					return;
				}
				this.handleHandshakeMessage1(connection, frame, packet.header.packetType);
				return;
			case "msg3":
				this.handleHandshakeMessage3(connection, frame, packet.header.packetType);
				return;
			case "ready":
				this.handleReadyPacket(connection, frame, packet);
				return;
			case "closed":
				return;
		}
	}

	private handleHandshakeMessage1(
		connection: Connection,
		frame: Uint8Array,
		packetType: number,
	): void {
		if (packetType !== PacketType.NoiseHandshakeMsg1) {
			throw new Error("unexpected or out-of-order handshake packet");
		}
		if (this.config.connectionMode === "legacy") {
			throw new Error("CONNECTION_MODE=legacy rejects secure-mode handshakes");
		}
		const info = parseHandshakeInfo(connection.secure.read_msg1(frame));
		const room = this.config.rooms.get(info.networkName);
		if (room === undefined) {
			this.close(connection, 4403, "network is not configured");
			return;
		}
		connection.peerId = info.peerId;
		connection.networkName = info.networkName;
		connection.send(connection.secure.build_msg2(room.network_secret));
		connection.phase = "msg3";
	}

	/**
	 * 旧版(非安全模式)握手:对应上游 EasyTier 的 `PacketType::HandShake`。
	 * 客户端发送明文 `HandshakeRequest`(含 network_name 与 network_secret
	 * 摘要),服务端校验房间与摘要后回发自身的 `HandshakeRequest`。
	 * 该路径面向无法配置 secure mode 的客户端,由 CONNECTION_MODE 启用。
	 */
	private handleLegacyHandshake(
		connection: Connection,
		frame: Uint8Array,
		header: ReturnType<typeof parsePacket>["header"],
	): void {
		if (this.config.connectionMode === "secure") {
			throw new Error("CONNECTION_MODE=secure rejects legacy plaintext handshakes");
		}
		if (header.fromPeerId === SERVER_PEER_ID) {
			throw new Error("legacy handshake peer id conflicts with the relay peer id");
		}
		const info = parseLegacyHandshakeInfo(parse_legacy_handshake(frame));
		const room = this.config.rooms.get(info.networkName);
		if (room === undefined) {
			this.close(connection, 4403, "network is not configured");
			return;
		}
		const digestOk = verify_network_secret_digest(
			info.networkSecretDigest,
			info.networkName,
			room.network_secret,
		);
		if (!digestOk) {
			throw new Error("legacy handshake network-secret digest mismatch");
		}
		connection.peerId = info.peerId;
		connection.networkName = info.networkName;
		connection.mode = "legacy";
		connection.send(
			build_legacy_handshake_response(
				SERVER_PEER_ID,
				info.networkName,
				room.network_secret,
			),
		);
		this.registerConnection(connection);
		completeHandshake(connection);
		this.releaseHandshakeSlot(connection);
		this.broadcastRouteUpdate(connection.networkName);
	}

	private handleHandshakeMessage3(
		connection: Connection,
		frame: Uint8Array,
		packetType: number,
	): void {
		if (packetType !== PacketType.NoiseHandshakeMsg3) {
			throw new Error("expected NoiseHandshakeMsg3");
		}
		const auth = parseAuthenticationInfo(connection.secure.finish_msg3(frame));
		if (
			auth.peerId !== connection.peerId ||
			auth.networkName !== connection.networkName
		) {
			throw new Error("secure handshake identity mismatch");
		}
		connection.remotePublicKey = auth.remotePublicKey;
		this.registerConnection(connection);
		completeHandshake(connection);
		this.releaseHandshakeSlot(connection);
		this.broadcastRouteUpdate(connection.networkName);
	}

	/** 握手完成或未认证断开时,归还未认证连接配额。 */
	private releaseHandshakeSlot(connection: Connection): void {
		if (this.pendingHandshakes > 0) this.pendingHandshakes -= 1;
		const remaining = (this.pendingHandshakesByIp.get(connection.clientIp) ?? 1) - 1;
		if (remaining > 0) {
			this.pendingHandshakesByIp.set(connection.clientIp, remaining);
		} else {
			this.pendingHandshakesByIp.delete(connection.clientIp);
		}
	}

	private handleReadyPacket(
		connection: Connection,
		frame: Uint8Array,
		packet: ReturnType<typeof parsePacket>,
	): void {
		const { header } = packet;
		if (header.toPeerId !== SERVER_PEER_ID) {
			// DISABLE_RELAY_DATA=true:丢弃节点间数据面流量,仅保留控制面(信令)转发。
			// 对端已通过路由同步中的 avoid_relay_data 特性标志得知本中继不承载数据。
			if (this.config.disableRelayData && isRelayDataPacket(frame)) return;
			const target = this.findPeer(connection.networkName, header.toPeerId);
			if (!target || target.phase !== "ready") return;
			const forwarded = incrementForwardCounter(frame);
			try {
				target.send(forwarded);
			} catch (error) {
				console.warn("EasyTier forwarding target rejected", {
					networkName: target.networkName,
					peerId: target.peerId,
					error: errorMessage(error),
				});
				this.close(target, 1013, "outbound relay capacity exceeded");
			}
			return;
		}
		if (header.fromPeerId !== connection.peerId) {
			throw new Error("direct control packet source does not match the authenticated peer");
		}

		if (
			(header.packetType === PacketType.Ping || header.packetType === PacketType.Pong) &&
			(header.flags & ENCRYPTED_FLAG) !== 0
		) {
			throw new Error("EasyTier Ping and Pong packets must remain unencrypted");
		}
		if (header.packetType === PacketType.Ping) {
			connection.send(createPong(frame));
			return;
		}
		if (header.packetType === PacketType.Pong) return;
		if (header.packetType !== PacketType.RpcReq && header.packetType !== PacketType.RpcResp) {
			// 本节点没有本地 TUN；数据包和端到端中继握手只有发往其他节点时才有意义。
			return;
		}
		const encrypted = (header.flags & ENCRYPTED_FLAG) !== 0;
		let clearPacket: ReturnType<typeof parsePacket>;
		if (connection.mode === "legacy") {
			// legacy 连接没有会话密钥:直达 RPC 必须保持明文。
			if (encrypted) {
				throw new Error("legacy connections must not send encrypted direct RPC packets");
			}
			clearPacket = packet;
		} else {
			if (!encrypted) {
				throw new Error("secure_mode requires encrypted direct RPC packets");
			}
			const clear = connection.secure.decrypt_packet(frame);
			if (clear.byteLength === 0) return;
			clearPacket = parsePacket(clear);
		}
		if (header.packetType === PacketType.RpcReq) {
			const result = this.rpc.handleRequest(connection, clearPacket.payload);
			if (result === "route") this.broadcastRouteUpdate(connection.networkName, connection.peerId);
		} else {
			this.rpc.handleResponse(connection, clearPacket.payload);
		}
	}

	private registerConnection(connection: Connection): void {
		const replaced = this.rooms.set(connection);
		if (replaced && replaced !== connection) {
			this.close(replaced, 4000, "replaced by an authenticated reconnect");
		}
		this.rpc.addPeer(connection);
	}

	private removeConnection(connection: Connection): void {
		if (connection.phase === "closed") return;
		const wasReady = connection.phase === "ready";
		connection.phase = "closed";
		this.connections.delete(connection.socket);
		if (!wasReady) this.releaseHandshakeSlot(connection);
		if (this.connections.size === 0 && this.maintenanceTimer) {
			clearTimeout(this.maintenanceTimer);
			this.maintenanceTimer = null;
		}
		this.rooms.delete(connection);
		if (wasReady) {
			this.rpc.removePeer(connection);
			this.broadcastRouteUpdate(connection.networkName);
		}
		disposeConnection(connection);
	}

	private broadcastRouteUpdate(networkName: string, excludePeerId?: number): void {
		for (const peer of this.rooms.peers(networkName)) {
			if (peer.peerId === excludePeerId || peer.phase !== "ready") continue;
			try {
				this.rpc.sendRouteUpdate(peer, false);
			} catch (error) {
				console.error("route synchronization failed", {
					networkName: peer.networkName,
					peerId: peer.peerId,
					error: errorMessage(error),
				});
				this.close(peer, 1011, "route synchronization failed");
			}
		}
	}

	private findPeer(networkName: string, peerId: number): Connection | undefined {
		return this.rooms.get(networkName, peerId);
	}

	private scheduleMaintenance(): void {
		if (this.maintenanceTimer || this.connections.size === 0) return;
		this.maintenanceTimer = setTimeout(() => {
			this.maintenanceTimer = null;
			const now = Date.now();
			for (const failure of this.rpc.cleanExpired(now)) {
				console.error("route synchronization retry failed", {
					networkName: failure.peer.networkName,
					peerId: failure.peer.peerId,
					error: failure.error.message,
				});
				const connection = this.findPeer(failure.peer.networkName, failure.peer.peerId);
				if (connection) this.close(connection, 1011, "route synchronization retry failed");
			}
			for (const connection of this.connections.values()) {
				if (connection.phase !== "ready") continue;
				try {
					this.rpc.maintainPeer(connection, now);
				} catch (error) {
					console.error("route synchronization maintenance failed", {
						networkName: connection.networkName,
						peerId: connection.peerId,
						error: errorMessage(error),
					});
					this.close(connection, 1011, "route synchronization maintenance failed");
				}
			}
			this.scheduleMaintenance();
		}, 10_000);
	}

	private failConnection(connection: Connection, error: unknown): void {
		console.warn("EasyTier connection rejected", {
			networkName: connection.networkName || undefined,
			peerId: connection.peerId || undefined,
			error: errorMessage(error),
		});
		this.close(connection, 4401, "EasyTier authentication or protocol error");
	}

	private close(connection: Connection, code: number, reason: string): void {
		if (connection.phase === "closed") return;
		try {
			connection.socket.close(code, reason.slice(0, 120));
		} finally {
			this.removeConnection(connection);
		}
	}
}

function decodeBase64Key(value: string): Uint8Array {
	const binary = atob(value);
	const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
	if (decoded.byteLength !== 32) {
		throw new Error("generated public key must decode to exactly 32 bytes");
	}
	return decoded;
}
