import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// EasyTierServer 继承 cloudflare:workers 的 DurableObject,vitest 环境没有该模块。
vi.mock("cloudflare:workers", () => ({
	DurableObject: class {
		constructor(_ctx: unknown, _env: unknown) {}
	},
}));

import { EasyTierServer } from "../src/server";
import { ENCRYPTED_FLAG, PacketType, SERVER_PEER_ID } from "../src/core/constants";
import { createPacket, parsePacket } from "../src/core/packet";
import { LegacyCipher, network_secret_digest } from "../src/wasm";
import type { EasyTierEnv } from "../src/core/config";

const NETWORK = "xaxka";
const SECRET = "et.xiaoyu";
const LEDE = 3092355464;
const WINDOWS = 3488605596;
const GHOST = 972326755;

/**
 * 单个 WebSocket 的一端。测试直接驱动服务端侧 socket:
 * - `receive(frame)` 模拟客户端发帧;
 * - `sent` 即客户端收到的服务端帧。
 */
class MockSocket {
	readyState = 1;
	binaryType = "arraybuffer";
	accepted = false;
	sent: Uint8Array[] = [];
	isClosed = false;
	private readonly listeners = new Map<string, Array<(event: unknown) => void>>();

	accept(): void {
		this.accepted = true;
	}

	addEventListener(type: string, listener: (event: unknown) => void): void {
		const list = this.listeners.get(type) ?? [];
		list.push(listener);
		this.listeners.set(type, list);
	}

	send(data: ArrayBuffer | Uint8Array): void {
		this.sent.push(data instanceof Uint8Array ? data : new Uint8Array(data));
	}

	close(code?: number, reason?: string): void {
		this.isClosed = true;
		this.readyState = 3;
		this.emit("close", { code, reason });
	}

	terminate(): void {
		this.emit("close", {});
	}

	receive(frame: Uint8Array): void {
		const copy = new ArrayBuffer(frame.byteLength);
		new Uint8Array(copy).set(frame);
		this.emit("message", { data: copy });
	}

	private emit(type: string, event: unknown): void {
		for (const listener of this.listeners.get(type) ?? []) listener(event);
	}
}

let lastPair: { "0": MockSocket; "1": MockSocket } | null = null;

class MockWebSocketPair {
	readonly "0": MockSocket;
	readonly "1": MockSocket;

	constructor() {
		this["0"] = new MockSocket();
		this["1"] = new MockSocket();
		lastPair = this;
	}
}

class MockResponse {
	readonly status: number;
	readonly webSocket: unknown;
	readonly body: string | null;

	constructor(
		body: string | null,
		init?: { status?: number; webSocket?: unknown; headers?: unknown },
	) {
		this.body = body;
		this.status = init?.status ?? 200;
		this.webSocket = init?.webSocket;
	}
}

class MockStorage {
	private readonly map = new Map<string, unknown>();

	async get<T>(key: string): Promise<T | undefined> {
		return this.map.get(key) as T | undefined;
	}

	async put(key: string, value: unknown): Promise<void> {
		this.map.set(key, value);
	}

	async delete(key: string): Promise<boolean> {
		return this.map.delete(key);
	}

	async list<T>(options?: { prefix?: string }): Promise<Map<string, T>> {
		const out = new Map<string, T>();
		const prefix = options?.prefix ?? "";
		for (const [key, value] of this.map) {
			if (key.startsWith(prefix)) out.set(key, value as T);
		}
		return out;
	}
}

class MockDurableObjectState {
	readonly storage = new MockStorage();
}

function buildEnv(): EasyTierEnv {
	return {
		EASYTIER_SERVER: {} as EasyTierEnv["EASYTIER_SERVER"],
		NETWORK_NAME: NETWORK,
		NETWORK_SECRET: SECRET,
		CONNECTION_MODE: "legacy",
		DISABLE_RELAY_DATA: "true",
	} as EasyTierEnv;
}

// ---------------------------------------------------------------------------
// 极简 protobuf 编解码(仅覆盖本测试需要的字段)。
// ---------------------------------------------------------------------------

const UTF8 = new TextEncoder();
const UTF8_DECODER = new TextDecoder();

function varint(value: number | bigint): number[] {
	const out: number[] = [];
	let remaining = typeof value === "bigint" ? value : BigInt(value);
	while (remaining >= 0x80n) {
		out.push(Number(remaining & 0x7fn) | 0x80);
		remaining >>= 7n;
	}
	out.push(Number(remaining));
	return out;
}

function varintField(tag: number, value: number | bigint): number[] {
	return [((tag << 3) | 0) & 0xff, ...varint(value)];
}

function boolField(tag: number, value: boolean): number[] {
	return varintField(tag, value ? 1 : 0);
}

function bytesField(tag: number, value: Uint8Array | number[]): number[] {
	const bytes = value instanceof Uint8Array ? Array.from(value) : value;
	return [...varint(((tag << 3) | 2) >>> 0), ...varint(bytes.length), ...bytes];
}

interface Field {
	readonly tag: number;
	readonly varint: bigint;
	readonly bytes: Uint8Array;
}

function decodeFields(message: Uint8Array): Field[] {
	const fields: Field[] = [];
	let offset = 0;
	while (offset < message.byteLength) {
		const [key, keyLength] = readVarint(message, offset);
		offset += keyLength;
		const tag = Number(key >> 3n);
		const wireType = Number(key & 7n);
		if (wireType === 0) {
			const [value, length] = readVarint(message, offset);
			offset += length;
			fields.push({ tag, varint: value, bytes: new Uint8Array() });
		} else if (wireType === 2) {
			const [length, lengthSize] = readVarint(message, offset);
			offset += lengthSize;
			const size = Number(length);
			fields.push({ tag, varint: 0n, bytes: message.subarray(offset, offset + size) });
			offset += size;
		} else {
			throw new Error(`unsupported wire type ${wireType}`);
		}
	}
	return fields;
}

function readVarint(bytes: Uint8Array, offset: number): [bigint, number] {
	let result = 0n;
	let shift = 0n;
	let length = 0;
	while (length < 10) {
		const byte = bytes[offset + length];
		result |= BigInt(byte & 0x7f) << shift;
		length += 1;
		if ((byte & 0x80) === 0) return [result, length];
		shift += 7n;
	}
	throw new Error("varint too long");
}

function field(fields: Field[], tag: number): Field | undefined {
	return fields.find((item) => item.tag === tag);
}

function u32(fields: Field[], tag: number): number {
	return Number(field(fields, tag)?.varint ?? 0);
}

function u64(fields: Field[], tag: number): bigint {
	return field(fields, tag)?.varint ?? 0n;
}

function subFields(fields: Field[], tag: number): Field[] {
	const value = field(fields, tag)?.bytes;
	return value ? decodeFields(value) : [];
}

function repeatedFields(fields: Field[], tag: number): Field[][] {
	return fields.filter((item) => item.tag === tag).map((item) => decodeFields(item.bytes));
}

// ---------------------------------------------------------------------------
// 帧与 RPC 信封构造。
// ---------------------------------------------------------------------------

interface PeerInfoInput {
	peerId: number;
	version: number;
	hostname: string;
}

interface ConnRowInput {
	peerId: number;
	version: number;
	connected: number[];
}

function encodePeerInfo(info: PeerInfoInput): number[] {
	const out: number[] = [];
	out.push(...varintField(1, info.peerId));
	out.push(...bytesField(6, UTF8.encode(info.hostname)));
	out.push(...varintField(9, info.version));
	out.push(...bytesField(10, UTF8.encode("2.6.4-test")));
	out.push(...varintField(13, 24));
	// feature_flag(field 11):support_conn_list_sync = true(field 5),
	// 使服务端推送走 ConnPeerList,与真实客户端行为一致。
	const featureFlag: number[] = [];
	featureFlag.push(...boolField(5, true));
	out.push(...bytesField(11, featureFlag));
	return out;
}

function encodeSyncRequest(options: {
	from: number;
	sessionId: number;
	items: PeerInfoInput[];
	rows: ConnRowInput[];
}): Uint8Array {
	const sync: number[] = [];
	sync.push(...varintField(1, options.from));
	sync.push(...varintField(2, options.sessionId));
	sync.push(...boolField(3, true));
	if (options.items.length > 0) {
		const infos: number[] = [];
		for (const item of options.items) {
			infos.push(...bytesField(1, encodePeerInfo(item)));
		}
		sync.push(...bytesField(4, infos));
	}
	if (options.rows.length > 0) {
		const rows: number[] = [];
		for (const row of options.rows) {
			const rowFields: number[] = [];
			rowFields.push(
				...bytesField(1, [...varintField(1, row.peerId), ...varintField(2, row.version)]),
			);
			for (const connected of row.connected) {
				rowFields.push(...varintField(2, connected));
			}
			rows.push(...bytesField(1, rowFields));
		}
		sync.push(...bytesField(7, rows));
	}
	return Uint8Array.from(sync);
}

function encodeRpcPacket(options: {
	from: number;
	to: number;
	transactionId: number | bigint;
	isRequest: boolean;
	body: Uint8Array;
}): Uint8Array {
	const descriptor: number[] = [];
	descriptor.push(...bytesField(1, UTF8.encode(NETWORK)));
	descriptor.push(...bytesField(2, UTF8.encode("peer_rpc.OspfRouteRpc")));
	descriptor.push(...bytesField(3, UTF8.encode("OspfRouteRpc")));
	descriptor.push(...varintField(4, 1));

	const packet: number[] = [];
	packet.push(...varintField(1, options.from));
	packet.push(...varintField(2, options.to));
	packet.push(...varintField(3, options.transactionId));
	packet.push(...bytesField(4, descriptor));
	packet.push(...bytesField(5, options.body));
	packet.push(...boolField(6, options.isRequest));
	packet.push(...varintField(7, 1));
	packet.push(...varintField(8, 0));
	return Uint8Array.from(packet);
}

// ---------------------------------------------------------------------------
// 客户端模拟器。
// ---------------------------------------------------------------------------

interface PushView {
	transactionId: bigint;
	peerInfos: Array<{ peerId: number; version: number }>;
	connRows: Array<{ peerId: number; connected: number[] }>;
}

class TestClient {
	readonly peerId: number;
	readonly socket: MockSocket;
	private readonly cipher: LegacyCipher;
	/** 模拟上游客户端 OSPF 会话:进程内稳定的 session id。 */
	readonly sessionId: number;
	private nextTransactionId = 1_000;
	readonly received: Uint8Array[] = [];
	readonly learnedPeers = new Map<number, number>();
	readonly learnedRows = new Map<number, Set<number>>();

	constructor(peerId: number, socket: MockSocket) {
		this.peerId = peerId;
		this.socket = socket;
		this.cipher = new LegacyCipher(SECRET);
		this.sessionId = peerId % 100_000 + 1;
	}

	handshake(): void {
		const payload: number[] = [];
		payload.push(...varintField(1, 0xd1e1a5e1));
		payload.push(...varintField(2, this.peerId));
		payload.push(...varintField(3, 1));
		payload.push(...bytesField(5, UTF8.encode(NETWORK)));
		payload.push(...bytesField(6, network_secret_digest(NETWORK, SECRET)));
		this.socket.receive(
			createPacket(this.peerId, 0, PacketType.Handshake, Uint8Array.from(payload)),
		);
	}

	sendSyncRequest(options: { items: PeerInfoInput[]; rows: ConnRowInput[] }): void {
		const sync = encodeSyncRequest({
			from: this.peerId,
			sessionId: this.sessionId,
			items: options.items,
			rows: options.rows,
		});
		const request: number[] = [];
		request.push(...bytesField(2, sync));
		request.push(...varintField(3, 3000));
		const rpc = encodeRpcPacket({
			from: this.peerId,
			to: SERVER_PEER_ID,
			transactionId: this.nextTransactionId,
			isRequest: true,
			body: Uint8Array.from(request),
		});
		this.socket.receive(createPacket(this.peerId, SERVER_PEER_ID, PacketType.RpcReq, rpc));
		this.nextTransactionId += 1;
	}

	/** 处理服务端新帧(吸收推送并回 ack),循环至队列清空。 */
	drain(): PushView[] {
		const pushes: PushView[] = [];
		for (;;) {
			const batch = this.socket.sent.splice(0);
			if (batch.length === 0) break;
			for (const frame of batch) {
				this.received.push(frame);
				const parsed = parsePacket(frame);
				if (parsed.header.packetType !== PacketType.RpcReq) continue;
				const clear = (parsed.header.flags & ENCRYPTED_FLAG) !== 0
					? this.cipher.decrypt_packet(frame)
					: frame;
				const clearParsed = parsePacket(clear);
				const push = this.parsePush(clearParsed.payload);
				if (!push) continue;
				pushes.push(push);
				this.absorb(push);
				const response: number[] = [];
				response.push(...boolField(1, true));
				response.push(...varintField(2, this.sessionId));
				const ack = encodeRpcPacket({
					from: this.peerId,
					to: SERVER_PEER_ID,
					transactionId: push.transactionId,
					isRequest: false,
					body: Uint8Array.from(response),
				});
				this.socket.receive(
					createPacket(this.peerId, SERVER_PEER_ID, PacketType.RpcResp, ack),
				);
			}
		}
		return pushes;
	}

	private absorb(push: PushView): void {
		for (const info of push.peerInfos) {
			if (info.peerId !== 0) this.learnedPeers.set(info.peerId, info.version);
		}
		for (const row of push.connRows) {
			this.learnedRows.set(row.peerId, new Set(row.connected));
		}
	}

	private parsePush(payload: Uint8Array): PushView | undefined {
		const packetFields = decodeFields(payload);
		const descriptor = subFields(packetFields, 4);
		const service = field(descriptor, 3)?.bytes;
		if (!service || UTF8_DECODER.decode(service) !== "OspfRouteRpc") return undefined;
		const body = subFields(packetFields, 5);
		const syncBytes = field(body, 2)?.bytes;
		if (!syncBytes) return undefined;
		const sync = decodeFields(syncBytes);
		const peerInfos = repeatedFields(subFields(sync, 4), 1).map((info) => ({
			peerId: u32(info, 1),
			version: u32(info, 9),
		}));
		const connRows = repeatedFields(subFields(sync, 7), 1).map((row) => {
			const peerIdVersion = subFields(row, 1);
			const connected = row
				.filter((item) => item.tag === 2)
				.map((item) => Number(item.varint));
			return { peerId: u32(peerIdVersion, 1), connected };
		});
		return { transactionId: u64(packetFields, 3), peerInfos, connRows };
	}

	/** 发出一帧经中继、端到端加密的 RPC(发往另一个客户端)。 */
	sendRelayedRpc(target: number, marker: number): void {
		const request: number[] = [];
		request.push(...bytesField(2, Uint8Array.from([marker])));
		const rpc = encodeRpcPacket({
			from: this.peerId,
			to: target,
			transactionId: this.nextTransactionId,
			isRequest: true,
			body: Uint8Array.from(request),
		});
		const clear = createPacket(this.peerId, target, PacketType.RpcReq, rpc);
		this.socket.receive(this.cipher.encrypt_packet(clear));
		this.nextTransactionId += 1;
	}

	/** 检查是否收到另一客户端发来的、端到端加密的中继帧。 */
	takeRelayedMarker(from: number): number | undefined {
		for (const frame of this.socket.sent.splice(0)) {
			this.received.push(frame);
			const parsed = parsePacket(frame);
			if (parsed.header.packetType !== PacketType.RpcReq) continue;
			if (parsed.header.toPeerId !== this.peerId || parsed.header.fromPeerId !== from) continue;
			const clear = this.cipher.decrypt_packet(frame);
			const inner = parsePacket(clear);
			// payload 是 RpcPacket protobuf:body(field 5)= RpcRequest,
			// 其 request(field 2) 载荷首字节即标记。
			const packetFields = decodeFields(inner.payload);
			const requestBody = field(subFields(packetFields, 5), 2)?.bytes;
			if (requestBody !== undefined && requestBody.byteLength >= 1) {
				return requestBody[0];
			}
		}
		return undefined;
	}
}

async function startServer(state: MockDurableObjectState): Promise<EasyTierServer> {
	vi.stubGlobal("WebSocketPair", MockWebSocketPair);
	vi.stubGlobal("Response", MockResponse);
	return new EasyTierServer(state as never, buildEnv());
}

async function connectClient(server: EasyTierServer, peerId: number): Promise<TestClient> {
	lastPair = null;
	await server.fetch(
		new Request("https://edge/", { headers: { Upgrade: "websocket" } }),
	);
	if (lastPair === null) throw new Error("fetch did not create a WebSocket pair");
	return new TestClient(peerId, lastPair["1"]);
}

async function advance(ms: number): Promise<void> {
	await vi.advanceTimersByTimeAsync(ms);
}

describe("server restart recovery (legacy clients)", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
		vi.unstubAllGlobals();
	});

	it("reconnected old node learns the new node and exchanges relayed RPCs", async () => {
		const state = new MockDurableObjectState();

		// === 阶段一:服务端实例 A,老节点 LEDE 在线同步。 ===
		const serverA = await startServer(state);
		const ledeBefore = await connectClient(serverA, LEDE);
		ledeBefore.handshake();
		ledeBefore.sendSyncRequest({
			items: [{ peerId: LEDE, version: 6, hostname: "lede" }],
			rows: [{ peerId: LEDE, version: 16, connected: [SERVER_PEER_ID] }],
		});
		ledeBefore.drain();

		// === 阶段二:服务端重启(全新 DO 实例,storage 保留)。 ===
		const serverB = await startServer(state);
		const lede = await connectClient(serverB, LEDE);
		lede.handshake();
		lede.sendSyncRequest({
			items: [{ peerId: LEDE, version: 6, hostname: "lede" }],
			rows: [{ peerId: LEDE, version: 16, connected: [SERVER_PEER_ID] }],
		});
		lede.drain();

		// === 阶段三:新重启的 Windows 节点接入同一实例。 ===
		const windows = await connectClient(serverB, WINDOWS);
		windows.handshake();
		windows.sendSyncRequest({
			items: [{ peerId: WINDOWS, version: 3, hostname: "DESKTOP" }],
			rows: [{ peerId: WINDOWS, version: 2, connected: [SERVER_PEER_ID] }],
		});
		windows.drain();

		// 推进维护周期,让两端路由同步收敛。
		await advance(11_000);
		lede.drain();
		windows.drain();
		await advance(11_000);
		lede.drain();
		windows.drain();

		// 断言 1:老节点 LEDE 学到了新节点 Windows 的 peer_info。
		expect(lede.learnedPeers.get(WINDOWS)).toBe(3);

		// 断言 2:Windows 发往 LEDE 的中继 RPC 能到达。
		windows.sendRelayedRpc(LEDE, 0x42);
		expect(lede.takeRelayedMarker(WINDOWS)).toBe(0x42);

		// 断言 3:LEDE 回给 Windows 的中继 RPC 也能到达。
		lede.sendRelayedRpc(WINDOWS, 0x43);
		expect(windows.takeRelayedMarker(LEDE)).toBe(0x43);
	});

	it("strips ghost neighbors from a direct peer's reported conn row", async () => {
		const state = new MockDurableObjectState();
		const server = await startServer(state);

		const lede = await connectClient(server, LEDE);
		lede.handshake();
		// LEDE 上报自身行,包含服务端不认识的幽灵邻居
		// (重启前与其他节点半开链路的残留)。
		lede.sendSyncRequest({
			items: [{ peerId: LEDE, version: 6, hostname: "lede" }],
			rows: [{ peerId: LEDE, version: 16, connected: [SERVER_PEER_ID, GHOST] }],
		});
		lede.drain();

		const windows = await connectClient(server, WINDOWS);
		windows.handshake();
		windows.sendSyncRequest({
			items: [{ peerId: WINDOWS, version: 3, hostname: "DESKTOP" }],
			rows: [{ peerId: WINDOWS, version: 2, connected: [SERVER_PEER_ID] }],
		});
		windows.drain();

		await advance(11_000);
		lede.drain();
		windows.drain();

		// Windows 吸收到的任何 conn 行都不得包含幽灵邻居。
		const ghostLeaked =
			[...windows.learnedRows.values()].some((row) => row.has(GHOST)) ||
			[...lede.learnedRows.values()].some((row) => row.has(GHOST));
		expect(ghostLeaked).toBe(false);
	});
});
