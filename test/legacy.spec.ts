import { describe, expect, it } from "vitest";
import {
	build_legacy_handshake_response,
	parse_legacy_handshake,
	verify_network_secret_digest,
} from "../src/wasm";
import { ENCRYPTED_FLAG, EASYTIER_AEAD_TAIL_SIZE, PacketType, SERVER_PEER_ID } from "../src/core/constants";
import { createPacket, parsePacket } from "../src/core/packet";
import { parseLegacyHandshakeInfo } from "../src/runtime/messages";

// 与上游 EasyTier 2.6.4 peer_conn.rs 的常量保持一致。
const HANDSHAKE_MAGIC = 0xd1e1a5e1;
const HANDSHAKE_VERSION = 1;

/**
 * 参考摘要,由独立程序按上游 `tunnel::generate_digest_from_str`
 * (std DefaultHasher 分片循环)计算,与 wasm/src/legacy.rs 的
 * Rust 单测共用同一组参考向量,确保 TS/WASM 两层一致。
 */
const REFERENCE_DIGEST = hexToBytes(
	"e0550395e5208dc40b9cf65f66b87eea575a1844c833322e1a06b681c260e86b",
);

interface ClientHandshakeOptions {
	peerId: number;
	networkName: string;
	/** 传入 "office"/"secret123" 时填入参考摘要;其余场景显式指定摘要字节。 */
	networkSecretDigest: Uint8Array;
	features?: string[];
	magic?: number;
	version?: number;
	headerFromPeerId?: number;
}

/**
 * 模拟上游客户端的 legacy 握手帧(对应 `peer_conn.rs::do_handshake`):
 * 16 字节 peer-manager 头 + 明文 protobuf `HandshakeRequest`。
 */
function buildClientHandshake(options: ClientHandshakeOptions): Uint8Array {
	const payload = encodeHandshakeRequest({
		magic: options.magic ?? HANDSHAKE_MAGIC,
		myPeerId: options.peerId,
		version: options.version ?? HANDSHAKE_VERSION,
		features: options.features ?? [],
		networkName: options.networkName,
		networkSecretDigest: options.networkSecretDigest,
	});
	return createPacket(
		options.headerFromPeerId ?? options.peerId,
		0,
		PacketType.Handshake,
		payload,
	);
}

interface HandshakeRequestFields {
	magic: number;
	myPeerId: number;
	version: number;
	features: string[];
	networkName: string;
	networkSecretDigest: Uint8Array;
}

/** 手写 protobuf 编码,避免测试依赖生成的 TS protobuf 运行时。 */
function encodeHandshakeRequest(fields: HandshakeRequestFields): Uint8Array {
	const encoder = new TextEncoder();
	const bytes: number[] = [];
	bytes.push(...varintField(1, fields.magic));
	bytes.push(...varintField(2, fields.myPeerId));
	bytes.push(...varintField(3, fields.version));
	for (const feature of fields.features) {
		const encoded = encoder.encode(feature);
		bytes.push(...lengthDelimitedField(4, encoded));
	}
	bytes.push(...lengthDelimitedField(5, encoder.encode(fields.networkName)));
	bytes.push(...lengthDelimitedField(6, fields.networkSecretDigest));
	return Uint8Array.from(bytes);
}

function varint(value: number): number[] {
	const out: number[] = [];
	let remaining = value;
	while (remaining >= 0x80) {
		out.push((remaining % 0x80) | 0x80);
		remaining = Math.floor(remaining / 0x80);
	}
	out.push(remaining);
	return out;
}

function varintField(tag: number, value: number): number[] {
	return [((tag << 3) | 0) & 0xff, ...varint(value)];
}

function lengthDelimitedField(tag: number, value: Uint8Array): number[] {
	return [...varint(((tag << 3) | 2) >>> 0), ...varint(value.byteLength), ...value];
}

function hexToBytes(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i += 1) {
		out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

function parseClientHandshake(frame: Uint8Array) {
	return parseLegacyHandshakeInfo(parse_legacy_handshake(frame));
}

describe("legacy handshake protocol", () => {
	it("round-trips a client handshake through the server parser", () => {
		const frame = buildClientHandshake({
			peerId: 123,
			networkName: "office",
			networkSecretDigest: REFERENCE_DIGEST,
		});
		const { header } = parsePacket(frame);
		expect(header.packetType).toBe(PacketType.Handshake);
		expect(header.flags & ENCRYPTED_FLAG).toBe(0);

		const info = parseClientHandshake(frame);
		expect(info.peerId).toBe(123);
		expect(info.networkName).toBe("office");
		expect(info.networkSecretDigest).toEqual(REFERENCE_DIGEST);
	});

	it("keeps feature strings out of the security-critical fields", () => {
		const frame = buildClientHandshake({
			peerId: 777,
			networkName: "office",
			networkSecretDigest: REFERENCE_DIGEST,
			features: ["ipv4", "proxy"],
		});
		const info = parseClientHandshake(frame);
		expect(info.peerId).toBe(777);
		expect(info.networkSecretDigest).toEqual(REFERENCE_DIGEST);
	});

	it("accepts the upstream all-zero digest from unauthenticated clients", () => {
		const frame = buildClientHandshake({
			peerId: 123,
			networkName: "office",
			networkSecretDigest: new Uint8Array(32),
		});
		const info = parseClientHandshake(frame);
		expect(info.networkSecretDigest).toEqual(new Uint8Array(32));
		expect(verify_network_secret_digest(new Uint8Array(32), "office", "secret123")).toBe(false);
	});

	it("rejects frames that are not HandShake packets", () => {
		const payload = encodeHandshakeRequest({
			magic: HANDSHAKE_MAGIC,
			myPeerId: 123,
			version: HANDSHAKE_VERSION,
			features: [],
			networkName: "office",
			networkSecretDigest: REFERENCE_DIGEST,
		});
		const ping = createPacket(123, 0, PacketType.Ping, payload);
		expect(() => parse_legacy_handshake(ping)).toThrow(/HandShake/);
	});

	it("rejects frames carrying the encrypted flag", () => {
		const frame = buildClientHandshake({
			peerId: 123,
			networkName: "office",
			networkSecretDigest: REFERENCE_DIGEST,
		});
		const encrypted = new Uint8Array(frame.byteLength + EASYTIER_AEAD_TAIL_SIZE);
		encrypted.set(frame);
		encrypted[9] = ENCRYPTED_FLAG;
		expect(() => parse_legacy_handshake(encrypted)).toThrow(/encrypted/);
	});

	it("rejects a wrong magic or version", () => {
		expect(() =>
			parseClientHandshake(
				buildClientHandshake({
					peerId: 123,
					networkName: "office",
					networkSecretDigest: REFERENCE_DIGEST,
					magic: 0xdeadbeef,
				}),
			),
		).toThrow(/magic/);
		expect(() =>
			parseClientHandshake(
				buildClientHandshake({
					peerId: 123,
					networkName: "office",
					networkSecretDigest: REFERENCE_DIGEST,
					version: 2,
				}),
			),
		).toThrow(/version/);
	});

	it("rejects a peer id mismatch between header and payload", () => {
		expect(() =>
			parseClientHandshake(
				buildClientHandshake({
					peerId: 222,
					networkName: "office",
					networkSecretDigest: REFERENCE_DIGEST,
					headerFromPeerId: 111,
				}),
			),
		).toThrow(/mismatch/);
	});

	it("rejects a zero peer id", () => {
		expect(() =>
			parseClientHandshake(
				buildClientHandshake({
					peerId: 0,
					networkName: "office",
					networkSecretDigest: REFERENCE_DIGEST,
				}),
			),
		).toThrow(/zero/);
	});

	it("rejects malformed network names and digests", () => {
		expect(() =>
			parseClientHandshake(
				buildClientHandshake({ peerId: 123, networkName: "", networkSecretDigest: REFERENCE_DIGEST }),
			),
		).toThrow(/network_name/);
		expect(() =>
			parseClientHandshake(
				buildClientHandshake({
					peerId: 123,
					networkName: "x".repeat(256),
					networkSecretDigest: REFERENCE_DIGEST,
				}),
			),
		).toThrow(/network_name/);
		expect(() =>
			parseClientHandshake(
				buildClientHandshake({
					peerId: 123,
					networkName: "office",
					networkSecretDigest: REFERENCE_DIGEST.slice(0, 31),
				}),
			),
		).toThrow(/32 bytes/);
	});

	it("rejects payloads that are not valid protobuf", () => {
		const garbage = createPacket(123, 0, PacketType.Handshake, Uint8Array.of(0xff, 0xff, 0xff));
		expect(() => parse_legacy_handshake(garbage)).toThrow();
	});
});

describe("verify_network_secret_digest", () => {
	it("accepts the upstream reference digest", () => {
		expect(verify_network_secret_digest(REFERENCE_DIGEST, "office", "secret123")).toBe(true);
	});

	it("rejects wrong secrets, wrong network names, and wrong digests", () => {
		expect(verify_network_secret_digest(REFERENCE_DIGEST, "office", "secret124")).toBe(false);
		expect(verify_network_secret_digest(REFERENCE_DIGEST, "office2", "secret123")).toBe(false);
		const tampered = REFERENCE_DIGEST.slice();
		tampered[0] ^= 0x01;
		expect(verify_network_secret_digest(tampered, "office", "secret123")).toBe(false);
	});

	it("rejects digests of unexpected length without throwing", () => {
		expect(verify_network_secret_digest(REFERENCE_DIGEST.slice(0, 16), "office", "secret123")).toBe(
			false,
		);
	});

	it("requires a non-empty network name", () => {
		expect(() => verify_network_secret_digest(REFERENCE_DIGEST, "", "secret123")).toThrow(
			/network_name/,
		);
	});
});

describe("build_legacy_handshake_response", () => {
	it("produces a frame the client can parse back", () => {
		const response = build_legacy_handshake_response(
			SERVER_PEER_ID,
			"office",
			"secret123",
		);
		const { header } = parsePacket(response);
		expect(header.packetType).toBe(PacketType.Handshake);
		expect(header.fromPeerId).toBe(SERVER_PEER_ID);
		expect(header.toPeerId).toBe(0);
		expect(header.flags).toBe(0);
		expect(header.forwardCounter).toBe(1);

		// 客户端按同样的 HandshakeRequest 结构解析服务端响应。
		const parsed = parseClientHandshake(response);
		expect(parsed.peerId).toBe(SERVER_PEER_ID);
		expect(parsed.networkName).toBe("office");
		expect(parsed.networkSecretDigest).toEqual(REFERENCE_DIGEST);
	});

	it("only echoes the real digest for the matching network identity", () => {
		const response = build_legacy_handshake_response(
			SERVER_PEER_ID,
			"office",
			"secret123",
		);
		const parsed = parseClientHandshake(response);
		// 客户端将响应摘要与本地计算结果比对,不一致则断开。
		expect(verify_network_secret_digest(parsed.networkSecretDigest, "office", "secret123")).toBe(
			true,
		);
		expect(verify_network_secret_digest(parsed.networkSecretDigest, "office", "other")).toBe(
			false,
		);
	});

	it("rejects invalid arguments", () => {
		expect(() => build_legacy_handshake_response(0, "office", "secret123")).toThrow(/zero/);
		expect(() => build_legacy_handshake_response(SERVER_PEER_ID, "", "secret123")).toThrow(
			/network_name/,
		);
		expect(() => build_legacy_handshake_response(SERVER_PEER_ID, "office", "")).toThrow(
			/network_secret/,
		);
	});
});
