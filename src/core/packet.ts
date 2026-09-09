import { is_relay_data_packet } from "../wasm";
import {
	EASYTIER_AEAD_TAIL_SIZE,
	EASYTIER_HEADER_SIZE,
	ENCRYPTED_FLAG,
	MAX_FORWARD_HOPS,
	PacketType,
} from "./constants";

interface PacketHeader {
	fromPeerId: number;
	toPeerId: number;
	packetType: number;
	flags: number;
	forwardCounter: number;
	reserved: number;
	payloadLength: number;
}

/**
 * 解析 16 字节小端 peer-manager 头(与 wasm/src/packet.rs 语义一致)。
 * 纯 JS 实现避免每个包一次 WASM 边界往返及 Vec 分配。
 */
export function parsePacket(bytes: Uint8Array): { header: PacketHeader; payload: Uint8Array } {
	if (bytes.byteLength < EASYTIER_HEADER_SIZE) {
		throw new Error(
			`EasyTier packet header too short: ${bytes.byteLength} < ${EASYTIER_HEADER_SIZE}`,
		);
	}
	const flags = bytes[9];
	const payloadLength = readU32(bytes, 12);
	const actual = bytes.byteLength - EASYTIER_HEADER_SIZE;
	const expected =
		payloadLength + ((flags & ENCRYPTED_FLAG) === 0 ? 0 : EASYTIER_AEAD_TAIL_SIZE);
	if (actual !== expected) {
		throw new Error(`payload length mismatch: ${actual} != ${expected}`);
	}
	return {
		header: {
			fromPeerId: readU32(bytes, 0),
			toPeerId: readU32(bytes, 4),
			packetType: bytes[8],
			flags,
			forwardCounter: bytes[10],
			reserved: bytes[11],
			payloadLength,
		},
		payload: bytes.subarray(EASYTIER_HEADER_SIZE),
	};
}

/** 构造控制面帧,与 wasm build_packet 一致(flags=0, forward_counter=1)。 */
export function createPacket(
	fromPeerId: number,
	toPeerId: number,
	packetType: number,
	payload: Uint8Array,
): Uint8Array {
	if (payload.byteLength > 0xffff_ffff) {
		throw new Error("packet payload exceeds the EasyTier u32 length");
	}
	const packet = new Uint8Array(EASYTIER_HEADER_SIZE + payload.byteLength);
	writeU32(packet, 0, fromPeerId);
	writeU32(packet, 4, toPeerId);
	packet[8] = packetType;
	packet[9] = 0;
	packet[10] = 1;
	packet[11] = 0;
	writeU32(packet, 12, payload.byteLength);
	packet.set(payload, EASYTIER_HEADER_SIZE);
	return packet;
}

export function incrementForwardCounter(frame: Uint8Array): Uint8Array {
	if (frame.byteLength < EASYTIER_HEADER_SIZE) {
		throw new Error("EasyTier packet header too short");
	}
	const counter = frame[10];
	if (counter > MAX_FORWARD_HOPS) {
		throw new Error("EasyTier forwarding hop limit exceeded");
	}
	// 原地递增跳数,不做整帧复制:每条 WebSocket message 事件的
	// buffer 由运行时独立分配,转发路径独占该帧;调用方在转发前
	// 拿到的 payload 视图(subarray(16))不覆盖第 10 字节,不受
	// 影响。改 1 个字节却复制整个帧(最大 1MB)在数据面转发开启
	// 后会成为每包热点,故保留零复制语义。
	frame[10] = counter + 1;
	return frame;
}

export function createPong(frame: Uint8Array): Uint8Array {
	if (frame.byteLength < EASYTIER_HEADER_SIZE || frame[8] !== PacketType.Ping) {
		throw new Error("only an EasyTier Ping packet can become Pong");
	}
	const pong = frame.slice();
	pong[8] = PacketType.Pong;
	return pong;
}

const PACKET_TYPE_FOREIGN_NETWORK = 10;
/**
 * 数据面包类型,镜像 wasm/src/packet.rs 的 `is_data_plane_packet_type`
 * (Rust 侧单测覆盖同一张表,两处需同步修改):
 * Data(1) / KCP_SRC(11) / KCP_DST(12) / QUIC_SRC(16) / QUIC_DST(17) /
 * DATA_KCP_MODIFIED(18) / DATA_QUIC_MODIFIED(19)。
 */
const RELAY_DATA_PLANE_TYPES = new Set<number>([1, 11, 12, 16, 17, 18, 19]);

/**
 * 判断帧是否属于中继数据面(与上游 disable_relay_data 的分类一致):
 * Data/KCP/QUIC 数据包及 ForeignNetworkPacket(内层为数据或无法解析)。
 * 快路径在 JS 完成:帧头在 parsePacket 阶段已解析,非 ForeignNetwork
 * 类型直接查表,避免每个过境帧一次 WASM 边界往返(含字节复制)。
 * 仅 ForeignNetworkPacket 需要拆内层头,交给 WASM 的权威实现。
 */
export function isRelayDataPacket(frame: Uint8Array): boolean {
	if (frame.byteLength >= EASYTIER_HEADER_SIZE && frame[8] !== PACKET_TYPE_FOREIGN_NETWORK) {
		return RELAY_DATA_PLANE_TYPES.has(frame[8]);
	}
	return is_relay_data_packet(frame);
}

export function toUint8Array(data: string | ArrayBuffer): Uint8Array {
	if (typeof data === "string") {
		throw new Error("EasyTier accepts binary WebSocket messages only");
	}
	return new Uint8Array(data);
}

function readU32(bytes: Uint8Array, offset: number): number {
	return (
		(bytes[offset] |
			(bytes[offset + 1] << 8) |
			(bytes[offset + 2] << 16) |
			(bytes[offset + 3] << 24)) >>>
		0
	);
}

function writeU32(bytes: Uint8Array, offset: number, value: number): void {
	bytes[offset] = value & 0xff;
	bytes[offset + 1] = (value >>> 8) & 0xff;
	bytes[offset + 2] = (value >>> 16) & 0xff;
	bytes[offset + 3] = (value >>> 24) & 0xff;
}
