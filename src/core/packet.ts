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
	const forwarded = frame.slice();
	forwarded[10] = counter + 1;
	return forwarded;
}

export function createPong(frame: Uint8Array): Uint8Array {
	if (frame.byteLength < EASYTIER_HEADER_SIZE || frame[8] !== PacketType.Ping) {
		throw new Error("only an EasyTier Ping packet can become Pong");
	}
	const pong = frame.slice();
	pong[8] = PacketType.Pong;
	return pong;
}

/**
 * 判断帧是否属于中继数据面(与上游 disable_relay_data 的分类一致):
 * Data/KCP/QUIC 数据包及 ForeignNetworkPacket(内层为数据或无法解析)。
 * 保留在 WASM 中实现:内层嵌套解析逻辑复杂且有 Rust 单测覆盖。
 */
export function isRelayDataPacket(frame: Uint8Array): boolean {
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
