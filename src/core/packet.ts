import { build_packet, inspect_packet, prepare_forward, prepare_pong } from "../wasm";
import { EASYTIER_HEADER_SIZE } from "./constants";

interface PacketHeader {
	fromPeerId: number;
	toPeerId: number;
	packetType: number;
	flags: number;
	forwardCounter: number;
	reserved: number;
	payloadLength: number;
}

export function parsePacket(bytes: Uint8Array): { header: PacketHeader; payload: Uint8Array } {
	const values = inspect_packet(bytes);
	const header: PacketHeader = {
		fromPeerId: values[0],
		toPeerId: values[1],
		packetType: values[2],
		flags: values[3],
		forwardCounter: values[4],
		reserved: values[5],
		payloadLength: values[6],
	};
	const payload = bytes.subarray(EASYTIER_HEADER_SIZE);
	return { header, payload };
}

export function createPacket(
	fromPeerId: number,
	toPeerId: number,
	packetType: number,
	payload: Uint8Array,
): Uint8Array {
	return build_packet(fromPeerId, toPeerId, packetType, payload);
}

export function incrementForwardCounter(frame: Uint8Array): Uint8Array {
	return prepare_forward(frame);
}

export function createPong(frame: Uint8Array): Uint8Array {
	return prepare_pong(frame);
}

export function toUint8Array(data: string | ArrayBuffer): Uint8Array {
	if (typeof data === "string") {
		throw new Error("EasyTier accepts binary WebSocket messages only");
	}
	return new Uint8Array(data);
}
