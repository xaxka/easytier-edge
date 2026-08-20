import { describe, expect, it } from "vitest";
import { PacketType } from "../src/core/constants";
import {
	createPacket,
	incrementForwardCounter,
	isRelayDataPacket,
	parsePacket,
} from "../src/core/packet";

describe("EasyTier packet framing", () => {
	it("uses the upstream 16-byte little-endian peer-manager header", () => {
		const frame = createPacket(0x10203040, 0x50607080, PacketType.RpcReq, new Uint8Array([1, 2, 3]));
		const { header, payload } = parsePacket(frame);
		expect(header).toMatchObject({
			fromPeerId: 0x10203040,
			toPeerId: 0x50607080,
			packetType: PacketType.RpcReq,
			payloadLength: 3,
		});
		expect([...payload]).toEqual([1, 2, 3]);
	});

	it("increments the forwarding counter without mutating the source", () => {
		const source = createPacket(1, 2, PacketType.Data, new Uint8Array([9]));
		const forwarded = incrementForwardCounter(source);
		expect(source[10]).toBe(1);
		expect(forwarded[10]).toBe(2);
	});

	it("rejects malformed plaintext lengths", () => {
		const frame = createPacket(1, 2, PacketType.Data, new Uint8Array([9]));
		new DataView(frame.buffer).setUint32(12, 99, true);
		expect(() => parsePacket(frame)).toThrow(/payload length/);
	});

	it("classifies relay data-plane packets like upstream disable_relay_data", () => {
		expect(isRelayDataPacket(createPacket(1, 2, PacketType.Data, new Uint8Array([9])))).toBe(
			true,
		);
		expect(isRelayDataPacket(createPacket(1, 2, PacketType.RpcReq, new Uint8Array([9])))).toBe(
			false,
		);
		expect(isRelayDataPacket(createPacket(1, 2, PacketType.Ping, new Uint8Array([9])))).toBe(
			false,
		);
	});
});
