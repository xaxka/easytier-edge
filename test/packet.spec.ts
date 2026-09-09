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

	it("increments the forwarding counter in place without copying the frame", () => {
		const source = createPacket(1, 2, PacketType.Data, new Uint8Array([9]));
		const { payload } = parsePacket(source);
		const forwarded = incrementForwardCounter(source);
		expect(forwarded).toBe(source);
		expect(source[10]).toBe(2);
		expect(forwarded[10]).toBe(2);
		// 载荷视图(subarray(16))不覆盖头部第 10 字节,保持可读。
		expect([...payload]).toEqual([9]);
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
		// JS 快路径的数据面类型表:KCP/QUIC 及其 SrcModified 变体。
		// 类型值镜像 wasm/src/packet.rs 的 PACKET_TYPE_* 常量。
		for (const kcpOrQuic of [11, 12, 16, 17, 18, 19]) {
			expect(isRelayDataPacket(createPacket(1, 2, kcpOrQuic, new Uint8Array([9])))).toBe(
				true,
			);
		}
		// 握手/控制面类型不属于数据面。
		for (const control of [2, 5, 9, 13, 15, 20, 21]) {
			expect(isRelayDataPacket(createPacket(1, 2, control, new Uint8Array([9])))).toBe(
				false,
			);
		}
	});
});
