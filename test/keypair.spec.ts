import { describe, expect, it } from "vitest";
import { SecurePeer, generate_keypair } from "../src/wasm";
import { parseGeneratedKeypair } from "../src/runtime/messages";
import { SERVER_PEER_ID } from "../src/core/constants";

describe("generate_keypair smoke", () => {
	it("produces a pair accepted by SecurePeer", () => {
		const pair = parseGeneratedKeypair(generate_keypair());
		expect(pair.privateKey).not.toBe(pair.publicKey);
		const peer = new SecurePeer(pair.privateKey, pair.publicKey, SERVER_PEER_ID);
		expect(peer.is_authenticated()).toBe(false);
		peer.free();
	});

	it("generates a fresh pair each call", () => {
		const first = parseGeneratedKeypair(generate_keypair());
		const second = parseGeneratedKeypair(generate_keypair());
		expect(first.privateKey).not.toBe(second.privateKey);
	});
});
