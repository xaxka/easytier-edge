import { describe, expect, it } from "vitest";
import { readServerConfig, type EasyTierEnv } from "../src/core/config";

const key = Buffer.alloc(32, 7).toString("base64");

function env(overrides: Partial<EasyTierEnv> = {}): EasyTierEnv {
	return {
		EASYTIER_SERVER: {} as DurableObjectNamespace,
		EASYTIER_NETWORKS: JSON.stringify([
			{ network_name: "office", network_secret: "office-secret" },
			{ network_name: "lab", network_secret: "lab-secret" },
		]),
		LOCAL_PRIVATE_KEY: key,
		LOCAL_PUBLIC_KEY: key,
		MAX_FRAME_BYTES: "1048576",
		...overrides,
	};
}

describe("readServerConfig", () => {
	it("loads multiple isolated room definitions", () => {
		const config = readServerConfig(env());
		expect([...config.rooms.keys()]).toEqual(["office", "lab"]);
		expect(config.rooms.get("office")?.network_secret).toBe("office-secret");
	});

	it("requires both secure-mode keys", () => {
		expect(() => readServerConfig(env({ LOCAL_PRIVATE_KEY: "" }))).toThrow(/requires/);
		expect(() => readServerConfig(env({ LOCAL_PUBLIC_KEY: "" }))).toThrow(/requires/);
	});

	it("rejects duplicate network names", () => {
		expect(() =>
			readServerConfig(
				env({
					EASYTIER_NETWORKS: JSON.stringify([
						{ network_name: "same", network_secret: "one" },
						{ network_name: "same", network_secret: "two" },
					]),
				}),
			),
		).toThrow(/duplicate/);
	});

	it("limits network names by UTF-8 byte length", () => {
		expect(() =>
			readServerConfig(
				env({
					EASYTIER_NETWORKS: JSON.stringify([
						{ network_name: "网".repeat(86), network_secret: "secret" },
					]),
				}),
			),
		).toThrow(/255 bytes/);
	});

	it("rejects malformed 32-byte X25519 key material", () => {
		expect(() => readServerConfig(env({ LOCAL_PUBLIC_KEY: btoa("short") }))).toThrow(/32 bytes/);
	});
});
