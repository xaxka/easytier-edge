import { describe, expect, it } from "vitest";
import { readServerConfig, type EasyTierEnv } from "../src/core/config";

const key = Buffer.alloc(32, 7).toString("base64");

function env(overrides: Partial<EasyTierEnv> = {}): EasyTierEnv {
	return {
		EASYTIER_SERVER: {} as DurableObjectNamespace,
		NETWORK_NAME: "office",
		NETWORK_SECRET: "office-secret",
		MAX_FRAME_BYTES: "1048576",
		...overrides,
	};
}

describe("readServerConfig", () => {
	it("loads the single network identity", () => {
		const config = readServerConfig(env());
		expect([...config.rooms.keys()]).toEqual(["office"]);
		expect(config.networkName).toBe("office");
		expect(config.networkSecret).toBe("office-secret");
		expect(config.rooms.get("office")?.network_secret).toBe("office-secret");
	});

	it("requires NETWORK_NAME and NETWORK_SECRET", () => {
		expect(() => readServerConfig(env({ NETWORK_NAME: "" }))).toThrow(/NETWORK_NAME/);
		expect(() => readServerConfig(env({ NETWORK_SECRET: "" }))).toThrow(/NETWORK_SECRET/);
	});

	it("omits server keys when they are not configured", () => {
		const config = readServerConfig(env());
		expect(config.localPrivateKey).toBeUndefined();
		expect(config.localPublicKey).toBeUndefined();
		expect(config.localPublicKeyBytes).toBeUndefined();
	});

	it("accepts a configured pinned keypair", () => {
		const config = readServerConfig(
			env({ LOCAL_PRIVATE_KEY: key, LOCAL_PUBLIC_KEY: key }),
		);
		expect(config.localPrivateKey).toBe(key);
		expect(config.localPublicKey).toBe(key);
		expect(config.localPublicKeyBytes?.byteLength).toBe(32);
	});

	it("rejects configuring only one key of the pair", () => {
		expect(() => readServerConfig(env({ LOCAL_PRIVATE_KEY: key }))).toThrow(/together/);
		expect(() => readServerConfig(env({ LOCAL_PUBLIC_KEY: key }))).toThrow(/together/);
	});

	it("rejects malformed 32-byte X25519 key material", () => {
		expect(() =>
			readServerConfig(
				env({ LOCAL_PRIVATE_KEY: key, LOCAL_PUBLIC_KEY: btoa("short") }),
			),
		).toThrow(/32 bytes/);
	});

	it("limits network names by UTF-8 byte length", () => {
		expect(() => readServerConfig(env({ NETWORK_NAME: "网".repeat(86) }))).toThrow(
			/255 bytes/,
		);
	});
});
