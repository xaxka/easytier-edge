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

	it("defaults MAX_PENDING_PER_IP to 17 and accepts overrides", () => {
		expect(readServerConfig(env()).maxPendingPerIp).toBe(17);
		expect(readServerConfig(env({ MAX_PENDING_PER_IP: "" })).maxPendingPerIp).toBe(17);
		expect(readServerConfig(env({ MAX_PENDING_PER_IP: "4" })).maxPendingPerIp).toBe(4);
		expect(readServerConfig(env({ MAX_PENDING_PER_IP: "2048" })).maxPendingPerIp).toBe(2048);
		expect(() => readServerConfig(env({ MAX_PENDING_PER_IP: "0" }))).toThrow(
			/MAX_PENDING_PER_IP/,
		);
		expect(() => readServerConfig(env({ MAX_PENDING_PER_IP: "-1" }))).toThrow(
			/MAX_PENDING_PER_IP/,
		);
		expect(() => readServerConfig(env({ MAX_PENDING_PER_IP: "2.5" }))).toThrow(
			/MAX_PENDING_PER_IP/,
		);
		expect(() => readServerConfig(env({ MAX_PENDING_PER_IP: "2049" }))).toThrow(
			/MAX_PENDING_PER_IP/,
		);
	});

	it("parses DISABLE_RELAY_DATA as an optional boolean", () => {
		expect(readServerConfig(env()).disableRelayData).toBe(false);
		expect(readServerConfig(env({ DISABLE_RELAY_DATA: "true" })).disableRelayData).toBe(true);
		expect(readServerConfig(env({ DISABLE_RELAY_DATA: "1" })).disableRelayData).toBe(true);
		expect(readServerConfig(env({ DISABLE_RELAY_DATA: "false" })).disableRelayData).toBe(false);
		expect(() => readServerConfig(env({ DISABLE_RELAY_DATA: "maybe" }))).toThrow(
			/DISABLE_RELAY_DATA/,
		);
	});

	it("defaults CONNECTION_MODE to auto", () => {
		expect(readServerConfig(env()).connectionMode).toBe("auto");
		expect(readServerConfig(env({ CONNECTION_MODE: "" })).connectionMode).toBe("auto");
		expect(readServerConfig(env({ CONNECTION_MODE: undefined })).connectionMode).toBe("auto");
	});

	it("accepts legacy and auto connection modes case-insensitively", () => {
		expect(readServerConfig(env({ CONNECTION_MODE: "legacy" })).connectionMode).toBe("legacy");
		expect(readServerConfig(env({ CONNECTION_MODE: "AUTO" })).connectionMode).toBe("auto");
		expect(readServerConfig(env({ CONNECTION_MODE: " Secure " })).connectionMode).toBe("secure");
	});

	it("rejects unknown CONNECTION_MODE values", () => {
		expect(() => readServerConfig(env({ CONNECTION_MODE: "both" }))).toThrow(/CONNECTION_MODE/);
		expect(() => readServerConfig(env({ CONNECTION_MODE: "0" }))).toThrow(/CONNECTION_MODE/);
	});
});
