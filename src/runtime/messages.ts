interface HandshakeInfo {
	peerId: number;
	networkName: string;
}

interface LegacyHandshakeInfo {
	peerId: number;
	networkName: string;
	networkSecretDigest: Uint8Array;
}

interface AuthenticationInfo {
	peerId: number;
	networkName: string;
	remotePublicKey: Uint8Array;
}

export interface GeneratedKeypair {
	privateKey: string;
	publicKey: string;
}

export function parseGeneratedKeypair(json: string): GeneratedKeypair {
	const value = parseObject(json, "generate_keypair result");
	return {
		privateKey: readString(value.private_key_base64, "private_key_base64"),
		publicKey: readString(value.public_key_base64, "public_key_base64"),
	};
}

export function parseHandshakeInfo(json: string): HandshakeInfo {
	const value = parseObject(json, "NoiseHandshakeMsg1 result");
	readString(value.client_encryption_algorithm, "client_encryption_algorithm");
	return {
		peerId: readPeerId(value.peer_id, "peer_id"),
		networkName: readString(value.network_name, "network_name"),
	};
}

export function parseLegacyHandshakeInfo(json: string): LegacyHandshakeInfo {
	const value = parseObject(json, "legacy Handshake result");
	return {
		peerId: readPeerId(value.peer_id, "peer_id"),
		networkName: readString(value.network_name, "network_name"),
		networkSecretDigest: decodeDigest(
			readString(value.network_secret_digest_base64, "network_secret_digest_base64"),
		),
	};
}

export function parseAuthenticationInfo(json: string): AuthenticationInfo {
	const value = parseObject(json, "NoiseHandshakeMsg3 result");
	if (value.auth_level !== "NetworkSecretConfirmed") {
		throw new Error("secure handshake did not confirm the network secret");
	}
	return {
		peerId: readPeerId(value.peer_id, "peer_id"),
		networkName: readString(value.network_name, "network_name"),
		remotePublicKey: decodePublicKey(
			readString(value.remote_public_key_base64, "remote_public_key_base64"),
		),
	};
}

function decodePublicKey(base64: string): Uint8Array {
	let key: Uint8Array;
	try {
		key = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
	} catch (error) {
		throw new Error("remote_public_key_base64 is not valid base64", { cause: error });
	}
	if (key.byteLength !== 32) {
		throw new Error("remote_public_key_base64 must decode to 32 bytes");
	}
	return key;
}

function decodeDigest(base64: string): Uint8Array {
	let digest: Uint8Array;
	try {
		digest = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
	} catch (error) {
		throw new Error("network_secret_digest_base64 is not valid base64", { cause: error });
	}
	if (digest.byteLength !== 32) {
		throw new Error("network_secret_digest_base64 must decode to 32 bytes");
	}
	return digest;
}

function parseObject(json: string, operation: string): Record<string, unknown> {
	let value: unknown;
	try {
		value = JSON.parse(json);
	} catch (error) {
		throw new Error(`${operation} is not valid JSON`, { cause: error });
	}
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Error(`${operation} must be a JSON object`);
	}
	return value as Record<string, unknown>;
}

function readPeerId(value: unknown, field: string): number {
	if (typeof value !== "number" || !Number.isInteger(value) || value <= 0 || value > 0xffffffff) {
		throw new Error(`${field} must be a non-zero u32 peer id`);
	}
	return value;
}

function readString(value: unknown, field: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new Error(`${field} must be a non-empty string`);
	}
	return value;
}
