interface RoomConfig {
	network_secret: string;
}

export interface ServerConfig {
	rooms: ReadonlyMap<string, RoomConfig>;
	networkName: string;
	networkSecret: string;
	hostname: string;
	localPrivateKey?: string;
	localPublicKey?: string;
	localPublicKeyBytes?: Uint8Array;
	maxFrameBytes: number;
}

export interface EasyTierEnv {
	EASYTIER_SERVER: DurableObjectNamespace;
	NETWORK_NAME: string;
	NETWORK_SECRET: string;
	LOCAL_PRIVATE_KEY?: string;
	LOCAL_PUBLIC_KEY?: string;
	EASYTIER_HOSTNAME?: string;
	MAX_FRAME_BYTES?: string;
}

const UTF8_ENCODER = new TextEncoder();

export function readServerConfig(env: EasyTierEnv): ServerConfig {
	const networkName = requireText(env.NETWORK_NAME, "NETWORK_NAME");
	const networkNameBytes = UTF8_ENCODER.encode(networkName).byteLength;
	if (networkNameBytes === 0 || networkNameBytes > 255) {
		throw new Error("NETWORK_NAME must be a non-empty string of at most 255 bytes");
	}
	const networkSecret = requireText(env.NETWORK_SECRET, "NETWORK_SECRET");
	if (networkSecret.length === 0) {
		throw new Error("NETWORK_SECRET must be a non-empty string");
	}
	const rooms = new Map<string, RoomConfig>([
		[networkName, { network_secret: networkSecret }],
	]);

	// 密钥对是可选的:未配置时服务端会在启动时生成临时 X25519 密钥,
	// 对应 EasyTier 官方 secure mode "同一信任域" 场景,
	// 节点只需 --network-name / --network-secret / --secure-mode 即可接入。
	const hasPrivateKey = Boolean(env.LOCAL_PRIVATE_KEY);
	const hasPublicKey = Boolean(env.LOCAL_PUBLIC_KEY);
	if (hasPrivateKey !== hasPublicKey) {
		throw new Error(
			"LOCAL_PRIVATE_KEY and LOCAL_PUBLIC_KEY must be configured together or omitted",
		);
	}

	const maxFrameBytes = Number(env.MAX_FRAME_BYTES ?? 1_048_576);
	if (!Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 1024 || maxFrameBytes > 16_777_216) {
		throw new Error("MAX_FRAME_BYTES must be an integer between 1024 and 16777216");
	}
	const hostname = env.EASYTIER_HOSTNAME ?? "edge";
	if (
		typeof hostname !== "string" ||
		hostname.length === 0 ||
		UTF8_ENCODER.encode(hostname).byteLength > 255
	) {
		throw new Error("EASYTIER_HOSTNAME must be a non-empty string of at most 255 bytes");
	}

	if (!hasPrivateKey) {
		return {
			rooms,
			networkName,
			networkSecret,
			hostname,
			maxFrameBytes,
		};
	}

	const privateKey = env.LOCAL_PRIVATE_KEY as string;
	const publicKey = env.LOCAL_PUBLIC_KEY as string;
	const publicBytes = decodeBase64Key(publicKey, "LOCAL_PUBLIC_KEY");
	decodeBase64Key(privateKey, "LOCAL_PRIVATE_KEY");

	return {
		rooms,
		networkName,
		networkSecret,
		hostname,
		localPrivateKey: privateKey,
		localPublicKey: publicKey,
		localPublicKeyBytes: publicBytes,
		maxFrameBytes,
	};
}

function requireText(value: string | undefined, name: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new Error(`${name} is required`);
	}
	return value;
}

function decodeBase64Key(value: string, name: string): Uint8Array {
	let decoded: Uint8Array;
	try {
		const binary = atob(value);
		decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
	} catch {
		throw new Error(`${name} must be valid base64`);
	}
	if (decoded.byteLength !== 32) {
		throw new Error(`${name} must decode to exactly 32 bytes`);
	}
	return decoded;
}
