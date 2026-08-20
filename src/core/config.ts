interface RoomConfig {
	network_secret: string;
}

/**
 * 握手方式:
 * - `secure`: 仅接受 Noise XX 安全握手(默认,与旧版行为一致)。
 * - `legacy`: 仅接受旧版 Handshake 握手,面向无法配置 secure mode 的客户端。
 * - `auto`: 按首包类型自动选择两种握手之一。
 */
export type ConnectionMode = "secure" | "legacy" | "auto";

export interface ServerConfig {
	rooms: ReadonlyMap<string, RoomConfig>;
	networkName: string;
	networkSecret: string;
	hostname: string;
	localPrivateKey?: string;
	localPublicKey?: string;
	localPublicKeyBytes?: Uint8Array;
	disableRelayData: boolean;
	maxFrameBytes: number;
	maxPendingPerIp: number;
	connectionMode: ConnectionMode;
}

export interface EasyTierEnv {
	EASYTIER_SERVER: DurableObjectNamespace;
	NETWORK_NAME: string;
	NETWORK_SECRET: string;
	LOCAL_PRIVATE_KEY?: string;
	LOCAL_PUBLIC_KEY?: string;
	DISABLE_RELAY_DATA?: string;
	EASYTIER_HOSTNAME?: string;
	MAX_FRAME_BYTES?: string;
	MAX_PENDING_PER_IP?: string;
	CONNECTION_MODE?: string;
}

const UTF8_ENCODER = new TextEncoder();
const DEFAULT_MAX_PENDING_PER_IP = 17;

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
	// 同一出口 IP 并发未认证(Noise 握手未完成)连接的上限,
	// 只作用于握手前,不影响完成认证后的长期连接。
	const maxPendingPerIp = parsePositiveInt(
		env.MAX_PENDING_PER_IP,
		"MAX_PENDING_PER_IP",
		DEFAULT_MAX_PENDING_PER_IP,
	);
	// DISABLE_RELAY_DATA=true 时只保留控制面(信令),丢弃节点间数据面转发,
	// 与上游 EasyTier 的 disable_relay_data / avoid_relay_data 语义一致。
	const disableRelayData = parseBoolean(env.DISABLE_RELAY_DATA, "DISABLE_RELAY_DATA");
	// CONNECTION_MODE 切换握手方式:secure(默认)/ legacy / auto。
	// legacy 模式面向无法配置 secure mode 的客户端,传输层不加密,
	// 身份认证依赖 network_secret 摘要匹配。
	const connectionMode = parseConnectionMode(env.CONNECTION_MODE);
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
			disableRelayData,
			maxFrameBytes,
			maxPendingPerIp,
			connectionMode,
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
		disableRelayData,
		maxFrameBytes,
		maxPendingPerIp,
		connectionMode,
	};
}

function parseConnectionMode(value: string | undefined): ConnectionMode {
	if (value === undefined || value === "") return "secure";
	const normalized = value.trim().toLowerCase();
	if (normalized === "secure" || normalized === "legacy" || normalized === "auto") {
		return normalized;
	}
	throw new Error("CONNECTION_MODE must be one of: secure, legacy, auto");
}

function parsePositiveInt(
	value: string | undefined,
	name: string,
	fallback: number,
): number {
	if (value === undefined || value === "") return fallback;
	const parsed = Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 2_048) {
		throw new Error(`${name} must be an integer between 1 and 2048`);
	}
	return parsed;
}

function parseBoolean(value: string | undefined, name: string): boolean {
	if (value === undefined || value === "") return false;
	const normalized = value.trim().toLowerCase();
	if (["true", "1", "yes", "on"].includes(normalized)) return true;
	if (["false", "0", "no", "off"].includes(normalized)) return false;
	throw new Error(`${name} must be a boolean (true/false)`);
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
