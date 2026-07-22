export default function init(module: WebAssembly.Module): Promise<WebAssembly.Exports>;

export function inspect_packet(packet: Uint8Array): Uint32Array;
export function build_packet(
	fromPeerId: number,
	toPeerId: number,
	packetType: number,
	payload: Uint8Array,
): Uint8Array;
export function prepare_forward(packet: Uint8Array): Uint8Array;
export function prepare_pong(packet: Uint8Array): Uint8Array;

export class SecurePeer {
	constructor(privateKeyBase64: string, publicKeyBase64: string, serverPeerId: number);
	read_msg1(packet: Uint8Array): string;
	build_msg2(networkSecret: string): Uint8Array;
	finish_msg3(packet: Uint8Array): string;
	is_authenticated(): boolean;
	decrypt_packet(packet: Uint8Array): Uint8Array;
	encrypt_packet(packet: Uint8Array): Uint8Array;
	free(): void;
}

export class WasmRpcCore {
	constructor(publicKey: Uint8Array, hostname: string, serverPeerId: number);
	add_peer(network: string, peerId: number, remotePublicKey: Uint8Array): void;
	remove_peer(network: string, peerId: number): void;
	handle_request(network: string, peerId: number, payload: Uint8Array, nowMs: bigint): Uint8Array;
	handle_response(network: string, peerId: number, payload: Uint8Array, nowMs: bigint): boolean;
	build_route_update(
		network: string,
		peerId: number,
		serverSessionId: bigint,
		forceFull: boolean,
		nowMs: bigint,
	): Uint8Array;
	clean_expired(nowMs: bigint): void;
	free(): void;
}
