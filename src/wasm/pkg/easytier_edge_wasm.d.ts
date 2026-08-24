/* tslint:disable */
/* eslint-disable */

export class SecurePeer {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * 为已明确配置的房间生成 EasyTier Noise 消息二。
     */
    build_msg2(network_secret: string): Uint8Array;
    /**
     * 使用 EasyTier 分代流量密钥解密节点直达服务器的数据包。
     * 节点间转发包必须绕过此方法并保持原始密文。
     */
    decrypt_packet(packet: Uint8Array): Uint8Array;
    /**
     * 加密服务器发往节点的控制包。Ping、Pong 和 Noise 帧由 TypeScript 直接发送。
     */
    encrypt_packet(packet: Uint8Array): Uint8Array;
    /**
     * 完成 Noise XX 交换并验证客户端对房间密钥的 HMAC 证明。
     * 连接在此步骤成功前不可参与路由。
     */
    finish_msg3(packet: Uint8Array): string;
    is_authenticated(): boolean;
    constructor(local_private_key_base64: string, local_public_key_base64: string, server_peer_id: number);
    /**
     * 解析 EasyTier Noise 消息一并返回连接请求的网络。
     * 网络密钥必须在此步骤之后由 TypeScript 房间白名单选择。
     */
    read_msg1(packet: Uint8Array): string;
}

export class WasmRpcCore {
    free(): void;
    [Symbol.dispose](): void;
    add_peer(network: string, peer_id: number, remote_public_key: Uint8Array): void;
    build_route_update(network: string, peer_id: number, server_session_id: bigint, force_full: boolean, now_ms: bigint): Uint8Array;
    clean_expired(now_ms: bigint): void;
    handle_request(network: string, authenticated_peer_id: number, payload: Uint8Array, now_ms: bigint): Uint8Array;
    handle_response(network: string, authenticated_peer_id: number, payload: Uint8Array, now_ms: bigint): boolean;
    /**
     * 查询到达目标节点的下一跳网关(链式接入)。
     * 返回 0 表示目标不可达;直连节点返回其自身。
     */
    get_next_hop(network: string, peer_id: number): number;
    /**
     * 恢复持久化的 peer_route_id(16 位十六进制字符串,宿主在 DO 启动时
     * 从 storage 注入,须早于 add_peer 调用)。
     */
    set_peer_route_id(network: string, route_id: string): void;
    /**
     * 读取(必要时生成)本中继在该网络的 peer_route_id,宿主负责把首次
     * 生成的值持久化到 DO storage,DO 重启后回注保持稳定。
     */
    get_peer_route_id(network: string): string;
    constructor(public_key: Uint8Array, hostname: string, server_peer_id: number);
    remove_peer(network: string, peer_id: number): void;
    /**
     * 设置 avoid_relay_data 特性标志并同步到已存在的所有网络分组。
     * 对应上游 EasyTier 的 disable_relay_data:控制面(RPC/路由/发现)保持在线,
     * 数据面转发在服务端被丢弃,同时告知节点不要把数据路由经过本中继。
     */
    set_avoid_relay_data(enabled: boolean): void;
}

/**
 * 构造服务端 legacy 握手响应帧并回给客户端。
 */
export function build_legacy_handshake_response(server_peer_id: number, network_name: string, network_secret: string): Uint8Array;

export function build_packet(from_peer_id: number, to_peer_id: number, packet_type: number, payload: Uint8Array): Uint8Array;

/**
 * 生成一对 X25519 密钥。
 * 未配置 LOCAL_PRIVATE_KEY / LOCAL_PUBLIC_KEY 时由服务端在首次使用时调用,
 * 生成结果由服务端持久化到 Durable Object storage,跨重启复用。
 * 与 EasyTier 官方"同一信任域"场景保持一致:握手仍为 Noise XX,
 * 身份认证完全依赖 network_secret 证明。
 */
export function generate_keypair(): string;

export function inspect_packet(bytes: Uint8Array): Uint32Array;

export function is_relay_data_packet(bytes: Uint8Array): boolean;

/**
 * 计算网络身份摘要(与上游 `generate_digest_from_str` 一致)。
 */
export function network_secret_digest(network_name: string, network_secret: string): Uint8Array;

/**
 * 解析客户端发来的 legacy 握手帧,返回
 * `{ peer_id, network_name, network_secret_digest_base64 }`。
 * 房间白名单与摘要匹配由 TypeScript 层结合配置完成。
 */
export function parse_legacy_handshake(packet: Uint8Array): string;

export function prepare_forward(bytes: Uint8Array): Uint8Array;

export function prepare_pong(bytes: Uint8Array): Uint8Array;

/**
 * 常数时间校验客户端摘要是否等于 `(network_name, network_secret)` 的摘要。
 */
export function verify_network_secret_digest(digest: Uint8Array, network_name: string, network_secret: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_securepeer_free: (a: number, b: number) => void;
    readonly __wbg_wasmrpccore_free: (a: number, b: number) => void;
    readonly build_legacy_handshake_response: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly build_packet: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly generate_keypair: (a: number) => void;
    readonly inspect_packet: (a: number, b: number, c: number) => void;
    readonly is_relay_data_packet: (a: number, b: number, c: number) => void;
    readonly network_secret_digest: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly parse_legacy_handshake: (a: number, b: number, c: number) => void;
    readonly prepare_forward: (a: number, b: number, c: number) => void;
    readonly prepare_pong: (a: number, b: number, c: number) => void;
    readonly securepeer_build_msg2: (a: number, b: number, c: number, d: number) => void;
    readonly securepeer_decrypt_packet: (a: number, b: number, c: number, d: number) => void;
    readonly securepeer_encrypt_packet: (a: number, b: number, c: number, d: number) => void;
    readonly securepeer_finish_msg3: (a: number, b: number, c: number, d: number) => void;
    readonly securepeer_is_authenticated: (a: number) => number;
    readonly securepeer_new: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly securepeer_read_msg1: (a: number, b: number, c: number, d: number) => void;
    readonly verify_network_secret_digest: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly wasmrpccore_add_peer: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly wasmrpccore_build_route_update: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number, h: bigint) => void;
    readonly wasmrpccore_clean_expired: (a: number, b: bigint) => void;
    readonly wasmrpccore_handle_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint) => void;
    readonly wasmrpccore_handle_response: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint) => void;
    readonly wasmrpccore_new: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly wasmrpccore_remove_peer: (a: number, b: number, c: number, d: number) => void;
    readonly wasmrpccore_set_avoid_relay_data: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export2: (a: number, b: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
