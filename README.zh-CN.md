# EasyTier-edge

[English](README.md) · [简体中文](README.zh-CN.md)

[![CI](https://github.com/xixka/easytier-edge/actions/workflows/ci.yml/badge.svg)](https://github.com/xixka/easytier-edge/actions/workflows/ci.yml)

**运行在 Cloudflare 边缘网络上的安全 EasyTier WebSocket 中继。**

Rust/WASM 负责 EasyTier 协议，TypeScript 只负责 Cloudflare 运行时适配，非休眠 Durable Object 提供连接和房间状态边界。

## 架构

```text
EasyTier peers
      │
      │  Noise XX over WSS
      ▼
Cloudflare Worker
      │  upgrade + health check
      ▼
Durable Object
      ├── TypeScript  · WebSocket 生命周期、房间注册、准入、背压
      └── Rust/WASM   · 帧处理、转发规则、Noise、AEAD、RPC、OSPF、PeerCenter
```

发往中继的报文经过认证、解密后交由 WASM 核心处理。端到端报文保持不透明，只会在所属的已认证网络内转发。

## 特性

- 单个 `wss://` 入口承载一个私有 EasyTier 网络(强制 private-mode 语义:仅接受相同网络身份的节点)
- Noise XX 握手与网络密码证明
- 服务端密钥可选:未配置时自动生成 X25519 身份并持久化到 Durable Object storage,重启后保持不变(对应官方 secure mode "同一信任域"场景)
- AES-GCM、ChaCha20-Poly1305 认证加密
- OSPF 路由同步与 PeerCenter 节点发现
- 链式接入:无法直连 Worker 的节点可经任一已认证节点(网关)接入;中继从网关的 OSPF 泛洪中学习其路由,并逐跳转发控制面帧。代发的路由条目按原始 protobuf 字节转播(新版客户端的未知字段不丢失),网关上报的链路(含网关—链式节点边)合并进全网拓扑。
- 通过转发 EasyTier RPC 协调客户端之间的 UDP/TCP 打洞
- 跨 WebSocket 重连共享 peer 级 `Create` / `Sync` / `Join` 会话
- 周期维护 OSPF session 并刷新路由版本
- 有界 RPC 分片、事务跟踪和防重放状态
- 中继链路具备帧大小、跳数和发送容量限制
- 可选 `DISABLE_RELAY_DATA=true`:仅保留控制面(信令),丢弃节点间数据面转发,并通过 `avoid_relay_data` 特性标志告知节点(对齐上游 EasyTier 的 `disable_relay_data`)
- 通过 `CONNECTION_MODE` 切换握手方式:`secure`(默认,仅 Noise XX 安全握手)或 `legacy`(EasyTier 2.6.4 旧版明文 `HandShake` 握手,凭网络密码摘要认证,面向无法配置 secure mode 的客户端)。两种模式不能混用,原因见[为什么两种模式不能混用](#为什么两种模式不能混用)。

## 部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/xixka/easytier-edge)

部署需要配置两个 Secret:

- `NETWORK_NAME`
- `NETWORK_SECRET`

服务端 X25519 密钥对(`LOCAL_PRIVATE_KEY` / `LOCAL_PUBLIC_KEY`)是可选的:不配置时会在首次使用时自动生成身份,持久化到 Durable Object storage 并跨重启保持稳定,节点接入无需任何密钥。若希望通过 `peer_public_key` 锁定服务端身份,可运行 `pnpm run keys` 生成并配置固定密钥。

## 本地开发

环境要求：

- Node.js 20+
- pnpm 11+
- Rust 1.95.0 与 `wasm32-unknown-unknown`

```bash
rustup target add wasm32-unknown-unknown
pnpm install
cp .dev.vars.example .dev.vars
pnpm run dev
```

配置 `.dev.vars`：

```dotenv
NETWORK_NAME=office
NETWORK_SECRET=replace-with-a-random-secret
EASYTIER_HOSTNAME=edge
```

## 配置

| 变量 | 必填 | 约束 |
| --- | --- | --- |
| `NETWORK_NAME` | 是 | 网络名称，非空且不超过 255 个 UTF-8 字节。 |
| `NETWORK_SECRET` | 是 | 网络密码，非空。所有节点必须一致。 |
| `LOCAL_PRIVATE_KEY` | 否 | Base64 编码的 32 字节 X25519 私钥。未配置时自动生成一次并持久化到 Durable Object storage。 |
| `LOCAL_PUBLIC_KEY` | 否 | 与私钥匹配的 Base64 编码 32 字节 X25519 公钥。与私钥必须成对配置。 |
| `EASYTIER_HOSTNAME` | 否 | 对外发布的 hostname，默认 `edge`，最大 255 个 UTF-8 字节。 |
| `DISABLE_RELAY_DATA` | 否 | 默认 `false`。设为 `true` 时仅转发控制面(路由同步、节点发现、打洞协调、Ping/Pong),丢弃节点间数据面转发,并在路由信息中发布 `avoid_relay_data`。链式接入不受影响:链式节点的控制面帧会转发到其网关,数据面走客户端间路径(p2p 直连或客户端间中继),不经过 Worker。 |
| `MAX_FRAME_BYTES` | 否 | 单帧上限，默认 1 MiB，允许范围为 1 KiB–16 MiB。 |
| `MAX_PENDING_PER_IP` | 否 | 同一出口 IP 并发未完成握手连接的上限，默认 `17`，允许范围 1–2048。仅限流握手阶段,不影响共享 NAT 出口已认证节点。 |
| `CONNECTION_MODE` | 否 | 握手方式选择器。`secure`(默认):仅接受 Noise XX 安全握手。`legacy`:仅接受 EasyTier 2.6.4 旧版明文 `HandShake` 握手,凭网络密码摘要认证,面向无法配置 secure mode 的客户端。legacy 模式下传输层不加密。两种模式不能在同一网络内混用,原因见[为什么两种模式不能混用](#为什么两种模式不能混用)。 |

通过 Wrangler 写入生产凭据：

```bash
pnpm exec wrangler secret put NETWORK_NAME
pnpm exec wrangler secret put NETWORK_SECRET
```

## 节点接入

节点无需配置任何密钥，`--secure-mode` 会自动生成临时 X25519 身份：

```bash
easytier-core \
  --network-name office \
  --network-secret 'replace-with-a-random-secret' \
  --secure-mode \
  --private-mode true \
  -p 'wss://<worker-domain>/'
```

服务端强制 private-mode 语义：只有 `network_name` 与 `network_secret` 均匹配且完成 `NetworkSecretConfirmed` 认证的节点才能接入，其他网络身份一律拒绝。

### 接入无法配置安全模式的客户端(`CONNECTION_MODE=legacy`)

部分客户端(旧版本、GUI 前端、嵌入式移植)无法配置 secure mode。将 `CONNECTION_MODE` 显式设为 `legacy`,中继将只接受明文 `HandShake` 握手,这类客户端无需 `--secure-mode` 即可接入:

```bash
easytier-core \
  --network-name office \
  --network-secret 'replace-with-a-random-secret' \
  -p 'wss://<worker-domain>/'
```

服务端按上游 EasyTier 2.6.4 的 `HandShake` 交换流程响应:双方通过交换网络密码摘要(SipHash 分片摘要,常数时间比较)证明网络身份后才允许接入。传输层保持明文(中继不加密流量),因此只要节点全部支持,请优先使用 `secure` 模式。

### 为什么两种模式不能混用

同一网络只能运行 `secure` 或 `legacy` 其中之一。上游 EasyTier secure 客户端经中继发送任何帧前都强制建立端到端 `Noise_IK` 会话(`relay_peer_map::send_msg` 强制 `ensure_session`),而 legacy 节点不上报静态公钥(`peer_ospf_route::new_updated_self` 在未开 secure mode 时 `noise_static_pubkey` 为空),会话握手必然失败("remote static pubkey not found"),混合节点对之间永远无法建立 p2p 直连。这是上游 EasyTier 协议层的限制。若需同时接入两类客户端,请部署两个网络(一个 `secure`、一个 `legacy`)。

### 链式接入(经其他节点接入)

无法直连 Worker 的节点(无出站 WSS、受限网络)可以经任一已认证节点——即其*网关*——接入:

```bash
# 网关 B:一个直连 Worker 的普通节点
easytier-core --network-name office --network-secret '...' --secure-mode \
  -p 'wss://<worker-domain>/'

# 链式节点 C:指向 B 上可达的监听协议(TCP/UDP/WireGuard)
easytier-core --network-name office --network-secret '...' --secure-mode \
  -p 'tcp://<B地址>:11010'
```

C 的路由信息经 B 的 OSPF 泛洪到达 Worker;Worker 将其作为第三方条目接受(绑定 C 的 Noise 公钥防止身份漂移),把 B—C 链路发布进全网拓扑,并把发往 C 的控制面帧经 B 转发。链式节点是完整成员:其他节点能学到它的路由、与其直接打洞建立 p2p 链路,打洞失败时也可经客户端间中继到达。

信任模型与限制:

- 网关必须是已认证成员(secure 握手或 legacy 摘要匹配)。任何已认证成员都可以为自己直连的节点代发路由;冒充中继、已直连节点或他人密钥的条目会被拒绝。
- 链式数据面不经过 Worker。`DISABLE_RELAY_DATA=true` 时由中继丢弃数据面帧来强制执行;路由信息中的 `avoid_relay_data` 标志告知节点在客户端之间直接路由数据(打洞 p2p 链路或客户端间中继)。若两个节点既打不出直连路径、又没有可用的公共客户端中继,则二者之间没有数据路径——这是 Worker 仅保留控制面的固有代价。
- 每个网络最多接受 4096 个链式节点;网关断开后,失去最后一个网关链路的链式节点会从路由表中移除。


## 工具链

| 命令 | 操作 |
| --- | --- |
| `pnpm run build:wasm` | 构建 `easytier-edge-wasm`。 |
| `pnpm run typecheck` | 检查 TypeScript。 |
| `pnpm run test` | 运行 Vitest。 |
| `pnpm run build` | 构建 WASM 并执行 Wrangler dry build。 |
| `pnpm run deploy` | 构建并部署 Worker。 |

## 运行约束

- WebSocket 入口：`GET /`
- 配置探针：`GET /healthz`
- 中继 peer ID：`10000001`
- 每个 Durable Object 最多同时保持 2048 条 WebSocket 连接
- Worker 不包含本地 TUN 接口，也不会创建 UDP 打洞 socket；它会中转控制 RPC，让客户端之间直接建立打洞链路。
- 会话和防重放状态保存在非休眠 Durable Object 中。
- Protobuf schema 与 EasyTier 2.6.4 的 `easytier/src/proto` 保持逐字一致。

## 许可证

LGPL-3.0。上游归属信息见 [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md)。
