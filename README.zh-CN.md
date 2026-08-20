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
- 服务端密钥可选:未配置时自动生成临时 X25519 身份(对应官方 secure mode "同一信任域"场景)
- AES-GCM、ChaCha20-Poly1305 认证加密
- OSPF 路由同步与 PeerCenter 节点发现
- 通过转发 EasyTier RPC 协调客户端之间的 UDP/TCP 打洞
- 跨 WebSocket 重连共享 peer 级 `Create` / `Sync` / `Join` 会话
- 周期维护 OSPF session 并刷新路由版本
- 有界 RPC 分片、事务跟踪和防重放状态
- 中继链路具备帧大小、跳数和发送容量限制
- 可选 `DISABLE_RELAY_DATA=true`:仅保留控制面(信令),丢弃节点间数据面转发,并通过 `avoid_relay_data` 特性标志告知节点(对齐上游 EasyTier 的 `disable_relay_data`)
- 通过 `CONNECTION_MODE` 切换握手方式:`secure`(默认,仅 Noise XX 安全握手)、`legacy`(EasyTier 2.6.4 旧版明文 `HandShake` 握手,凭网络密码摘要认证,面向无法配置 secure mode 的客户端)或 `auto`(按首包类型自动二选一)

## 部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/xixka/easytier-edge)

部署需要配置两个 Secret:

- `NETWORK_NAME`
- `NETWORK_SECRET`

服务端 X25519 密钥对(`LOCAL_PRIVATE_KEY` / `LOCAL_PUBLIC_KEY`)是可选的:不配置时每次启动自动生成临时身份,节点接入无需任何密钥。若希望通过 `peer_public_key` 锁定服务端身份,可运行 `pnpm run keys` 生成并配置固定密钥。

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
| `LOCAL_PRIVATE_KEY` | 否 | Base64 编码的 32 字节 X25519 私钥。未配置时自动生成临时密钥。 |
| `LOCAL_PUBLIC_KEY` | 否 | 与私钥匹配的 Base64 编码 32 字节 X25519 公钥。与私钥必须成对配置。 |
| `EASYTIER_HOSTNAME` | 否 | 对外发布的 hostname，默认 `edge`，最大 255 个 UTF-8 字节。 |
| `DISABLE_RELAY_DATA` | 否 | 默认 `false`。设为 `true` 时仅转发控制面(路由同步、节点发现、打洞协调、Ping/Pong),丢弃节点间数据面转发,并在路由信息中发布 `avoid_relay_data`。 |
| `MAX_FRAME_BYTES` | 否 | 单帧上限，默认 1 MiB，允许范围为 1 KiB–16 MiB。 |
| `MAX_PENDING_PER_IP` | 否 | 同一出口 IP 并发未完成握手连接的上限，默认 `17`，允许范围 1–2048。仅限流握手阶段,不影响共享 NAT 出口已认证节点。 |
| `CONNECTION_MODE` | 否 | 握手方式选择器。`secure`(默认):仅接受 Noise XX 安全握手。`legacy`:仅接受 EasyTier 2.6.4 旧版明文 `HandShake` 握手,凭网络密码摘要认证,面向无法配置 secure mode 的客户端。`auto`:按首包类型自动接受两种握手。legacy 模式下传输层不加密。 |

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

### 接入无法配置安全模式的客户端(`CONNECTION_MODE=legacy` 或 `auto`)

部分客户端(旧版本、GUI 前端、嵌入式移植)无法配置 secure mode。将 `CONNECTION_MODE` 设为 `legacy`(仅明文握手)或 `auto`(两种握手均可),即可在不加 `--secure-mode` 的情况下接入:

```bash
easytier-core \
  --network-name office \
  --network-secret 'replace-with-a-random-secret' \
  -p 'wss://<worker-domain>/'
```

服务端按上游 EasyTier 2.6.4 的 `HandShake` 交换流程响应:双方通过交换网络密码摘要(SipHash 分片摘要,常数时间比较)证明网络身份后才允许接入。传输层保持明文(中继不加密流量),因此只要节点全部支持,请优先使用 `secure` 模式。

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
