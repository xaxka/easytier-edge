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

- 单个 `wss://` 入口承载多个相互隔离的 EasyTier 网络
- Noise XX 握手与网络密码证明
- AES-GCM、ChaCha20-Poly1305 认证加密
- OSPF 路由同步与 PeerCenter 节点发现
- 通过转发 EasyTier RPC 协调客户端之间的 UDP/TCP 打洞
- 跨 WebSocket 重连共享 peer 级 `Create` / `Sync` / `Join` 会话
- 周期维护 OSPF session 并刷新路由版本
- 有界 RPC 分片、事务跟踪和防重放状态
- 中继链路具备帧大小、跳数和发送容量限制
- 不支持旧版明文模式，不共享跨网络状态

## 部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/xixka/easytier-edge)

部署需要配置三个 Secret：

- `EASYTIER_NETWORKS`
- `LOCAL_PRIVATE_KEY`
- `LOCAL_PUBLIC_KEY`

部署前生成 X25519 服务端身份：

```bash
pnpm run keys
```

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
EASYTIER_NETWORKS=[{"network_name":"office","network_secret":"replace-with-a-random-secret"}]
LOCAL_PRIVATE_KEY=<base64-encoded-32-byte-private-key>
LOCAL_PUBLIC_KEY=<base64-encoded-32-byte-public-key>
EASYTIER_HOSTNAME=edge
```

## 配置

| 变量 | 必填 | 约束 |
| --- | --- | --- |
| `EASYTIER_NETWORKS` | 是 | 非空 JSON 数组，每项包含唯一的 `network_name` 和非空 `network_secret`。 |
| `LOCAL_PRIVATE_KEY` | 是 | Base64 编码的 32 字节 X25519 私钥。 |
| `LOCAL_PUBLIC_KEY` | 是 | 与私钥匹配的 Base64 编码 32 字节 X25519 公钥。 |
| `EASYTIER_HOSTNAME` | 否 | 对外发布的 hostname，默认 `edge`，最大 255 个 UTF-8 字节。 |
| `MAX_FRAME_BYTES` | 否 | 单帧上限，默认 1 MiB，允许范围为 1 KiB–16 MiB。 |

通过 Wrangler 写入生产凭据：

```bash
pnpm exec wrangler secret put EASYTIER_NETWORKS
pnpm exec wrangler secret put LOCAL_PRIVATE_KEY
pnpm exec wrangler secret put LOCAL_PUBLIC_KEY
```

## 节点接入

```bash
easytier-core \
  --network-name office \
  --network-secret 'replace-with-a-random-secret' \
  --secure-mode \
  --local-private-key '<client-private-key>' \
  --local-public-key '<client-public-key>' \
  -p 'wss://<worker-domain>/'
```

同一网络内的节点必须使用相同凭据。同一 Worker 上配置的不同网络不会共享路由、发现、RPC 或转发状态。

只有完成 `NetworkSecretConfirmed` 认证的节点才能接入。该部署模型会明确拒绝旧版明文模式和仅凭 credential 接入的节点。

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
