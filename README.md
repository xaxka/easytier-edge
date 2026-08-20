# EasyTier-Edge

[English](README.md) · [简体中文](README.zh-CN.md)

[![CI](https://github.com/xixka/easytier-edge/actions/workflows/ci.yml/badge.svg)](https://github.com/xixka/easytier-edge/actions/workflows/ci.yml)

**A secure EasyTier WebSocket relay running at the Cloudflare edge.**

Rust/WASM owns the EasyTier protocol. TypeScript owns only the Cloudflare runtime adapter. A non-hibernating Durable Object provides the connection and room state boundary.

## Architecture

```text
EasyTier peers
      │
      │  Noise XX over WSS
      ▼
Cloudflare Worker
      │  upgrade + health check
      ▼
Durable Object
      ├── TypeScript  · WebSocket lifecycle, room registry, admission, backpressure
      └── Rust/WASM   · framing, forwarding rules, Noise, AEAD, RPC, OSPF, PeerCenter
```

Packets addressed to the relay are authenticated, decrypted, and processed by the WASM core. Peer-to-peer packets stay opaque and are forwarded only inside their authenticated network.

## Properties

- One private EasyTier network behind a `wss://` endpoint (private-mode semantics enforced: only peers with the same network identity are admitted)
- Noise XX authentication with network-secret proof
- Optional server keys: an ephemeral X25519 identity is generated at startup when none is configured (the official secure-mode "same trust domain" scenario)
- AES-GCM and ChaCha20-Poly1305 authenticated encryption
- OSPF route synchronization and PeerCenter discovery
- Client-to-client UDP/TCP hole-punch coordination through forwarded EasyTier RPC
- Peer-level `Create` / `Sync` / `Join` sessions shared across reconnecting WebSockets
- Periodic OSPF session maintenance and route-version refresh
- Bounded RPC fragmentation, transaction tracking, and anti-replay state
- Frame, hop, and outbound-capacity limits on the relay path
- No legacy plaintext mode

## Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/xixka/easytier-edge)

The deployment requires two secrets:

- `NETWORK_NAME`
- `NETWORK_SECRET`

The server X25519 keypair (`LOCAL_PRIVATE_KEY` / `LOCAL_PUBLIC_KEY`) is optional: without it an ephemeral identity is generated on each startup and peers need no keys at all. Run `pnpm run keys` only if you want a pinned identity that clients can lock onto via `peer_public_key`.

## Local development

Requirements:

- Node.js 20+
- pnpm 11+
- Rust 1.95.0 with `wasm32-unknown-unknown`

```bash
rustup target add wasm32-unknown-unknown
pnpm install
cp .dev.vars.example .dev.vars
pnpm run dev
```

Configure `.dev.vars`:

```dotenv
NETWORK_NAME=office
NETWORK_SECRET=replace-with-a-random-secret
EASYTIER_HOSTNAME=edge
```

## Configuration

| Variable | Required | Contract |
| --- | --- | --- |
| `NETWORK_NAME` | Yes | Network name; non-empty, at most 255 UTF-8 bytes. |
| `NETWORK_SECRET` | Yes | Network secret; non-empty. Must match on every peer. |
| `LOCAL_PRIVATE_KEY` | No | Base64-encoded 32-byte X25519 private key. An ephemeral key is generated when omitted. |
| `LOCAL_PUBLIC_KEY` | No | Matching Base64-encoded 32-byte X25519 public key. Must be set together with the private key. |
| `EASYTIER_HOSTNAME` | No | Advertised hostname; defaults to `edge`, maximum 255 UTF-8 bytes. |
| `MAX_FRAME_BYTES` | No | Frame limit; defaults to 1 MiB, allowed range 1 KiB–16 MiB. |

Set production credentials through Wrangler:

```bash
pnpm exec wrangler secret put NETWORK_NAME
pnpm exec wrangler secret put NETWORK_SECRET
```

## Connect a peer

Peers need no keys; `--secure-mode` generates an ephemeral X25519 identity automatically:

```bash
easytier-core \
  --network-name office \
  --network-secret 'replace-with-a-random-secret' \
  --secure-mode \
  --private-mode \
  -p 'wss://<worker-domain>/'
```

The relay enforces private-mode semantics: only peers whose `network_name` and `network_secret` both match and that complete `NetworkSecretConfirmed` authentication are admitted; any other network identity is rejected. Legacy plaintext and credential-only admission are intentionally rejected by this deployment model.

## Toolchain

| Command | Action |
| --- | --- |
| `pnpm run build:wasm` | Build `easytier-edge-wasm`. |
| `pnpm run typecheck` | Check TypeScript. |
| `pnpm run test` | Run Vitest. |
| `pnpm run build` | Build WASM and run a Wrangler dry build. |
| `pnpm run deploy` | Build and deploy the Worker. |

## Runtime contract

- WebSocket endpoint: `GET /`
- Configuration probe: `GET /healthz`
- Relay peer ID: `10000001`
- Maximum simultaneous WebSocket connections per Durable Object: 2048
- The Worker has no local TUN interface and opens no UDP hole-punch sockets; it relays the control RPC that lets clients punch paths directly between themselves.
- Session and anti-replay state live in a non-hibernating Durable Object.
- Protobuf schemas are copied verbatim from EasyTier 2.6.4 under `easytier/src/proto`.

## License

LGPL-3.0. See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md) for upstream attribution.
