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
- Optional `DISABLE_RELAY_DATA=true`: keep the control plane (signaling) only, drop peer data-plane forwarding, and advertise the `avoid_relay_data` feature flag to peers (aligned with upstream EasyTier's `disable_relay_data`)
- Switchable handshake via `CONNECTION_MODE`: `auto` (default, accept either, selected by the first packet), `secure` (Noise XX only), or `legacy` (EasyTier 2.6.4 plaintext `HandShake` with network-secret digest matching, for clients that cannot configure secure mode)

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
| `DISABLE_RELAY_DATA` | No | Defaults to `false`. When `true`, only the control plane (route sync, discovery, hole-punch coordination, ping/pong) is forwarded; peer data-plane forwarding is dropped and `avoid_relay_data` is advertised in route info. |
| `MAX_FRAME_BYTES` | No | Frame limit; defaults to 1 MiB, allowed range 1 KiB–16 MiB. |
| `MAX_PENDING_PER_IP` | No | Per-IP cap on concurrent connections that have not finished the handshake; defaults to `17`, allowed range 1–2048. Only throttles handshakes, never authenticated peers behind shared NAT. |
| `CONNECTION_MODE` | No | Handshake selector. `auto` (default): accept either handshake, selected by the first packet. `secure`: accept only Noise XX secure handshakes. `legacy`: accept only the EasyTier 2.6.4 plaintext `HandShake` exchange authenticated by the network-secret digest, for clients that cannot configure secure mode. Legacy mode never encrypts the transport. |

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
  --private-mode true \
  -p 'wss://<worker-domain>/'
```

The relay enforces private-mode semantics: only peers whose `network_name` and `network_secret` both match and that complete `NetworkSecretConfirmed` authentication are admitted; any other network identity is rejected.

### Connecting clients without secure mode (default `auto`)

Some clients (older builds, GUI frontends, embedded ports) cannot configure secure mode. With the default `CONNECTION_MODE=auto` they connect without `--secure-mode` out of the box; set `legacy` to accept plaintext handshakes only:

```bash
easytier-core \
  --network-name office \
  --network-secret 'replace-with-a-random-secret' \
  -p 'wss://<worker-domain>/'
```

The relay answers the upstream EasyTier 2.6.4 `HandShake` exchange: both sides prove the network identity by exchanging the network-secret digest (SipHash-based, compared in constant time) before admission. The transport stays plaintext — traffic is not encrypted by the relay — so prefer `secure` mode whenever every peer supports it.

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
