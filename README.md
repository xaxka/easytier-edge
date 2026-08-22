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
- Optional server keys: when none is configured, an X25519 identity is generated once and persisted in Durable Object storage, surviving restarts (the official secure-mode "same trust domain" scenario)
- AES-GCM and ChaCha20-Poly1305 authenticated encryption
- OSPF route synchronization and PeerCenter discovery
- Chained access: a peer that cannot reach the Worker directly may join through any authenticated peer (its gateway); the relay learns its route from the gateway's OSPF flood and forwards control-plane frames hop by hop. Relayed route entries are rebroadcast as the original protobuf bytes so fields from newer clients survive the trip, and gateway-reported links (including gateway-to-chained-peer edges) are merged into the published topology.
- Client-to-client UDP/TCP hole-punch coordination through forwarded EasyTier RPC
- Peer-level `Create` / `Sync` / `Join` sessions shared across reconnecting WebSockets
- Periodic OSPF session maintenance and route-version refresh
- Bounded RPC fragmentation, transaction tracking, and anti-replay state
- Frame, hop, and outbound-capacity limits on the relay path
- Optional `DISABLE_RELAY_DATA=true`: keep the control plane (signaling) only, drop peer data-plane forwarding, and advertise the `avoid_relay_data` feature flag to peers (aligned with upstream EasyTier's `disable_relay_data`)
- Switchable handshake via `CONNECTION_MODE`: `secure` (default, Noise XX only) or `legacy` (EasyTier 2.6.4 plaintext `HandShake` with network-secret digest matching, for clients that cannot configure secure mode). The two modes cannot be mixed — see [Why the two modes cannot be mixed](#why-the-two-modes-cannot-be-mixed).

## Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/xixka/easytier-edge)

The deployment requires two secrets:

- `NETWORK_NAME`
- `NETWORK_SECRET`

The server X25519 keypair (`LOCAL_PRIVATE_KEY` / `LOCAL_PUBLIC_KEY`) is optional: without it an identity is generated on first use, persisted in Durable Object storage, and kept stable across restarts, so peers need no keys at all. Run `pnpm run keys` only if you want a pinned identity that clients can lock onto via `peer_public_key`.

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
| `LOCAL_PRIVATE_KEY` | No | Base64-encoded 32-byte X25519 private key. When omitted, a key is generated once and persisted in Durable Object storage. |
| `LOCAL_PUBLIC_KEY` | No | Matching Base64-encoded 32-byte X25519 public key. Must be set together with the private key. |
| `EASYTIER_HOSTNAME` | No | Advertised hostname; defaults to `edge`, maximum 255 UTF-8 bytes. |
| `DISABLE_RELAY_DATA` | No | Defaults to `false`. When `true`, only the control plane (route sync, discovery, hole-punch coordination, ping/pong) is forwarded; peer data-plane forwarding is dropped and `avoid_relay_data` is advertised in route info. Chained access still works: control frames for chained peers are forwarded to their gateway, while data frames follow client-side paths (direct p2p or gateway relay between clients) and never transit the Worker. |
| `MAX_FRAME_BYTES` | No | Frame limit; defaults to 1 MiB, allowed range 1 KiB–16 MiB. |
| `MAX_PENDING_PER_IP` | No | Per-IP cap on concurrent connections that have not finished the handshake; defaults to `17`, allowed range 1–2048. Only throttles handshakes, never authenticated peers behind shared NAT. |
| `CONNECTION_MODE` | No | Handshake selector. `secure` (default): accept only Noise XX secure handshakes. `legacy`: accept only the EasyTier 2.6.4 plaintext `HandShake` exchange authenticated by the network-secret digest, for clients that cannot configure secure mode. Legacy mode never encrypts the transport. The two modes cannot be mixed in one network — see [Why the two modes cannot be mixed](#why-the-two-modes-cannot-be-mixed). |

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

### Connecting clients without secure mode (`CONNECTION_MODE=legacy`)

Some clients (older builds, GUI frontends, embedded ports) cannot configure secure mode. Set `CONNECTION_MODE=legacy` so the relay accepts plaintext `HandShake` exchanges only; such clients connect without `--secure-mode`:

```bash
easytier-core \
  --network-name office \
  --network-secret 'replace-with-a-random-secret' \
  -p 'wss://<worker-domain>/'
```

The relay answers the upstream EasyTier 2.6.4 `HandShake` exchange: both sides prove the network identity by exchanging the network-secret digest (SipHash-based, compared in constant time) before admission. The transport stays plaintext — traffic is not encrypted by the relay — so prefer `secure` mode whenever every peer supports it.

### Why the two modes cannot be mixed

A single network must run either `secure` or `legacy` — never both. Upstream EasyTier secure clients require an end-to-end `Noise_IK` session before sending any frame through a relay (`relay_peer_map::send_msg` forces `ensure_session`). Legacy peers do not publish a static public key (`peer_ospf_route::new_updated_self` leaves `noise_static_pubkey` empty when secure mode is off), so the session handshake always fails with "remote static pubkey not found," and mixed pairs can never establish direct p2p connections. This is an upstream EasyTier protocol constraint. If you need both client types, run two separate networks (one `secure`, one `legacy`).

### Chained access (joining through another peer)

A peer that cannot reach the Worker directly (no outbound WSS, restricted network) can join through any authenticated peer — its *gateway*:

```bash
# On the gateway B: a normal peer connected to the Worker
easytier-core --network-name office --network-secret '...' --secure-mode \
  -p 'wss://<worker-domain>/'

# On the chained peer C: point at B over a reachable protocol (TCP/UDP/WireGuard listener)
easytier-core --network-name office --network-secret '...' --secure-mode \
  -p 'tcp://<B-address>:11010'
```

C's route info reaches the Worker through B's OSPF flood; the Worker accepts it as a third-party entry (bound to C's Noise key to prevent identity drift), publishes the B–C link in the network topology, and forwards control-plane frames addressed to C through B. Chained peers are full members: other peers learn their routes, can hole-punch direct p2p paths with them, and can reach them through client-side relays when punching fails.

Trust and limits:

- The gateway must be an authenticated member (secure handshake or legacy digest). Any authenticated member may publish routes for peers it is directly connected to; entries impersonating the relay, an already-direct peer, or another member's key are rejected.
- Chained data never transits the Worker. With `DISABLE_RELAY_DATA=true` this is enforced by dropping data-plane frames; the `avoid_relay_data` flag published in route info tells clients to route data directly between themselves (punched p2p path or gateway relay between clients). If two peers can neither punch a direct path nor relay through a common client, they have no data path at all — that is the cost of keeping the Worker control-plane only.
- Each network accepts at most 4096 chained peers; when a gateway disconnects, chained peers that lost their last gateway link are removed from the route table.


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
