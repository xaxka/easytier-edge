# AGENTS.md — AI 代理协作指南

## 项目简介

EasyTier-Edge 是运行在 Cloudflare Workers 边缘的 EasyTier WebSocket 中继（`wss://` 接入点）：私有 EasyTier 网络的节点经由它完成信令与数据中继，中继本身强制 private-mode 准入。本仓库是 fordes123/easytier-edge 的 fork。架构分工：Rust/WASM 负责 EasyTier 协议本体，TypeScript 只做 Cloudflare 运行时适配，非休眠 Durable Object 承载连接与房间状态。

## 技术栈与结构

- TypeScript 5.9（ESM）+ Cloudflare Workers（wrangler 4，`nodejs_compat`）；包管理 pnpm 11，测试 Vitest 4。
- Rust 1.95（edition 2024）经 wasm-pack 编译到 wasm32-unknown-unknown，crate 位于 `wasm/`（crate 名 easytier-edge-wasm，LGPL-3.0）。
- 目录职责：
  - `src/index.ts`：Worker 入口，路由 `GET /`（WebSocket 升级）与 `GET /healthz`（配置探针）。
  - `src/server.ts`：Durable Object `EasyTierServer`（非休眠、SQLite 存储），负责连接生命周期、房间注册、准入与背压。
  - `src/core/`：环境配置解析、协议常量、帧解析、RPC 封装。
  - `src/runtime/`：连接状态机（secure/legacy）、消息解析、房间注册表、错误处理。
  - `src/wasm/`：wasm-bindgen 胶水与类型声明（`pkg/` 为生成物，勿手改）。
  - `wasm/src/`：协议核心——`secure.rs`（Noise XX 握手与 AEAD）、`legacy.rs`（EasyTier 2.6.4 明文握手）、`packet.rs`（帧格式）、`route_state.rs`（OSPF 路由）、`rpc.rs`、`peer_center.rs`。
  - `protos/`：从 EasyTier 2.6.4 原样拷贝的 .proto（勿修改）。
  - `scripts/`：`build-wasm.mjs`（构建 WASM）、`generate-keypair.mjs`（生成 X25519 密钥对）。
  - `test/`：Vitest 单测（`*.spec.ts`）。

## 构建与 CI

CI 配置为 `.github/workflows/ci.yml`，其步骤仅作参考（本地禁止执行）：`pnpm install --frozen-lockfile` → 安装 Rust 1.95.0 + wasm32 target → `cargo test --manifest-path wasm/Cargo.toml` → `pnpm run build:wasm` → `pnpm run typecheck`（tsc --noEmit）→ `pnpm run test`（vitest run）。改动是否可用一律以该 CI 通过为准。

## 硬性工作规则

1. 禁止本地编译：不得在本地运行任何构建/编译/测试命令（`pnpm`、`wrangler`、`cargo`、`wasm-pack` 等均不允许）；改动是否可用以 GitHub CI 编译/测试通过为准。
2. 每完成一个改动立即 commit 并 push，确认成功后再进行下一项改动。
3. 所有提交使用 xaxka 身份（本 clone 已配置 `user.name=xaxka`、`user.email=73456104+xaxka@users.noreply.github.com`，不要改动这些配置）。
4. 任务结束后清理本地 clone（删除本地仓库目录）。

## 与上游 fork 的关系

- 同步上游 fordes123/easytier-edge 时，优先保留上游对协议核心的修复：`wasm/src/`、`src/core/`、`src/runtime/`、`protos/`。
- 严禁被上游覆盖或删除：本 `AGENTS.md`、`.github/workflows/ci.yml` 的既有结构、README 中指向本 fork 的徽章与 Deploy 按钮。
- `protos/` 必须与上游 EasyTier 2.6.4 保持逐字节一致，同步时不要手工编辑。
- `LICENSE`（LGPL-3.0）与 `THIRD_PARTY_NOTICES.md` 为上游署名文件，不要改动。

## 代码约定

- 注释与文档注释使用中文（TS 的 `/** */` 与 Rust 的 `//!` 均如此），关键常量注明来源或上游出处。
- 常量用 SCREAMING_SNAKE_CASE；TS 使用具名导出、接口不加 `I` 前缀、可变字段用显式 `null` 而非 undefined；Rust 遵循标准 rustfmt 风格。
- 格式化由 `.prettierrc`（printWidth 140、单引号、分号、Tab 缩进、LF）与 `.editorconfig`（Tab、LF；YAML 用空格）约束，改动须保持一致。
- 密码学相关代码（`secure.rs`、`legacy.rs`）要求常数时间比较、有界状态；不要随意引入新依赖或放松既有安全限制。

## 关键文档/敏感区

- 改握手/加密逻辑前必读 README.md 的 Architecture、Configuration 表与 "Why the two modes cannot be mixed"：`secure` 与 `legacy` 两种模式不可混用于同一网络。
- `wrangler.jsonc` 是部署配置：Durable Object 类名与 `migrations`（tag v1，SQLite）绑定存储；改类名需新增 migration，勿随意改动。
- `src/wasm/pkg/` 与 `worker-configuration.d.ts` 为生成物，不要手工编辑；类型变更走 `wrangler types`（同样仅在 CI 语境考虑）。
- 协议常量（帧头、包类型、SERVER_PEER_ID=10000001 等）须与上游 EasyTier 2.6.4 语义一致，改动前对照 `protos/` 与上游源码。
- `README.md` 与 `README.zh-CN.md` 成对维护，改文档时两份同步更新。
