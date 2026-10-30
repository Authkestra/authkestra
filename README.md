<picture>
  <source media="(prefers-color-scheme: dark)" srcset="design/logo/mark-on-dark.svg">
  <img src="design/logo/mark-on-light.svg" alt="Authkestra" width="56" height="56">
</picture>

# Authkestra

[![CI](https://github.com/marcjazz/authkestra/actions/workflows/ci.yml/badge.svg)](https://github.com/marcjazz/authkestra/actions)
[![Coverage](https://codecov.io/gh/marcjazz/authkestra/branch/main/graph/badge.svg)](https://codecov.io/gh/marcjazz/authkestra)
[![Crates.io](https://img.shields.io/crates/v/authkestra.svg)](https://crates.io/crates/authkestra)
[![Docs](https://docs.rs/authkestra/badge.svg)](https://docs.rs/authkestra)

**The Compile-Time Safe Identity & AI Agent Authorization Engine for Rust**

`authkestra` is a modular, framework-agnostic authentication and authorization orchestration system designed to be idiomatic to Rust, emphasizing **explicit control flow, strong typing, and composability** over dynamic middleware strategies common in other ecosystems. It unifies enterprise-grade identity (OAuth 2.1, OpenID Connect Provider/Client, Passkeys/WebAuthn, TOTP, Passwordless, DPoP, SD-JWT, SSF/CAEP) with autonomous AI agent security via the Model Context Protocol (MCP).

## 📦 Getting Started

The easiest way to use Authkestra is via the `authkestra` facade crate. It re-exports all sub-crates behind feature flags, allowing you to manage your authentication stack from a single dependency.

Add this to your `Cargo.toml`:

```toml
[dependencies]
# Use the facade with the features you need
authkestra = { version = "0.13", features = ["axum", "github"] }
```

For advanced users, individual crates are still available and can be used independently if preferred.

### 🔐 TLS backend

Authkestra talks to identity providers over HTTPS, so it needs a TLS backend. It
is selected by a feature flag rather than by `reqwest`'s defaults, so you can
choose the crypto provider yourself:

| Feature | Backend | Notes |
| --- | --- | --- |
| `rustls-aws-lc-rs` | rustls + [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) | **Default.** Compiles C and assembly, so it needs a C toolchain. |
| `rustls-no-provider` | rustls, provider chosen by you | Pure-Rust builds (`ring`), `*-unknown-linux-musl`, `cargo-deny` policies that ban `aws-lc-rs`. |

The default keeps the historical behaviour, so no change is needed unless you
want to get off `aws-lc-rs`. To do that, turn the default off and install a
provider yourself:

```toml
[dependencies]
authkestra = { version = "0.13", default-features = false, features = ["axum", "github", "rustls-no-provider"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12", "logging"] }
```

```rust,ignore
// Must run before any Authkestra call that builds an HTTP client,
// otherwise reqwest panics at client construction.
rustls::crypto::ring::default_provider()
    .install_default()
    .expect("failed to install rustls crypto provider");
```

Every Authkestra crate that speaks HTTPS exposes the same two features and
forwards them to `authkestra-engine`. Cargo features are additive, so if any
crate in your graph still enables `rustls-aws-lc-rs`, `aws-lc-rs` comes back - 
check with `cargo tree -i aws-lc-rs -e features`.

## 🚀 Features

- **Modular & Unified Core**: Following our RFC-001 architecture, core concerns are unified in `authkestra-engine` while adapters like `authkestra-axum` and `authkestra-actix` provide seamless framework integrations.
- **Stateless OAuth**: OAuth `state` and `nonce` are stored securely in encrypted cookies - never in your database - keeping your architecture clean and horizontally scalable.
- **Performant OIDC Discovery**: OIDC discovery documents are cached via background `tokio::spawn` tasks, completely eliminating per-request latency for fetching keys.
- **Database Agnostic**: Authkestra never enforces schemas. All data access is strictly defined via traits (`KvStore`, `SessionStore`, `CredentialStore`, and `authkestra-op`'s `OpStore`), allowing you to use any database or ORM. There is deliberately no user/account table and no `UserStore` trait -  your application owns that data (see `docs/book/ch02-core-engine-and-identity.md`).
- **Flexible Chaining**: Chain multiple authentication strategies (Token, Session, Basic, Custom) seamlessly.
- **OpenID Connect Provider (OP)**: Build your own identity provider and authorization server using `authkestra-op`.
- **Session Management**: Built-in support for in-memory, Redis, and SQL via `sqlx`.
- **Passwordless-native authentication**: passkeys (WebAuthn), TOTP, **magic links**, **email/SMS one-time codes** and **recovery codes** -  the last three added in 0.13. Recovery codes are a factor-agnostic look-up secret authenticator (NIST SP 800-63B §5.1.2), not TOTP-specific backup codes, so they work for an account that never enrolled TOTP.
- **Re-proof gating**: enrolling a second factor demands a *fresh* proof of identity, not merely a live session (`ReproofRequirement`). Method-agnostic by design -  the framework owns no password to re-prompt for, and an account that has only a passkey should not be locked out of enrolment.
- **SD-JWT (Selective Disclosure)**: Issue a single JWT carrying selectively disclosable claims (`draft-ietf-oauth-selective-disclosure-jwt`); the holder decides, per presentation, which claims to reveal to each verifier.
- **AI Agent & MCP Tool Security**: Built-in guard for Model Context Protocol (MCP) servers via `authkestra-mcp`. Enforce 3-tier access control (`Public`, `Scoped`, `HumanApproved`), RFC 8785 JSON Canonicalization Scheme (JCS) cryptographic parameter binding, Passkey/WebAuthn human-in-the-loop (HITL) step-up approval, single-use `AtomicConsume` execution proofs, and zero-trust AES-256-GCM token brokering that shields downstream credentials from LLM context windows.

## 📦 Workspace Crates

| Crate | Description |
| --- | --- |
| [`authkestra`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra)                     | **Primary Facade**: Re-exports all other crates behind features. Hosts the runnable examples. |
| [`authkestra-engine`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-engine)       | Foundational types, traits and the **Engine** orchestrator.               |
| [`authkestra-mcp`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-mcp)             | Embedded Model Context Protocol (MCP) security guard, RFC 8785 JCS cryptographic step-up approval, and zero-trust downstream token vault. |
| [`authkestra-resource`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-resource)   | Resource server enforcement and validation (JWT, etc).                    |
| [`authkestra-providers`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-providers) | Concrete implementation for OAuth providers (GitHub, Google, Discord).    |
| [`authkestra-axum`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-axum)           | Axum-specific integration, including `AuthSession` extractors.            |
| [`authkestra-actix`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-actix)         | Actix-specific integration, including `ActixState` macro support.         |
| [`authkestra-oidc`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-oidc)           | OpenID Connect discovery and provider support.                            |
| [`authkestra-op`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-op)               | OpenID Connect Provider (OP) implementation.                              |
| [`authkestra-devsig`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-devsig)       | Device-bound signature authentication (proof-of-possession + Issuer attestation). |
| [`authkestra-crypto-util`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-crypto-util) | Shared strict signature/key verification helpers used by the OP and devsig crates. |
| [`authkestra-policy`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-policy)       | **Proof of concept** ([#21](https://github.com/marcjazz/authkestra/issues/21)): AWS Cedar authorization policies, not yet wired into any guard. |
| [`authkestra-ssf`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-ssf)             | Shared Signals Framework: Security Event Token (RFC 8417) ingestion and CAEP events. |
| [`authkestra-store-sqlx`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-store-sqlx) | `OpStore` backed by `sqlx` (PostgreSQL, MySQL, SQLite).                  |
| [`authkestra-store-testsuite`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-store-testsuite) | Shared conformance suites a store implementation runs against, so a third-party backend can prove it honours the traits' atomicity contracts. |
| [`authkestra-macros`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra-macros)       | Procedural macros for simplifying Authkestra integration.                 |

## 🛠️ Usage

Authkestra utilizes a powerful **Typestate Builder Pattern** (`Engine::builder()`). This enforces at compile-time that certain methods are only available if their prerequisites are met (e.g., you can only call session methods if a `SessionStore` was provided).

### Quick Start Example

```rust,ignore
use authkestra::Authkestra;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{OAuth2Flow, SessionStore};
use authkestra_providers::github::GithubProvider;
use std::sync::Arc;

// The builder ensures compile-time safety for your authentication stack
let github_provider = GithubProvider::new(client_id, client_secret, redirect_uri);
let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

let auth_engine = Authkestra::builder()
    .provider(OAuth2Flow::new(github_provider))
    .session_store(session_store)
    .build();
```

Every runnable example lives in the facade crate, under
[`crates/authkestra/examples/`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples),
so a single `cargo run -p authkestra --example <name>` covers both frameworks. Each example's
own module docs list the environment variables it needs.

| Example | Command |
| --- | --- |
| Axum basic setup | `cargo run -p authkestra --example axum_basic_setup --all-features` |
| Actix basic setup | `cargo run -p authkestra --example actix_basic_setup --all-features` |
| Axum with GitHub OAuth | `cargo run -p authkestra --example axum_oauth2_github --all-features` |
| Axum with Google OIDC | `cargo run -p authkestra --example axum_oidc_google --all-features` |
| Axum stateless OAuth (JWT callback) | `cargo run -p authkestra --example axum_oauth_stateless --all-features` |
| Axum with Redis session | `cargo run -p authkestra --example axum_session_redis --all-features` |
| Axum resource server | `cargo run -p authkestra --example axum_resource_server --all-features` |
| Axum OP server | `cargo run -p authkestra --example axum_op_server --all-features` |
| Axum OP server on SQLx | `cargo run -p authkestra --example axum_op_server_sqlx --all-features` |
| Axum OP server with device attestation | `cargo run -p authkestra --example axum_op_server_attestation --features full` |
| Axum MFA server (TOTP + WebAuthn) | `cargo run -p authkestra --example axum_mfa_server --all-features` |
| Axum device-bound signatures | `cargo run -p authkestra --example axum_devsig --all-features` |
| Axum data-layer macros (`KvStore` derive) | `cargo run -p authkestra --example axum_data_layer_macros --all-features` |
| Axum OP server with a custom grant | `cargo run -p authkestra --example axum_op_server_custom_grant --all-features` |
| Axum resource server with chained strategies | `cargo run -p authkestra --example axum_resource_server_strategy --all-features` |
| Axum MCP security server | `cargo run -p authkestra --example axum_mcp_server --all-features` |

Most of these have an Actix counterpart under the same name with the `actix_` prefix - 
`actix_basic_setup`, `actix_oauth2_github`, `actix_oidc_google`, `actix_oauth_stateless`,
`actix_op_server`, `actix_op_server_sqlx`, `actix_op_server_custom_grant`,
`actix_op_server_attestation`, `actix_resource_server_strategy`, `actix_devsig`. Five scenarios
are Axum-only today and have **no** Actix twin: `axum_mcp_server`, `axum_mfa_server`, `axum_session_redis`,
`axum_data_layer_macros`, and `axum_resource_server`.

Four protocol-level examples live in `authkestra-engine` instead, because they need no web
framework at all:

- [Client Credentials Flow](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/client_credentials.rs): `cargo run -p authkestra-engine --example client_credentials`
- [Device Flow](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/device_flow.rs): `cargo run -p authkestra-engine --example device_flow`
- [SD-JWT (Selective Disclosure)](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/sd_jwt.rs): `cargo run -p authkestra-engine --example sd_jwt`
- [TOTP enrolment and verification](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra-engine/examples/totp_webauthn.rs) (named `totp_webauthn`, but it exercises the TOTP path only): `cargo run -p authkestra-engine --example totp_webauthn --features totp,sql-sqlite`

## 🏗️ Technical Design Principles

Our architecture enforces strict design principles to guarantee compile-time safety and optimal Developer Experience (DX):

- **Typestate Builder Pattern**: The `Engine::builder()` uses Rust's typestate pattern. This makes misconfigurations a compile-time error rather than a runtime surprise.
- **Trait Objects over Generics**: For I/O bound paths, we prefer `Box<dyn Trait>` (e.g., `Box<dyn AuthMethod>`) over heavy monomorphized generics. This drastically optimizes compilation times without sacrificing meaningful runtime performance.
- **Framework Agnostic Core**: The `authkestra-engine` is pure Rust logic. Axum and Actix integrations are entirely isolated in separate adapter crates, utilizing explicit Extractors like `AuthSession(session)`.
- **Plugin Interfaces**: We extend functionality via strict plugin interfaces (`AuthMethod`, `Flow`) rather than opaque, ordering-dependent middleware.
- **Production-Ready Tracing**: Every handler, endpoint, and logical branch is deeply instrumented with the `tracing` crate, ensuring request flows and errors are fully visible in production without code changes.

## 🤖 AI Agents & Model Context Protocol (MCP) Security

When autonomous AI agents and LLMs interact with backend systems via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), ambient bearer tokens expose systems to prompt injection, confused deputy invocations, and post-approval parameter tampering.

Authkestra's `mcp` module (`authkestra-mcp`) brings zero-trust security to embedded MCP servers:

1. **Three-Tier Security Model (`McpSecurityTier`)**:
 - `Public`: Unauthenticated or optionally authenticated read-only tools (e.g. `echo`, `ping`).
 - `Scoped { required_scopes }`: Protected by OAuth 2.1 / DPoP access tokens validated via `authkestra-resource`. Returns RFC 9728 `WWW-Authenticate` response headers with resource discovery endpoints.
 - `HumanApproved { required_scopes, reproof, approval_ttl_secs }`: High-risk operations (e.g. wire transfers, database drops) requiring human-in-the-loop (HITL) cryptographic approval.
2. **Cryptographic Parameter Binding (RFC 8785 JCS + SHA-256)**:
   Tool arguments are deterministically canonicalized via JSON Canonicalization Scheme (JCS) and signed into a SHA-256 challenge digest over `(session_id, tool_name, jcs_arguments, expires_at)`. Modifying any argument between user approval and tool execution fails verification with a parameter mismatch error.
3. **Hardware-Backed Step-Up Approval**:
   Human approval is validated via `ReproofRequirement` (Passkeys / WebAuthn, TOTP, or device-bound signatures) ensuring freshness before an `AtomicConsume` single-use execution proof token is minted.
4. **Zero-Trust Downstream Token Vault (`EncryptedKvTokenVault`)**:
   Downstream OAuth tokens and credentials are stored at rest using AES-256-GCM authenticated encryption. MCP tool handlers receive a secure `ToolContext` that dynamically resolves scoped credentials without leaking secrets or refresh tokens into LLM prompts.

## 🧠 AI Discoverability & Agent Skills (`llms.txt`)

Authkestra provides first-class support for AI development assistants, coding agents, and context-aware LLMs:

- **Machine-Readable Documentation (`llms.txt`)**:
 - Compact index for coding agents: [`https://authkestra.com/llms.txt`](https://authkestra.com/llms.txt)
 - Full API & typestate reference: [`https://docs.authkestra.com/llms-full.txt`](https://docs.authkestra.com/llms-full.txt)
- **Official Agent Skills (`Authkestra/skills`)**:
 - Repository of ready-to-use skills for Antigravity, Claude Code, and Roo Code: [`https://github.com/Authkestra/skills`](https://github.com/Authkestra/skills).
 - Provides AI models with complete typestate builder rules, zero-hallucination recipes, and security best practices for Authkestra integrations.

## 🧩 Feature Flags Reference

The `authkestra` facade crate exposes granular features matching each deployment profile:

| Category | Feature Flag | Description |
| --- | --- | --- |
| **All Capabilities** | `full` | Enables all capabilities (engine, OIDC, OP, MCP, webauthn, TOTP, devsig, SSF, policy, all providers). Excludes storage backends and TLS choices. |
| **AI / MCP** | `mcp` | Embedded Model Context Protocol security guard, RFC 8785 JCS parameter binding, HITL step-up approval, and encrypted downstream token vault. |
| **Core & Protocols** | `engine` | Core authentication engine orchestrator, flows, sessions, and credentials. |
| | `oidc` | OpenID Connect client, discovery caching, and ID token validation. |
| | `resource` | OAuth 2.0 / 2.1 resource server verification (JWT validation, scope checks, DPoP). |
| | `op` | OpenID Connect Provider / Authorization Server implementation. |
| | `devsig` | Device-bound signature authentication (proof-of-possession). |
| | `ssf` | Shared Signals Framework & CAEP event ingestion. |
| | `policy` | Proof-of-concept AWS Cedar authorization policy engine. |
| **Frameworks** | `axum` | Axum adapter (`authkestra-axum`) with extractors and middleware. |
| | `actix` | Actix Web adapter (`authkestra-actix`) with `ActixState` derive and extractors. |
| **OAuth Providers** | `github`, `google`, `discord` | Pre-configured OAuth 2.0 / OIDC provider clients. |
| **Authentication** | `webauthn` | Passkeys and WebAuthn hardware security keys. |
| | `totp` | Time-based One-Time Passwords (RFC 6238). |
| | `magic-link` | Passwordless email login links. |
| | `otp` | Short numeric email/SMS one-time codes. |
| | `recovery-codes` | Factor-agnostic backup lookup codes (NIST SP 800-63B). |
| | `captcha` | Cloudflare Turnstile and Google reCAPTCHA v3 bot protection. |
| **Storage Backends** | `memory` | Ephemeral in-memory store for development and testing. |
| | `redis` | High-performance distributed session and token cache. |
| | `sql-postgres` | PostgreSQL storage backend via SQLx. |
| | `sql-sqlite` | SQLite storage backend via SQLx. |
| | `sql-mysql` | MySQL / MariaDB storage backend via SQLx. |
| **TLS Provider** | `rustls-aws-lc-rs` | **Default.** Rustls backed by AWS-LC-RS crypto provider. |
| | `rustls-no-provider` | Rustls without default crypto provider (install `ring` or custom provider). |

## 📜 License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/marcjazz/authkestra/blob/main/LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](https://github.com/marcjazz/authkestra/blob/main/LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
