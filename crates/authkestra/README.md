# authkestra

[![Crates.io](https://img.shields.io/crates/v/authkestra.svg)](https://crates.io/crates/authkestra)
[![Docs.rs](https://docs.rs/authkestra/badge.svg)](https://docs.rs/authkestra)
[![CI](https://github.com/marcjazz/authkestra/actions/workflows/ci.yml/badge.svg)](https://github.com/marcjazz/authkestra/actions)
[![License](https://img.shields.io/crates/l/authkestra.svg)](https://github.com/marcjazz/authkestra/blob/main/LICENSE-MIT)

**The Compile-Time Safe Identity & AI Agent Authorization Engine for Rust**

`authkestra` is the primary facade crate for the Authkestra ecosystem. It unifies enterprise-grade identity (OAuth 2.1, OpenID Connect Provider/Client, Passkeys/WebAuthn, TOTP, Passwordless, DPoP, SD-JWT, SSF/CAEP) and autonomous AI agent tool authorization (Model Context Protocol (MCP) server guards, JCS cryptographic parameter binding, HITL step-up approval, and zero-trust downstream credential brokering) into a single, cohesive, compile-time safe Rust crate.

---

## 🚀 Key Highlights

- **Compile-Time Safe Typestate Builder**: Unrepresented or invalid auth configurations fail at compile-time, not in production.
- **Unified Facade**: Manage your entire identity and agent authorization stack from a single dependency via fine-grained Cargo feature flags.
- **Autonomous AI Agent & MCP Security (`authkestra-mcp`)**: Protect Model Context Protocol tool endpoints with 3-tier authorization (`Public`, `Scoped`, `HumanApproved`), RFC 8785 JSON Canonicalization Scheme (JCS) parameter binding, Passkey/WebAuthn human-in-the-loop (HITL) step-up approval, and AES-256-GCM zero-trust downstream credential vaults.
- **Framework Adapters**: First-class, ergonomic integrations for both **Axum** (`authkestra-axum`) and **Actix Web** (`authkestra-actix`).
- **Database & Schema Agnostic**: No forced schemas or rigid user tables. Bring your own database via clean trait abstractions (`KvStore`, `SessionStore`, `CredentialStore`, `OpStore`).
- **Production-Ready Tracing & Security**: Full `tracing` instrumentation across all request lifecycles, timing-safe cryptographic comparisons, and single-use `AtomicConsume` execution proofs.

---

## 📦 Installation

Add `authkestra` to your `Cargo.toml` with the features you need:

```toml
[dependencies]
# Example: Axum web application with GitHub OAuth2 and in-memory store
authkestra = { version = "0.13", features = ["axum", "github", "memory"] }
```

Or for an MCP server protecting AI agent tool calls:

```toml
[dependencies]
# Example: Axum MCP server with Model Context Protocol security & Passkeys
authkestra = { version = "0.13", features = ["axum", "mcp", "webauthn", "memory"] }
```

### 🔐 TLS Backend

Authkestra requires an HTTPS crypto provider to speak to identity providers and token endpoints:

| Feature | Description |
| --- | --- |
| `rustls-aws-lc-rs` | **Default.** Fast, hardware-accelerated crypto provider via `aws-lc-rs`. Requires a C toolchain. |
| `rustls-no-provider` | Pure-Rust builds (`ring`) or custom environments where `aws-lc-rs` is banned by `cargo-deny`. |

---

## 🛠️ Quickstart

### 1. Web Application Authentication (Axum + OAuth2)

```rust,ignore
use authkestra::Authkestra;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{OAuth2Flow, SessionStore};
use authkestra_providers::github::GithubProvider;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap();
    let client_secret = std::env::var("GITHUB_CLIENT_SECRET").unwrap();
    let redirect_uri = "http://localhost:3000/auth/github/callback".to_string();

    let github_provider = GithubProvider::new(client_id, client_secret, redirect_uri);
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

    // Compile-time typestate builder validates prerequisites
    let auth_engine = Authkestra::builder()
        .provider(OAuth2Flow::new(github_provider))
        .session_store(session_store)
        .build();
}
```

### 2. AI Agent MCP Server Guard (`authkestra::mcp`)

Protect your Model Context Protocol (MCP) server endpoints with granular security tiers, cryptographic parameter binding, and human-in-the-loop approval:

```rust,ignore
use authkestra::mcp::{McpRouter, McpSecurityTier, ToolHandler, ToolContext, McpError};
use authkestra_engine::reproof::ReproofRequirement;
use serde_json::{json, Value};
use std::sync::Arc;

struct TransferTool;

#[async_trait::async_trait]
impl ToolHandler for TransferTool {
    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<Value, McpError> {
        let amount = args["amount"].as_i64().unwrap_or(0);
        let to = args["to"].as_str().unwrap_or("unknown");
        
        // Downstream credentials resolved securely without exposing keys to LLM context
        let api_token = ctx.get_downstream_token("bank_api", &["transfers:write"]).await;

        Ok(json!({ "status": "executed", "amount": amount, "to": to }))
    }
}

// Build the MCP security router
let mut router = McpRouter::new(session_store.clone(), kv_store.clone());

// Register a high-risk tool requiring Passkey step-up and JCS parameter binding
router.register_tool(
    "execute_transfer",
    "Execute high-value financial transfers",
    json!({
        "type": "object",
        "properties": {
            "amount": { "type": "number" },
            "to": { "type": "string" }
        },
        "required": ["amount", "to"]
    }),
    McpSecurityTier::HumanApproved {
        required_scopes: vec!["scope:transfer".into()],
        reproof: ReproofRequirement::FreshPasskey,
        approval_ttl_secs: 300,
    },
    Arc::new(TransferTool),
);
```

Run the complete, runnable Axum MCP server example:

```bash
cargo run -p authkestra --example axum_mcp_server --all-features
```

---

## 🧩 Feature Flags Reference

| Feature | Category | Description |
| --- | --- | --- |
| `full` | Meta | Enables all capabilities across the engine, OIDC, OP, MCP, Passkeys, TOTP, and providers. |
| `mcp` | AI / Agent | Embedded Model Context Protocol security guard, RFC 8785 JCS parameter binding, HITL step-up approval, and zero-trust token vault. |
| `engine` | Core | Core authentication engine orchestrator, flows, sessions, and credentials. |
| `oidc` | Protocols | OpenID Connect discovery caching, ID token validation, and client flow. |
| `resource` | Protocols | OAuth 2.0 / 2.1 resource server verification (JWT validation, scope checks, DPoP). |
| `op` | Protocols | OpenID Connect Provider / Authorization Server implementation. |
| `devsig` | Protocols | Device-bound signature authentication (proof-of-possession). |
| `ssf` | Protocols | Shared Signals Framework & CAEP event ingestion. |
| `policy` | Authorization | Proof-of-concept AWS Cedar authorization policy engine. |
| `axum` | Framework | Axum adapter (`authkestra-axum`) with extractors and MCP router. |
| `actix` | Framework | Actix Web adapter (`authkestra-actix`) with `ActixState` macro and MCP scope. |
| `github` | Providers | Pre-configured GitHub OAuth 2.0 provider. |
| `google` | Providers | Pre-configured Google OpenID Connect provider. |
| `discord` | Providers | Pre-configured Discord OAuth 2.0 provider. |
| `webauthn` | Auth Methods | Passkeys and WebAuthn hardware security keys. |
| `totp` | Auth Methods | Time-based One-Time Passwords (RFC 6238). |
| `magic-link` | Auth Methods | Passwordless email login links. |
| `otp` | Auth Methods | Numeric email/SMS one-time codes. |
| `recovery-codes` | Auth Methods | Factor-agnostic backup lookup codes (NIST SP 800-63B). |
| `captcha` | Security | Cloudflare Turnstile and Google reCAPTCHA v3 bot protection. |
| `memory` | Storage | In-memory store for development and testing. |
| `redis` | Storage | High-performance Redis session and token store. |
| `sql-postgres` | Storage | PostgreSQL store backed by SQLx. |
| `sql-sqlite` | Storage | SQLite store backed by SQLx. |
| `sql-mysql` | Storage | MySQL / MariaDB store backed by SQLx. |
| `rustls-aws-lc-rs` | TLS | **Default.** Rustls with AWS-LC-RS crypto provider. |
| `rustls-no-provider` | TLS | Rustls without crypto provider (install `ring` manually). |

---

## 🧠 AI Discoverability & Claude Code Skills (`llms.txt`)

- **Agent Index**: [`https://authkestra.com/llms.txt`](https://authkestra.com/llms.txt)
- **Full API Documentation**: [`https://docs.authkestra.com/llms-full.txt`](https://docs.authkestra.com/llms-full.txt)
- **Official Skills Repository**: [`https://github.com/Authkestra/skills`](https://github.com/Authkestra/skills) for Claude Code, Antigravity, and Roo Code agent integration.

---

## 📜 License

Dual-licensed under [MIT](https://github.com/marcjazz/authkestra/blob/main/LICENSE-MIT) or [Apache 2.0](https://github.com/marcjazz/authkestra/blob/main/LICENSE-APACHE) at your option.
