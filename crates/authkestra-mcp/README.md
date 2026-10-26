# authkestra-mcp

[![Crates.io](https://img.shields.io/crates/v/authkestra-mcp.svg)](https://crates.io/crates/authkestra-mcp)
[![Documentation](https://docs.rs/authkestra-mcp/badge.svg)](https://docs.rs/authkestra-mcp)
[![License](https://img.shields.io/crates/l/authkestra-mcp.svg)](LICENSE)

Embedded [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) security, delegated authorization, and cryptographic step-up approval engine for the `authkestra` framework.

Part of the [Authkestra](https://authkestra.com) ecosystem — **The Compile-Time Safe Identity & AI Agent Authorization Engine for Rust**.

---

## Overview

When Large Language Models (LLMs) and autonomous AI agents invoke external tools through MCP servers, traditional bearer-token authorization fails to defend against:
1. **Agent Confused Deputy & Prompt Injection Attacks**: A hijacked agent context can craft high-risk tool calls (e.g. transfer funds, wipe production databases) using ambient bearer tokens.
2. **Post-Approval Parameter Mutation**: If a user approves an operation based on an initial parameter summary, a malicious or malfunctioning client could alter parameters (e.g. changing `amount: 50` to `amount: 5000`) before final execution.
3. **Execution Proof Replay Attacks**: Intercepted approval confirmation tokens can be replayed repeatedly against state-changing tools.
4. **Credential Leakage in LLM Context Windows**: Exposing long-lived API keys or OAuth refresh tokens directly to the AI agent creates severe data-exfiltration vulnerabilities.

`authkestra-mcp` solves these challenges by providing:
- **Three Composable Security Tiers (`McpSecurityTier`)**: Granular per-tool access control (`Public`, `Scoped`, `HumanApproved`).
- **Cryptographic Parameter Binding (RFC 8785 JCS + SHA-256)**: Tool arguments are deterministically canonicalized and hashed into a tamper-proof challenge digest.
- **Human-In-The-Loop (HITL) Step-Up Ceremonies**: High-risk tools require explicit re-authentication (Passkeys/WebAuthn, TOTP, device signatures) with freshness verification (`ReproofRequirement`).
- **Single-Use Replay Defense (`AtomicConsume`)**: Minted execution proof tokens are consumed atomically in a single read-and-delete operation.
- **Zero-Trust Downstream Token Vault (`EncryptedKvTokenVault`)**: Stores third-party OAuth2 tokens at rest using AES-256-GCM authenticated encryption, resolving scoped credentials directly in the server execution context without ever leaking them into LLM prompts.
- **RFC 9728 Protected Resource Metadata**: Standardized OAuth 2.0 protected resource metadata discovery (`/.well-known/oauth-protected-resource`) and `WWW-Authenticate` header elicitation.

---

## Security Architecture

```
[ AI Agent / MCP Client ]
         │
         │  1. tools/call {"name": "transfer", "arguments": {"to": "alice", "amount": 50}}
         ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Authkestra MCP Server Guard                                            │
│                                                                        │
│ 1. Validate Scopes (OAuth 2.1 / DPoP via authkestra-resource)          │
│ 2. Check McpSecurityTier: HumanApproved                                │
│ 3. Compute RFC 8785 JCS canonical arguments                            │
│ 4. Compute Challenge Digest:                                           │
│    SHA-256(session_id : tool_name : jcs_arguments : expires_at)        │
│ 5. Persist PendingApprovalChallenge in KvStore with TTL                │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   │ 2. Step-Up Elicitation (-32001)
                                   ▼
[ AI Agent / Human User ] <───────────────────┐
         │                                    │
         │ 3. Human authenticates via Passkey │
         ▼                                    │
┌───────────────────────────────────────────┐ │
│ Step-Up Approval Ceremony                 │ │
│ 1. Verify ReproofRequirement (freshness)  │ │
│ 2. Mint single-use execution proof token  │ │
│ 3. Return execution_token to user/agent   │ │
└──────────────────┬────────────────────────┘ │
                   │                          │
                   │ 4. Retries tools/call    │
                   │    with execution_token  │
                   ▼                          │
┌───────────────────────────────────────────┐ │
│ Execution Gate                            │ │
│ 1. AtomicConsume::consume(token)          │ │
│    ↳ Replay rejected if None!             │ │
│ 2. Re-compute JCS SHA-256 Digest          │ │
│    ↳ ParameterMismatch if tampered!       │ │
│ 3. Execute Tool Handler                   │ │
│    ↳ Resolves downstream token via vault  │ │
└───────────────────────────────────────────┘ │
```

---

## Security Tiers (`McpSecurityTier`)

| Tier | Policy | Unauthenticated Behavior | Insufficient Scopes | HITL Step-Up |
|---|---|---|---|---|
| `Public` | Open to all callers | Executes tool | N/A | No |
| `Scoped` | Requires valid bearer or DPoP token with scopes | RFC 9728 `401 Unauthorized` (`WWW-Authenticate`) | `403 Forbidden` (`insufficient_scope`) | No |
| `HumanApproved` | Scope check + cryptographic parameter binding | `401 Unauthorized` | `403 Forbidden` | **Yes** (RFC 8785 + SHA-256 digest) |

---

## Installation

Add `authkestra-mcp` to your `Cargo.toml`:

```toml
[dependencies]
authkestra-mcp = "0.13.1"
```

---

## Quickstart Example

```rust
use authkestra_mcp::{
    BoxedToolHandler, McpRouter, McpSecurityTier, ToolCallResult, ToolContext, ToolDefinition,
};
use authkestra_engine::auth::ReproofRequirement;
use authkestra_engine::store::MemoryStore;
use serde_json::json;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize storage backends
    let pending_store = Arc::new(MemoryStore::new());
    let execution_store = Arc::new(MemoryStore::new());

    // 2. Define a high-risk tool requiring human approval and fresh authentication
    let transfer_tool = ToolDefinition::new(
        "transfer_funds",
        json!({
            "type": "object",
            "properties": {
                "recipient": { "type": "string" },
                "amount": { "type": "number" }
            },
            "required": ["recipient", "amount"]
        }),
        McpSecurityTier::human_approved(
            vec!["payments:transfer"],
            ReproofRequirement::new(300), // Human must have authenticated within 5 minutes
            300,                          // 5-minute approval challenge TTL
        ),
        |args, ctx: ToolContext| async move {
            let recipient = args["recipient"].as_str().unwrap_or("unknown");
            let amount = args["amount"].as_f64().unwrap_or(0.0);

            // Optional: Resolve downstream payment gateway credentials without leaking to LLM
            // let api_key = ctx.get_downstream_token("stripe", &["charges:write"]).await?;

            Ok(ToolCallResult::text(format!(
                "Successfully transferred ${:.2} to {}",
                amount, recipient
            )))
        },
    ).with_description("Transfers funds to a recipient account");

    // 3. Build the McpRouter
    let router = McpRouter::builder(pending_store, execution_store)
        .tool(transfer_tool)
        .approval_base_url("https://auth.example.com")
        .build();

    Ok(())
}
```

---

## Cryptographic Parameter Binding (RFC 8785 JCS)

When a `HumanApproved` tool call arrives without an execution proof token:
1. The tool arguments are normalized and canonicalized using **RFC 8785 JSON Canonicalization Scheme (JCS)** via `serde_json_canonicalizer`.
2. A SHA-256 digest is computed over `(session_id, tool_name, jcs_canonical_arguments, expires_at)`.
3. The server responds with JSON-RPC error code `-32001` (`RPC_STEP_UP_REQUIRED`) containing the challenge digest and approval URL.
4. When the human approves, an `ApprovedExecutionRecord` is minted in `KvStore`.
5. Upon retry with the execution token, the router re-canonicalizes the arguments and re-computes the digest. If *any* argument was changed, re-ordered keys retain the same hash, but altered values (or injected keys) produce a hash mismatch, failing immediately with `-32003` (`RPC_PARAMETER_MISMATCH`).

---

## Single-Use Replay Defense (`AtomicConsume`)

Execution tokens can only be presented once. The router calls `AtomicConsume::consume(key)` which atomically removes the token from the underlying store. If an attacker intercepts the token and replays it, the second request yields `None` and is rejected with `-32004` (`RPC_TOKEN_REPLAY_OR_EXPIRED`).

---

## Zero-Trust Downstream Token Vault

To prevent autonomous agents from inspecting raw OAuth refresh tokens or master secrets in LLM prompt contexts, `authkestra-mcp` includes `EncryptedKvTokenVault`:
- Tokens are encrypted at rest using **AES-256-GCM** (NIST SP 800-38D with 12-byte random nonces and 16-byte authentication tags) via `authkestra-crypto-util`.
- Storage keys isolate tokens per tenant: `mcp:vault:{provider_id}:{external_id}:{service}`.
- Tool handlers access tokens strictly through `ToolContext::get_downstream_token(service, scopes)`, ensuring zero-trust credential isolation.

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
