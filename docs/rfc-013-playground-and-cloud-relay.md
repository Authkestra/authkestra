# RFC-013: Playground Revamp (Auth & MCP Flow Architect) and Cloud Hosted Relay

> **Status: proposed / design record**  
> Tracking issue: [authkestra#412](https://github.com/marcjazz/authkestra/issues/412)  
> Crate associations: `authkestra-mcp`, `authkestra-policy`, `authkestra-ssf`, `authkestra-engine`, `authkestra-axum`  
> Strategic phase: Phase 5 (Platform & AI-Native DX) & Commercial Cloud SaaS

---

## 1. Summary

This RFC establishes the unified product and technical architecture for two synergistic Authkestra initiatives:

1. **Part 1 — Playground Revamp ("Auth & MCP Flow Architect" at `play.authkestra.com`)**:  
   An interactive, browser-based visual architect and live ceremony simulator. Developers visually compose their authentication topology (combining human auth methods with AI/MCP security tiers: `Public`, `Scoped`, `HumanApproved` with RFC 8785 JCS parameter binding, Cedar ABAC/ReBAC policies, and OpenID CAEP continuous revocation), execute live JSON-RPC and biometric step-up flows in-browser, test adversarial parameter tampering and replay attacks, and export ready-to-compile Rust backend handlers (`axum` / `actix-web`) alongside Agent Skills (`SKILL.md`) and Cursor IDE rules (`.cursorrules`).

2. **Part 2 — Cloud Hosted Relay (`relay.authkestra.com`)**:  
   A high-margin, zero-user-PII commercial cloud control plane that operationalizes Authkestra in headless AI agent environments. It solves the two most pressing operational bottlenecks for autonomous agent deployments:
   - **Out-of-Band Passkey Step-Up Relay**: Hosted WebAuthn biometric approval endpoint with instant SSE / webhook push to headless CLI, background worker, or IDE agent processes that lack a local browser UI.
   - **Managed Zero-Trust Agent Token Broker**: AWS KMS envelope-encrypted downstream OAuth credential storage with dynamic, short-lived, DPoP-bound and JCS-bound token dispensing—ensuring long-lived credentials never enter LLM prompt contexts.

By bridging design-time prototyping at `play.authkestra.com` with run-time execution at `relay.authkestra.com`, Authkestra captures developers at the prototyping phase and provides a friction-free on-ramp to enterprise production infrastructure.

---

## 2. Motivation

### 2.1 The Autonomous Agent Security Crisis

The rapid adoption of Model Context Protocol (MCP) clients and autonomous agent frameworks (Claude Desktop, Cursor, Cline, Windsurf, custom LangChain/AutoGPT agents) has created a dangerous divergence between application capabilities and authentication primitives:

1. **Headless Execution Environments**: Agents run in terminal windows, background containers, or CI/CD pipelines where no interactive browser or WebAuthn authenticator is available. When an agent attempts an irreversible action (e.g. `transfer_funds`, `drop_table`, `deploy_production`), it cannot satisfy biometric step-up requirements locally.
2. **Prompt Injection & Credential Exfiltration**: Exposing static API tokens or long-lived OAuth refresh tokens to agent execution loops makes them vulnerable to prompt injection attacks, wherein malicious context instructs the model to leak or misuse the credential.
3. **Parameter Mutation & Confused Deputy Attacks**: Without cryptographic binding between what a human approves and what the agent actually executes, a compromised model can elicit human approval for a benign action (e.g., `transfer $10`) and subsequently execute a malicious action (e.g., `transfer $10,000`).
4. **Lack of Continuous Session Revocation**: If a developer's identity provider revokes their session (e.g. Okta or Google CAEP `SessionRevoked` or `CredentialChange`), headless agent instances typically continue executing until access tokens expire naturally hours later.

### 2.2 Why Developers Need a Visual Flow Architect

Configuring zero-trust authentication across human users, Cedar policy sets, CAEP event handlers, and MCP agent tools involves non-trivial typestate combinations and security invariants:
- Hand-crafting Rust authorization guards and JCS digest verifiers introduces friction and error potential.
- Prototyping requires immediate visual feedback: seeing an agent tool call get rejected by Cedar, prompting a mobile passkey biometric pulse, and observing single-use token consumption upon execution.
- Development teams require exportable, self-documenting artifacts: not just starter code, but complete agent context files (`SKILL.md`) and Cursor IDE guardrails (`.cursorrules`) so coding assistants automatically comply with compile-time security invariants.

---

## 3. What Already Exists, Traced Before Designing Anything

Authkestra `v0.13` provides the foundation in the core Rust monorepo:

| Crate | Version | Production Capability |
|---|---|---|
| `authkestra-mcp` | `0.13.1` | `McpSecurityTier` (`Public`, `Scoped`, `HumanApproved`), RFC 8785 JCS canonicalizer + SHA-256 parameter digest, error code `-32001` step-up challenge, single-use `AtomicConsume`, `EncryptedKvTokenVault` (AES-256-GCM envelope encryption). |
| `authkestra-policy` | `0.13.1` | AWS Cedar ABAC/ReBAC policy engine (`CedarPolicyEngine`, `AuthorizationRequest`, `EntityRecord`, `MemoryResourceLoader`). Sub-100µs deterministic decision latency, fail-closed `UnreliableDecision` enforcement. |
| `authkestra-ssf` | `0.13.1` | RFC 8417 Security Event Token (SET) verification, RFC 8935 HTTP push receiver, typed OpenID CAEP 1.0 event parsing (`SessionRevoked`, `CredentialChange`), `SessionRevocationHandler`. |
| `authkestra-engine` | `0.13.1` | Passwordless primitives (`magic-link`, `otp` with `AtomicDecrement` attempt limiting, `recovery-codes` NIST SP 800-63B), `ReproofRequirement` (`require_step_up`), WebAuthn passkeys, TOTP. |
| `authkestra-axum` | `0.13.1` | Typed extractors (`Identity`, `AuthSession`, `McpToolGuard`), Cedar middleware, SSF push receiver endpoints (`POST /.well-known/ssf/events`, `POST /ssf/events`). |

Neither `play.authkestra.com` nor `relay.authkestra.com` requires invent-from-scratch cryptographic foundations; both directly compose these proven primitives.

---

## 4. Architecture & System Topology

The end-to-end Authkestra ecosystem links browser design-time flow composition with production runtime execution:

```
+-----------------------------------------------------------------------------------+
|                        DESIGN-TIME: play.authkestra.com                            |
|                                                                                   |
|  +--------------------+     +---------------------+     +----------------------+  |
|  |   Step 1: Choose   | --> |   Step 2: Live      | --> |    Step 3: Export    |  |
|  |   Topology Graph   |     |  Ceremony Simulator |     |  Rust + SKILL.md     |  |
|  +--------------------+     +---------------------+     +----------------------+  |
+------------------------------------------+----------------------------------------+
                                           | deploys to production
                                           v
+-----------------------------------------------------------------------------------+
|                         RUNTIME: PRODUCTION DEPLOYMENT                             |
|                                                                                   |
|  +---------------------+        JSON-RPC        +-------------------------------+  |
|  | Headless MCP Client | <====================> | Authkestra-Guarded MCP Server |  |
|  |  (CLI / Cursor IDE) |                        | (Axum / Actix + Cedar Policy) |  |
|  +----------+----------+                        +---------------+---------------+  |
|             |                                                   |                  |
|             | Poll / SSE                                        | Out-of-band      |
|             | Challenge Wait                                    | Challenge Push   |
|             v                                                   v                  |
|  +------------------------------------------------------------------------------+  |
|  |              CLOUD HOSTED RELAY (relay.authkestra.com)                        |  |
|  |                                                                              |  |
|  |  +-----------------------+     +-------------------+     +----------------+  |  |
|  |  | Zero-PII Relay Store  |     | WebAuthn Approval |     | Zero-Trust     |  |  |
|  |  | Ephemeral ChallengeDB |     | Hosted UI / QR    |     | Token Broker   |  |  |
|  |  +-----------------------+     +---------+---------+     +----------------+  |  |
|  +------------------------------------------|-----------------------------------+  |
|                                             | WebAuthn Biometric Prompt            |
|                                             v                                      |
|                                  +---------------------+                           |
|                                  |   Approver Mobile   |                           |
|                                  |   Passkey Device    |                           |
|                                  +---------------------+                           |
+-----------------------------------------------------------------------------------+
```

---

## 5. Part 1 — Playground Revamp ("Auth & MCP Flow Architect" at `play.authkestra.com`)

### 5.1 Interactive Visual Flow Topology

The Playground features a reactive node-graph canvas rendered in the Warm Obsidian (`#09090b`) & Signal Amber (`#f4845f`) palette:
- **Ingress Node**: Represents incoming user or agent requests (OAuth2, Passkey, Magic Link, OTP, or MCP JSON-RPC).
- **Policy Gate Node**: Evaluates Cedar ABAC policies (e.g. `permit(principal, action, resource) when { context.mcp_tier == "HumanApproved" };`).
- **Security Guard Node**: Visualizes the active MCP tier (`Public`, `Scoped`, `HumanApproved`) and highlights RFC 8785 JCS canonicalization.
- **Relay Bridge Node**: Toggles local vs. Cloud Hosted Relay out-of-band step-up approval routing.
- **Vault Node**: Represents the Zero-Trust Token Vault releasing downstream API tokens directly to the backend handler.

Nodes pulsate with Signal Amber glows when active, providing instant visual feedback during scenario execution.

### 5.2 Live Ceremony Simulator

The simulator provides dedicated interactive ceremony panels for all v0.13.1 capabilities:

1. **MCP Security Tier Simulator (`authkestra-mcp`)**:
   - Allows selecting tool tier: `Public`, `Scoped`, or `HumanApproved`.
   - Tool arguments editor with JSON formatting.
   - **Simulate Call**: Triggers RFC 8785 JCS canonicalization, computes `SHA-256(session_id : tool_name : jcs_args : expires_at)`, and returns JSON-RPC `-32001` challenge.
   - **Simulate Passkey Approval**: Triggers WebAuthn biometric pulse, generating a cryptographically signed execution token.
   - **Test Tampering Attack**: Mutates a JSON parameter (e.g. changing amount from `10.00` to `1000.00`) and asserts that the server rejects execution with an RFC 8785 digest mismatch.
   - **Test Replay Attack**: Submits the execution token a second time to demonstrate instant rejection via single-use `AtomicConsume`.

2. **Passwordless Suite (`authkestra-engine`)**:
   - **Magic Link**: Generates a cryptographically random one-time link token, renders the simulated email inbox, and verifies single-use redemption.
   - **OTP**: Dispatches 6-digit counter/time code, tests constant-time verification, and simulates brute-force lockout via `AtomicDecrement` attempt counter.
   - **Recovery Codes**: Generates 10 x 80-bit base32 NIST SP 800-63B recovery codes, verifying one-time redemption and live remaining counter.
   - **Reproof Gate**: Evaluates `ReproofRequirement` (e.g. freshness <= 300s, required factor level).

3. **Cedar Policy Evaluator (`authkestra-policy`)**:
   - Template library: `AdminOnly`, `DepartmentABAC`, `EmergencyBreakGlass`.
   - Live Cedar evaluator measuring sub-100µs decision latency and rendering detailed diagnostics (matched policy IDs, forbidding clauses).

4. **Continuous SSF / CAEP Revocation (`authkestra-ssf`)**:
   - Dispatches RFC 8417 Security Event Tokens (e.g. `SessionRevoked`, `CredentialChange`).
   - Demonstrates instant session termination across connected simulator state.

### 5.3 Code & Agent Skill Exporter

Step 3 exports three fully configured, ready-to-run artifacts:
1. **Rust Backend Source**: Complete Axum or Actix project zip containing `main.rs`, handlers, Cedar policy files, and `Cargo.toml` with exact v0.13.1 dependencies.
2. **Agent Skill Specification (`SKILL.md`)**: Standardized Agent Skills format detailing available MCP tools, required security tiers, and parameters.
3. **Cursor IDE Rules (`.cursorrules` & `.cursor/rules/authkestra.mdc`)**: Explicit prompt instructions that enforce compile-time typestate rules, preventing LLM code assistants from introducing insecure bypasses.

---

## 6. Part 2 — Cloud Hosted Relay (`relay.authkestra.com`)

### 6.1 Zero-User-PII Architecture Invariant

`relay.authkestra.com` enforces a strict cryptographic zero-PII invariant:
- **No Personal Identifiers**: The relay never accepts, processes, or stores usernames, email addresses, phone numbers, IP addresses, or user database IDs.
- **Ephemeral State**: State is keyed strictly by:
  - `challenge_id`: Ephemeral UUIDv4 generated by the customer's MCP server.
  - `parameter_digest`: RFC 8785 SHA-256 hash of the canonicalized tool arguments.
  - `session_nonce`: Ephemeral 256-bit random nonce.
- **Short Time-to-Live**: All challenge state in Redis/Memory automatically expires after 300 seconds (5 minutes). Once consumed or expired, records are purged immediately.

### 6.2 Out-of-Band Passkey Step-Up Relay

When a headless agent initiates a `HumanApproved` tool call:
1. The customer's MCP server creates an ephemeral challenge on `relay.authkestra.com`:
   ```
   POST /v1/challenges
   Authorization: Bearer <RELAY_API_KEY>
   {
     "challenge_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
     "tool_name": "transfer_funds",
     "parameter_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "display_metadata": {
       "title": "Transfer Funds",
       "summary": "Transfer $500.00 to Account #8492"
     },
     "expires_in_seconds": 300
   }
   ```
2. The relay returns an approval URL: `https://relay.authkestra.com/approve/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d`.
3. The MCP server returns a `-32001` error to the headless agent containing the approval URL and a QR code data URI.
4. The user scans the QR code on their mobile device or clicks the link in their terminal, triggering a WebAuthn biometric prompt (`UserVerification = required`).
5. Upon biometric completion, the relay validates the WebAuthn signature against the user's registered public key and dispatches an approval event over SSE / WebSocket to the waiting MCP server or agent CLI.
6. The MCP server releases a cryptographically signed, single-use `execution_token`.

### 6.3 Managed Zero-Trust Agent Token Broker

To prevent API credentials from ever leaking into LLM contexts:
1. Downstream OAuth tokens (e.g. GitHub, Slack, AWS, Stripe) are stored envelope-encrypted in the Broker using AES-256-GCM with customer-managed or AWS KMS master keys.
2. The agent never receives the raw token. Instead, when executing a tool, the agent passes its single-use `execution_token` to the MCP tool handler.
3. The MCP tool handler forwards the token to the Broker, which validates the JCS digest and caller identity, performs the external API call directly, and returns only the sanitized result to the agent.
4. For services requiring direct agent transmission, the Broker dispenses ultra-short-lived (e.g. 60-second) DPoP-bound access tokens constrained strictly to the required resource URI.

---

## 7. Protocol Flows & Sequence Diagrams

### 7.1 Out-of-Band Passkey Approval Ceremony

```
+---------------+        +--------------+         +----------------+         +------------------+
| Headless MCP  |        | Customer MCP |         | relay.authkestra|         | User Mobile /    |
| Agent (CLI)   |        | Server Guard |         | .com (Relay)   |         | Browser Passkey  |
+-------+-------+        +------+-------+         +-------+--------+         +--------+---------+
        |                       |                         |                           |
        | 1. tools/call         |                         |                           |
        | (tool, args)          |                         |                           |
        |---------------------->|                         |                           |
        |                       | 2. JCS SHA-256 Hash     |                           |
        |                       |    & Policy Check       |                           |
        |                       |                         |                           |
        |                       | 3. POST /v1/challenges  |                           |
        |                       | (digest, metadata)      |                           |
        |                       |------------------------>|                           |
        |                       | 4. { challenge_id, url }|                           |
        |                       |<------------------------|                           |
        | 5. JSON-RPC -32001    |                         |                           |
        | (approval_url, QR)    |                         |                           |
        |<----------------------|                         |                           |
        |                       |                         |                           |
        | 6. Poll / SSE Connect |                         |                           |
        | (GET /v1/wait/:id)    |                         |                           |
        |------------------------------------------------>|                           |
        |                       |                         |                           |
        |                       |                         | 7. User navigates to URL  |
        |                       |                         | <approve/:challenge_id>   |
        |                       |                         |<--------------------------|
        |                       |                         | 8. WebAuthn CredentialGet |
        |                       |                         |-------------------------->|
        |                       |                         | 9. Biometric signature    |
        |                       |                         |<--------------------------|
        |                       |                         |                           |
        | 10. SSE Push Event    |                         | 10b. Approval Confirmed   |
        | "status": "approved"  |                         |-------------------------->|
        |<------------------------------------------------|                           |
        |                       |                         |                           |
        | 11. tools/call        |                         |                           |
        | (tool, args, exec_tok)|                         |                           |
        |---------------------->|                         |                           |
        |                       | 12. AtomicConsume &     |                           |
        |                       |     Digest Match Check  |                           |
        |                       | 13. Execute Tool Logic  |                           |
        | 14. Tool Result JSON  |                         |                           |
        |<----------------------|                         |                           |
```

### 7.2 Zero-Trust Token Broker Dispensing

```
+---------------+        +--------------+         +----------------+         +------------------+
| Headless MCP  |        | Customer MCP |         | Authkestra     |         | Downstream API   |
| Tool Handler  |        | Server Guard |         | Token Broker   |         | (GitHub/Stripe)  |
+-------+-------+        +------+-------+         +-------+--------+         +--------+---------+
        |                       |                         |                           |
        | 1. Execute with       |                         |                           |
        |    execution_token    |                         |                           |
        |---------------------->|                         |                           |
        |                       | 2. POST /v1/broker/dispense                         |
        |                       | (exec_tok, target_api)  |                           |
        |                       |------------------------>|                           |
        |                       |                         | 3. Validate Token & Cedar |
        |                       |                         | 4. KMS Decrypt RefreshTok |
        |                       |                         | 5. Mint DPoP Access Tok   |
        |                       | 6. Ephemeral Token /    |                           |
        |                       |    Proxied Request      |                           |
        |                       |<------------------------|                           |
        |                       |                                                     |
        |                       | 7. Call downstream with DPoP token                  |
        |                       |---------------------------------------------------->|
        |                       | 8. Response data                                    |
        |                       |<----------------------------------------------------|
        | 9. Sanitized Output   |                         |                           |
        |<----------------------|                         |                           |
```

### 7.3 CAEP Continuous Revocation Wave

```
+---------------+        +--------------+         +----------------+         +------------------+
| Identity      |        | relay.auth   |         | Customer MCP   |         | Active Agent     |
| Provider (IdP)|        | kestra.com   |         | Server Ingress |         | Session State    |
+-------+-------+        +------+-------+         +-------+--------+         +--------+---------+
        |                       |                         |                           |
        | 1. CAEP Push Event    |                         |                           |
        | POST /ssf/events      |                         |                           |
        | (SessionRevoked SET)  |                         |                           |
        |---------------------->|                         |                           |
        |                       | 2. Verify SET Signature |                           |
        |                       | 3. Fan-out SSF Event    |                           |
        |                       |------------------------>|                           |
        |                       |                         | 4. SessionRevocation      |
        |                       |                         |    Handler                |
        |                       |                         | 5. Evict Session Store    |
        |                       |                         |-------------------------->|
        |                       |                         | 6. Kill active streams    |
        |                       |                         |    & reject pending tokens|
```

---

## 8. Security Architecture, Threat Model & Zero-PII Invariants

### 8.1 Cryptographic Parameter Binding (RFC 8785 JCS)

To defend against parameter tampering:
- Argument JSON objects are canonicalized via RFC 8785:
  - Object keys sorted lexicographically by UTF-16 code units.
  - Whitespace between tokens eliminated.
  - Floating point numbers formatted deterministically per ECMAScript specification.
- Parameter Digest calculation:
  $$\text{digest} = \text{SHA-256}(\text{session\_id} \parallel \text{":"} \parallel \text{tool\_name} \parallel \text{":"} \parallel \text{JCS}(\text{arguments}) \parallel \text{":"} \parallel \text{expires\_at})$$
- The biometric approval signs this exact digest. If an attacker tampers with even a single byte or reorders a dictionary key, the computed digest mismatches and execution is aborted with an audit alert.

### 8.2 Single-Use Token Invariant (`AtomicConsume`)

Execution tokens emitted upon step-up approval are bound to Redis / Memory via an atomic compare-and-swap primitive (`GETDEL` or Lua script):
- `AtomicConsume` guarantees that once a token is submitted for tool execution, its state changes from `Unconsumed` to `Consumed` in a single atomic transaction.
- Replay attacks are cryptographically impossible: subsequent invocations with the same token fail with `ExecutionTokenReplayed`.

### 8.3 WebAuthn Security Flags

All approvals relayed through `relay.authkestra.com` require:
- **User Presence (`UP = 1`)**: The user physically touched or interacted with the authenticator.
- **User Verification (`UV = 1`)**: Biometrics (Face ID, Touch ID, Windows Hello) or device PIN was verified by the secure enclave.

### 8.4 Threat Matrix

| Threat | Attack Vector | Authkestra Mitigation |
|---|---|---|
| **Parameter Tampering** | Attacker intercepts approval request and alters payload parameters (e.g. recipient account). | RFC 8785 JCS + SHA-256 digest binding. Signature validation fails if arguments differ by a single bit. |
| **Token Replay** | Attacker captures approved execution token and re-executes tool. | `AtomicConsume` atomic deletion upon first use. Second submission fails instantly. |
| **Relay Compromise / Breach** | Attacker breaches `relay.authkestra.com` database. | Zero-PII invariant: Database stores only ephemeral UUIDs, hashes, and public keys with 300s TTL. No usernames, emails, or cleartext tokens exist to steal. |
| **Prompt Injection Token Exfiltration** | Malicious context instructs LLM to print its API keys. | Zero-Trust Token Vault: LLM never holds keys. MCP tool handlers inject keys inside the verified backend boundary. |
| **DDoS on Approval Endpoint** | Attacker floods challenge creation API. | Rate limiting via sliding window Governor + token bucket per API key; IP reputation scoring; proof-of-work challenges if triggered. |

---

## 9. Monetization Tiers & Commercial Strategy

`relay.authkestra.com` operates as a high-margin developer SaaS with clear utility-based pricing tiers:

### 9.1 Tier Comparison Matrix

| Feature | Developer (Free) | Team / Pro | Enterprise |
|---|---|---|---|
| **Monthly Price** | **$0** | **$49 / month** | **Custom Annual ($12k–$60k/yr)** |
| **Included Approvals** | 1,000 / month | 50,000 / month | Unlimited / Custom Quota |
| **Overage Fee** | Hard stop / $0 | $0.002 / approval | Volume discounts |
| **Active Headless Agents** | Up to 2 | Unlimited | Unlimited |
| **Branding** | relay.authkestra.com | Custom Domain (`auth.company.com`) + Custom Logo | Full white-label + On-Prem / VPC Option |
| **Token Broker Vault** | Up to 10 secrets | Up to 500 secrets | Unlimited secrets + Bring-Your-Own-KMS (AWS/GCP/Vault) |
| **CAEP Event Streams** | Community feed | 5 IdP connections | Unlimited IdP streams + SIEM webhook routing |
| **SLA & Support** | Community GitHub / Discord | 99.9% uptime SLA, 24h email support | 99.99% uptime SLA, 1h emergency pager, dedicated Slack channel |
| **Compliance** | Standard Terms | SOC 2 Type II reports, DPA | Custom MSA, HIPAA BAA, FedRAMP alignment |

### 9.2 Unit Economics & Margins

- **Cost of Goods Sold (COGS)**:
  - Redis / Ephemeral challenge storage: ~$0.00002 per challenge.
  - SSE connection maintenance: Sub-millisecond async I/O in Rust, negligible compute cost (~$0.00005 per approval).
  - Outgoing WebPush / Webhook: ~$0.00001 per message.
  - Total COGS per approval: < $0.0001.
- **Gross Margin**:
  - At $0.002 overage pricing, gross margin exceeds **95%**.
  - High fixed-to-variable margin structure characteristic of top-tier developer infrastructure (similar to Ngrok, Resend, or Clerk).

---

## 10. Concrete API Surfaces & Framework Integration

### 10.1 Crate Mappings & Rust Signatures

In `authkestra-mcp`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum McpSecurityTier {
    Public,
    Scoped,
    HumanApproved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub challenge_id: Uuid,
    pub session_id: String,
    pub tool_name: String,
    pub parameter_digest: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionToken {
    pub token_id: Uuid,
    pub challenge_id: Uuid,
    pub parameter_digest: String,
    pub signature: Vec<u8>,
}
```

In `authkestra-axum`:
```rust
// Guarding an MCP tool endpoint with Cedar policy and human step-up approval
pub async fn execute_mcp_tool(
    guard: McpToolGuard,
    State(engine): State<Arc<CedarPolicyEngine>>,
    Json(payload): Json<ToolInvocationRequest>,
) -> Result<Json<ToolInvocationResponse>, McpError> {
    guard.verify_execution(&payload, &engine).await?;
    let result = invoke_tool(&payload.name, payload.arguments).await?;
    Ok(Json(result))
}
```

### 10.2 Relay REST & SSE API Surface

- `POST /v1/challenges`: Create pending out-of-band step-up challenge.
- `GET /v1/challenges/:challenge_id`: Fetch public challenge metadata for display in the mobile browser.
- `POST /v1/challenges/:challenge_id/verify`: Submit WebAuthn assertion response (`authenticatorData`, `clientDataJSON`, `signature`).
- `GET /v1/challenges/:challenge_id/events`: SSE stream emitting `approved`, `rejected`, or `expired`.
- `POST /v1/broker/dispense`: Exchange valid execution token for scoped downstream credential or proxied execution.

---

## 11. Out of Scope / Deferred

1. **Direct Agent Execution Sandboxing**: `relay.authkestra.com` relays authentication and brokers credentials; it does not execute arbitrary Docker containers or sandbox agent LLM reasoning loops.
2. **First-Party SMS / Voice OTP Delivery for Relay**: The hosted relay relies on WebAuthn passkeys (FIDO2/WebAuthn) for high-assurance step-up. SMS fallback is explicitly omitted to avoid SIM-swap vulnerabilities.
3. **Decentralized / Blockchain Key Storage**: Key management relies on proven WebAuthn secure enclaves and AWS KMS; blockchain-based decentralized identity is deferred.

---

## 12. Open Questions

1. **Push Notification Channel for Mobile Devices**:  
   *Question*: Should the Relay integrate Apple APNs and Google FCM directly to send push notifications to a user's mobile device when a headless agent requests approval, or is standard QR code scanning and desktop URL opening sufficient for Phase 5?  
   *Current consensus*: Begin with QR code and browser link (universally supported without custom mobile apps); introduce an optional companion PWA with Web Push in Phase 5.2.

2. **WebAuthn Credential Registration for Out-of-Band Approvers**:  
   *Question*: How does the user register their passkey with `relay.authkestra.com` without creating a full user account?  
   *Current consensus*: Pairing ceremony during initial developer setup: `authkestra relay pair` outputs a QR code; scanning it registers the phone's passkey and links its public key to the developer's API key ID without storing personal identity.

---

*RFC-013 is submitted for implementation in `authkestra-playground` v0.13 upgrade and commercial deployment planning.*
