# Chapter 6: Adapters and Integrations

To be truly framework-agnostic, the core engine must not know about HTTP requests or specific database connections. Adapters bridge this gap. Our architecture strictly separates interfaces from implementations—for example, `authkestra-engine`'s `store` module defines the `KvStore`/`SessionStore` contracts unconditionally, while the implementations plug in dynamically via feature flags (e.g., `memory`, `redis`).

## Web Framework Adapters

We provide first-class integration layers for:

- **Axum** (`authkestra-axum`)
- **Actix Web** (`authkestra-actix`)

These are not just loose helpers, but robust, native-feeling extensions providing middleware, extractors, and routing guards. Each maps the engine's framework-neutral results — an `Identity`, a `Session`, a `Claims` — into the framework's own request and response types, via extractors (`AuthSession`, `AuthToken`, `Auth<I>`, `Jwt<T>`) and pre-wired routers (`axum_router()` / `actix_scope()`).

### Supported Session Providers

All three live in `authkestra-engine`'s `store` module, behind features on that crate:

- **Memory** (`memory` feature) for local development.
- **Redis** (`redis` feature) via `redis-rs`.
- **SQL** (`sql-postgres`, `sql-mysql`, `sql-sqlite` features) for Postgres, MySQL and SQLite.

## Database Adapters

For session and protocol state, adapters rely strictly on traits (`SessionStore`, `KvStore`, `CredentialStore`), so you can plug an existing database straight in via a feature-flagged implementation or your own. User and account records are **not** among them — see Chapter 2.

## Device-Bound Signature Authentication (`authkestra-devsig`)

`authkestra-devsig` is a fourth request-authentication family, alongside OAuth/OIDC, sessions,
and Basic: per-request proof of possession of a device-bound private key, with the public key
and its identity binding travelling in the request itself (an `X-Signature` JWS signed by the
device, plus an `X-Attestation` JWS signed by the Issuer binding that key to an identity).
Verification needs no session store, no token introspection, and no per-request network call —
any service holding a cached Issuer JWKS can verify a request independently. See
[authkestra#137](https://github.com/marcjazz/authkestra/issues/137) for the original proposal.

Per the "Framework Agnostic" rule above, `authkestra-devsig` itself ships only the plain
`verify()` function and the types it needs — it does not depend on axum, actix, or any other web
framework. Framework wiring lives in the adapter crates, following the same "extractors vs
middleware" split as the rest of this chapter:

- **Axum** (`authkestra-axum`, `devsig` feature): `DeviceSignatureLayer` is a `tower::Layer` that
  buffers the request body ahead of axum's own extraction (needed for the `bdh` body-hash
  check), calls `authkestra_devsig::verify`, and injects the verified identity into request
  extensions on success — or short-circuits with `401`/`413` on failure, answering in
  device-signature profile v1's shape (a JSON body `{"error": "<code>"}` and a
  `WWW-Authenticate: DeviceSignature` challenge; see `docs/rfc-014-devsig-profile-v1.md`). The
  `AuthDeviceSignature` extractor reads that identity back out via `FromRequestParts`. See
  `crates/authkestra/examples/axum_devsig/` for a runnable example.
- **Actix Web** (`authkestra-actix`, `devsig` feature): `DeviceSignatureAuth` is the equivalent
  `actix_web::dev::Transform` middleware, with an `AuthDeviceSignature` extractor implementing
  `FromRequest`. See `crates/authkestra/examples/actix_devsig/` for a runnable example.

Both adapters buffer the whole body before verification (never just streaming it through) —
buffering is a deliberate, explicitly-capped memory trade-off, because the `bdh` check needs the
complete body to hash it. Both wrap `authkestra_devsig::DeviceIdentity` in a small newtype
(`AuthDeviceSignature`) rather than implementing the framework's extractor trait directly on it:
`DeviceIdentity` is defined in `authkestra-devsig` and the extractor trait (`FromRequestParts` /
`FromRequest`) is defined in axum/actix, so neither is local to the adapter crate — Rust's
orphan rules require the impl to live on a type the adapter crate owns instead.

Neither adapter implements `authkestra-engine`'s `AuthenticationStrategy<I>` today: that trait's
`authenticate(&self, parts: &Parts)` only ever sees header/URI data, never the body, so it
cannot express the `bdh` check without silently skipping it — not a reasonable default for a
scheme designed to protect write requests. Migrating either adapter to a body-aware
`authkestra-engine` trait, if one is added, is a matter of swapping which caller builds a
`SignedRequest` and calls `verify()`; the verification algorithm itself does not change.

## Device/Service Attestation Issuance (OP)

Beyond the standard OIDC provider surface, `authkestra-op` (behind the `op`
feature) can issue **device/service attestations**: short-lived,
`cnf.jkt`-bound JWS tokens that let a mobile device or backend service prove
possession of a key it enrolled, without a bearer token ever leaving the
device. This is the Issuer side of the device-bound-signature authentication
method. Three handlers, framework-agnostic in `authkestra-op`, are wired
into both adapters:

| Route | Purpose |
|---|---|
| `POST /enrol` | Validate the caller's public key and second factor, issue a single-use proof-of-possession challenge. |
| `POST /enrol/complete` | Consume the challenge, verify the signature was produced by the enrolled key, compute `cnf.jkt` from that key (never from caller input), and mint the attestation. |
| `POST /reissue` | Silently renew a near-expiry attestation by re-proving possession of the same key — no second factor required, since continuity of the key stands in for it. |

Both `authkestra-axum` and `authkestra-actix` wire these three routes with
the same `tracing` instrumentation the rest of each adapter's handlers use.

**Axum** exposes them through a router split from the main OIDC router
rather than folded into it, so an application that only wants standard OIDC
never has to supply attestation-specific dependencies just to keep
compiling:

```rust,ignore
let app = Router::new()
    .merge(state.op_axum_router())              // /authorize, /token, /userinfo, ...
    .merge(state.op_axum_attestation_router())   // /enrol, /enrol/complete, /reissue
    .with_state(state);
```

**Actix** wires the same three routes via `OpExt::op_actix_scope()`,
resolving each dependency (`EnrolmentChallengeStore`, `SecondFactorVerifier`,
`TokenManager`, `AttestationConfig`) from `app_data` — an application that
has not registered the optional `AttestationStatusProvider` simply gets
`None` at the extractor, exactly like Axum's `Option<Arc<dyn
AttestationStatusProvider>>: FromRef<AppState>`.

The ceremony has two pluggable hooks a host application implements, since
`authkestra-op` deliberately does not hardcode a telecom integration or an
attribute/revocation store:

- **`SecondFactorVerifier`** — verifies whatever proof the caller submits at
  enrolment (SMS/TOTP for a device; an out-of-band admin approval or
  one-time bootstrap secret for a service principal).
- **`AttestationStatusProvider`** *(optional)* — supplies current
  attributes at re-issuance time, and can refuse re-issuance outright for a
  revoked principal. If not configured, re-issuance falls back to copying
  the previous attestation's attributes forward, still bound by
  proof-of-possession.

The enrolment-challenge store itself is just another `EnrolmentChallengeStore`
trait — implemented as a blanket impl over any `KvStore` + `AtomicConsume`
backend, so Redis/SQL/in-memory all work via the same mechanism session and
OP data already use elsewhere in this chapter.

See `crates/authkestra/examples/axum_op_server_attestation.rs` and
`crates/authkestra/examples/actix_op_server_attestation.rs` for a
self-contained, runnable walkthrough of enrolment and re-issuance end to end
(no external services required — the challenge store is an in-memory
`MemoryStore` for the example).

### Architectural Decisions & Future Direction

- **Extractors vs Middleware:** In Axum and Actix, both serve different purposes and we must provide both. Custom extractors (`async fn handler(user: Identity)`) provide the best developer experience (DX) for route-specific logic. Middleware is better suited for global URL protection rules.
- **Database Schema:** Enforcing a specific database schema is a fatal mistake that alienates 90% of developers who have existing databases. So persistence is expressed as traits (`KvStore`/`SessionStore`, `CredentialStore`, `authkestra-op`'s `OpStore`) that you map onto your existing tables, rather than migrations we impose. Note this stops short of user data: there is no `UserStore` trait, because Authkestra does not own the `users` table at all — see Chapter 2, "The Identity Handoff".
