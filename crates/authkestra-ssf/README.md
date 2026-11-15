# authkestra-ssf

Shared Signals Framework ingestion for the `authkestra` framework: validate Security Event Tokens
([RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)), decode typed
[OpenID CAEP 1.0](https://openid.net/specs/openid-caep-specification-1_0.html) events, and receive
them over the [RFC 8935](https://www.rfc-editor.org/rfc/rfc8935) HTTP push delivery method.

Part of [authkestra#25](https://github.com/Authkestra/authkestra/issues/25).

## Status

| Capability | Status |
| --- | --- |
| SET parsing and validation — `typ`, `alg` allow-listing, signature, issuer, audience, `iat` freshness, optional max age, `exp` when present, non-empty `events`, `jti` replay | done (`SetVerifier`) |
| RFC 9493 subject identifiers (`iss_sub`, `email`, `opaque`, `phone_number`, everything else preserved) | done (`SubjectIdentifier`) |
| Typed CAEP 1.0 events: session revoked, token claims change, credential change, assurance level change, device compliance change — unknown event types preserved, never dropped | done (`CaepEvent`) |
| RFC 8935 push delivery semantics: 202, or 400 with a registered `err` code | done (`PushReceiver`) |
| Revoking or attenuating a live session when an event arrives | **not implemented** |
| Middleware that rejects tokens invalidated by a CAEP event | **not implemented** |
| Axum / Actix route wiring | **not implemented** |

The last three rows are follow-up work. Until they land, a `SetHandler` implementation is where a
deployment plugs in its own reaction to an event; the events themselves are fully validated and
decoded.

## Usage

```rust,ignore
use std::sync::Arc;
use std::time::Duration;

use authkestra_ssf::{InMemorySetReplayGuard, LoggingHandler, PushReceiver, SetVerifier};
use jsonwebtoken::{Algorithm, DecodingKey};

let verifier = SetVerifier::builder("https://idp.example.com/")
    .audience("https://sp.example.com/caep")
    .algorithms([Algorithm::EdDSA])
    .key(transmitter_key)
    .max_age(Duration::from_secs(60 * 60))
    .replay_guard(Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(60 * 60))))
    .build()?;

let receiver = PushReceiver::new(Arc::new(verifier)).with_handler(Arc::new(LoggingHandler));

// From your HTTP handler: pass the Content-Type header and the raw body through.
let response = receiver.receive(content_type, body).await;
// -> response.status(), response.content_type(), response.content_language(), response.body()
```

For a transmitter that rotates keys, implement `SetKeyResolver` over your JWKS cache and pass it
to `.key_resolver(...)` instead of `.key(...)`.

## Framework integration

There is none in this crate, on purpose: per the workspace `AGENTS.md` "Framework Agnostic" rule,
`PushReceiver::receive` takes a content type and a byte slice and returns a `PushResponse`
describing the status, headers and body to send. Turning that into an axum or actix route is a
handful of lines today and a dedicated adapter feature in a follow-up PR.

## Notable behaviours worth knowing before you deploy

- **A retransmitted SET is answered `202`, not `400`.** RFC 8935 §2 requires the recipient to
  respond to a repeat transmission exactly as it would to a first one. The replay guard therefore
  suppresses handler dispatch, not the acknowledgement.
- **Event payloads are decoded during verification, not after it.** `SetVerifier::verify` returns
  a `VerifiedSet { set, events }`, and a modelled event whose payload does not conform is refused
  *before* the `(iss, jti)` replay slot is taken. Decoding afterwards would burn the `jti` on a
  SET that is then rejected, so the transmitter's corrected retransmission under the same `jti`
  would come back `202` from the replay path and never reach a handler.
- **Failure descriptions never echo your configuration.** The RFC 8935 §2.3 `description` goes to
  an unauthenticated caller — the push endpoint has no authentication of its own — so the
  configured issuer, the accepted audiences, the clock leeway and the maximum accepted age stay
  out of it. All of them are logged as structured tracing fields instead.
- **`alg: none` is rejected by name**, before any typed parsing, because RFC 8417 §2.4's own
  worked example is an unsecured JWT.
- **Explicit typing is required.** RFC 8417 §2.3 makes `typ: secevent+jwt` conditional; a
  general-purpose receiver is exactly the "could be confused with other kinds of JWTs" context
  that condition names, so this crate requires it. Both `secevent+jwt` and
  `application/secevent+jwt` are accepted, case-insensitively.
- **`exp` is optional and honoured; `nbf` is parsed and ignored.** RFC 8417 §2.2 says `exp` is NOT
  RECOMMENDED in a SET and never profiles `nbf` at all.
- **An empty or whitespace-only `jti` is refused** with `400 invalid_request`. RFC 8417 §2.2 makes
  `jti` the SET's unique identifier; an empty one identifies nothing, and accepting it would
  collapse the replay guard to a single slot per issuer so that the first such SET permanently
  suppressed every later one.
- **The request body is size-capped** at `DEFAULT_MAX_BODY_BYTES` (1 MiB), configurable with
  `PushReceiver::with_max_body_bytes`. This is a *second* line of defence: by the time `receive`
  is called the body is already in memory, so set your framework's own limit (axum's
  `DefaultBodyLimit`, actix's `PayloadConfig`, or the proxy's `client_max_body_size`) too.
- **Handlers run before the response.** This crate has no store of its own, so a handler *is* the
  persistence step RFC 8935 §2 asks for before acknowledging. Enqueue-and-return inside a handler
  if you want the RFC's asynchronous shape.
- **Handlers must be idempotent.** A `HandlerError::Internal` answers 500 and releases the SET's
  replay slot so the transmitter's retry is genuinely dispatched rather than acknowledged as a
  duplicate — which means the retry re-runs *every* handler for *every* event in the SET,
  including the handlers that already succeeded before the one that failed. A
  `HandlerError::Rejected` (400) keeps the slot, because the transmitter is not going to retry.
  One window stays open by design: a concurrent duplicate arriving between the record and the
  release is answered 202 without dispatch, but the retry of the failed delivery still delivers
  the event, so nothing is lost.
- **The public models are `#[non_exhaustive]` but constructible.** `SecurityEventToken::new`,
  `TokenClaimsChange::new`, `CredentialChange::new`, `AssuranceLevelChange::new`,
  `DeviceComplianceChange::new`, `CaepMetadata::empty` and `SessionRevoked::default` exist so a
  downstream crate can build fixtures for its own tests without minting and verifying a real SET
  (the problem reported for `devsig`'s `DeviceIdentity` in authkestra#282). None of them validate
  anything.

## License

Licensed under either of MIT or Apache-2.0 at your option.
