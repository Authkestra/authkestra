# RFC-014: Device-signature profile v1

> **Status: proposed.** Implemented in `authkestra-devsig`, `authkestra-axum` and
> `authkestra-actix` (`devsig` feature) by the PR that adds this file; accepted when a
> maintainer says so on the profile epic. The conformance vectors are
> [`conformance/devsig-profile-v1/vectors.json`](../conformance/devsig-profile-v1/vectors.json).

## 1. Summary

`authkestra-devsig` verifies a device-signed request: an `X-Signature` JWS signed by a key that
never leaves the device, and an `X-Attestation` JWS from an issuer binding that key's RFC 7638
thumbprint to an identity (#137; the issuer side is `authkestra-op`'s attestation ceremony, #136).
Two client projects implement the same scheme: fespalier's `fespalier_sign_keypair` (Dart, the
client and a reference verifier) and CrateStack's device-signature provider
(`examples/auth-pluggable`). The request signature agrees across the three; everything around it
did not — the refusal body, the `att` claim, the issuer algorithms, the code names, the edge cases.

This RFC writes that "everything around it" down once, as **profile v1**, and ships the vectors
that pin it. Client projects vendor the vectors by commit; nobody has to read another project's
code to find out what a refusal looks like.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 2. Motivation

What each project did, at Authkestra `9d40169`, fespalier `a9bd33e`, CrateStack `3278bf7`:

| | Authkestra | fespalier | CrateStack example |
| --- | --- | --- | --- |
| Refusal body | plain text `key_not_bound` | JSON `{"error": code}` | JSON, re-shaped by the provider |
| `att` | object, `status` required | a key-role string (example server); top-level `status` (test issuer) | reads `att.roles` |
| Issuer algs | HS256*, RS256, EdDSA with `kid` | ES256, no `kid` | Authkestra's |
| Replay code | `replay_detected` | `replay` | Authkestra's |
| Binding codes | `method_mismatch`, `path_mismatch`, … | one `mismatch` | Authkestra's |
| Stray `qsh`/`bdh` | accepted | refused | Authkestra's |
| Empty header | `malformed` | missing | Authkestra's |

\* `authkestra-op` can mint HS256 attestations; `authkestra-devsig` has always refused them.

The consequence: a fespalier client talking to an Authkestra server read every refusal as
ambiguous — it never renewed an expired attestation and never signed out on a key that is not
bound. Each project's tests passed, because each tested against fixtures it minted itself.

## 3. Credentials

### 3.1. Headers

| Header | Content |
| --- | --- |
| `X-Signature` | the request signature, a compact JWS |
| `X-Attestation` | the attestation, a compact JWS, sent unchanged on every request |

A server MAY use other header names (both adapters take them as configuration); the vectors use
these. **An empty header value is an absent credential.**

### 3.2. Request signature

A compact JWS with all three segments (the claims travel in the payload; see
`authkestra-devsig/src/signature.rs` for why a detached payload cannot work).

- Protected header: `alg` and `jwk` (the device's **public** key). `typ` MAY be present and is
  ignored.
- `alg`: clients MUST sign **ES256**. Verifiers MUST accept ES256 and MAY accept EdDSA (Ed25519,
  verified strictly). `none`, every HMAC algorithm and RSA are refused (`bad_alg`).
- `jwk` MUST NOT carry a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`); its type MUST match
  `alg` (`bad_jwk`).

| Claim | Value |
| --- | --- |
| `iat`, `exp` | seconds; `exp - iat` ≤ 300 |
| `jti` | unique per send, retries and replays included |
| `mth` | the HTTP method, upper case |
| `pth` | the path exactly as sent — percent-encoding included, query excluded; an empty path is `/` |
| `qsh` | lower-case hex SHA-256 of the raw query string (no `?`); **present exactly when the request has a non-empty query** |
| `bdh` | lower-case hex SHA-256 of the exact body bytes; **present exactly when the request has a non-empty body** |
| `aud` | the API the signature is for |

A request URL that ends in a bare `?` has no query. A zero-length body is no body.

**A hash on one side only is a mismatch.** A `qsh` with no query, or a `bdh` with no body, means
what the device signed is not what arrived: the body (or query) was stripped in transit. Accepting
it would let a captured signed write be replayed as an empty one while its `jti` is still fresh.

### 3.3. Attestation

- Protected header: `alg` and **`kid`** (both REQUIRED). `typ` MAY be present and is ignored
  (`authkestra-op` sets `webank-attest+jws`).
- `alg`: verifiers MUST accept **ES256, EdDSA and RS256** for the issuer, each resolved by `kid`
  in the issuer's JWKS. HMAC is never accepted: an attestation is verified by services that must
  not be able to mint one.

| Claim | Value |
| --- | --- |
| `iss` | the issuer, one the verifier trusts |
| `sub` | the identity the device belongs to |
| `did` | the device |
| `iat`, `exp` | the attestation's validity |
| `cnf.jkt` | RFC 7638 SHA-256 thumbprint of the device's public JWK, computed by the issuer |
| `att` | **a JSON object** (anything else is `malformed`) |
| `principal_type` | OPTIONAL, `device` or `service` (`authkestra-op` sets it) |

`att` members defined by the profile:

| Member | |
| --- | --- |
| `status` | REQUIRED, string. Only `"active"` is accepted; anything else, or absent, is `device_not_active`. |
| `role` | OPTIONAL, string. `"user_present"`: the key whose every use is gated by the platform (a biometric or the device credential). Absent, `"ambient"`, or **any other value**: the ambient key, which never prompts. |

Every other member of `att` belongs to the application (`kyc_level`, `roles`, …) and is surfaced
unchanged (`DeviceIdentity::attributes`).

*Why `role` is lenient.* `att.role` was already used by applications for their own roles (the
`DeviceIdentity::new` doc example uses `"user"`). Reading only the exact `"user_present"` as the
user-present key means an existing value can never be mistaken for a presence proof, and those
applications keep working. A value this crate does not understand degrades to the key with the
fewest privileges. (Alternative considered: a dedicated `key_role` member. Rejected for v1 because
both client projects already read `role`; open for review.)

## 4. Verification

The order is `authkestra-devsig`'s (#137) and is unchanged by this profile: presence; parse and
`alg` for both credentials; attestation trust (issuer, `kid`, signature, validity, `att.status`);
**the binding** (the embedded `jwk`'s thumbprint equals `cnf.jkt`, constant-time); the request
signature; freshness; request binding (`mth`, `pth`, `aud`, `qsh`, `bdh`); replay, recorded last
and failing closed. The first failing check decides the refusal.

Tolerances: a clock skew of **30 s** applied to both credentials, and a longest signature of
**300 s** (`VerifierConfig::profile_v1`). The vectors stay well away from both boundaries, so an
implementation with a slightly different boundary rule still agrees on every vector.

## 5. Refusals

A refused request is answered with:

- the status in the table below;
- `Content-Type: application/json` and the body **exactly** `{"error":"<code>"}` — no
  credential, no detail beyond the code (a server MAY add members; clients read `error` only);
- for every `401`, `WWW-Authenticate: DeviceSignature error="<code>"` (RFC 6750 §3 syntax).

The client action is what a client SHOULD do; it is the contract fespalier's
`webankRefusals` and CrateStack's provider implement.

| Code | Status | Client action | Produced by |
| --- | --- | --- | --- |
| `missing_credential` | 401 | key lost: sign out | verifier |
| `malformed` | 401 | none | verifier |
| `bad_alg` | 401 | none | verifier |
| `untrusted_issuer` | 401 | none | verifier |
| `unknown_kid` | 401 | renew the attestation, once | verifier |
| `bad_attestation` | 401 | none | verifier |
| `attestation_expired` | 401 | renew the attestation, once | verifier |
| `device_not_active` | 401 | renew the attestation, once (re-issuance says whether it is revoked) | verifier |
| `bad_jwk` | 401 | key lost: sign out | verifier |
| `key_not_bound` | 401 | key lost: sign out | verifier |
| `bad_signature` | 401 | none | verifier |
| `signature_expired` | 401 | none | verifier |
| `lifetime_too_long` | 401 | none | verifier |
| `method_mismatch`, `path_mismatch`, `audience_mismatch`, `query_mismatch`, `body_mismatch` | 401 | none | verifier |
| `replay_detected` | 401 | none | verifier |
| `body_too_large` | 413 | none | adapter |
| `device_revoked` | 403 | revoked: sign out, wipe | application |
| `insufficient_user_authentication` | 401 | step up: re-sign this request with the user-present key, once | application |

"None" means the refusal stands: the client neither renews nor signs out, and does not loop.

- `unknown_kid` renews because the usual cause is an issuer key rotation; a client retries at most
  once, so a verifier with a stale JWKS cannot cause a loop.
- `missing_credential` signs out because the client knows it sent both headers: a server that did
  not receive them is not one the session can recover with. This is fespalier's existing rule,
  kept.
- `replay_detected` covers an unreachable replay store too (fail closed); the two are deliberately
  indistinguishable on the wire and distinguishable in the server's logs.
- `device_revoked` and `insufficient_user_authentication` are never produced by `verify()`: an
  attestation cannot say "revoked since it was issued", and the verifier does not know which
  routes need the user-present key. An application answers them with
  `authkestra_devsig::Refusal::device_revoked()` /
  `Refusal::insufficient_user_authentication()`, rendered by each adapter's
  `devsig::refusal_response`, after checking its own revocation state or
  `DeviceIdentity::key_role()`.

**Legacy names.** Clients SHOULD keep reading the names they shipped with: `replay` as
`replay_detected`, `mismatch` as any `*_mismatch`, and `DEVICE_REVOKED` (any case) as
`device_revoked`. Servers MUST send the canonical names.

## 6. Enrolment and renewal

Profile v1 documents the issuer side as `authkestra-op` serves it today
(`authkestra-axum`/`authkestra-actix` `op_*_attestation_router`); changing it is follow-up work on
the profile epic.

| Step | Request | Response |
| --- | --- | --- |
| `POST /enrol` | `{subject, principal_id, principal_type, public_jwk, attributes, second_factor: {kind, value}}` | `{challenge, expires_in}` |
| `POST /reissue` | `{attestation, public_jwk}` (the still-valid attestation and the key it binds) | `{challenge, expires_in}` |
| `POST /enrol/complete` | `{challenge, challenge_signature}` (a JWS over `{"challenge": "<challenge>"}` by the new key) | `{attestation, expires_in, reissue_after}` |

- The second factor is checked in `/enrol`, before a challenge is issued.
- One key per ceremony. A device with two keys (ambient and user-present) enrols twice; until the
  OP mints `att.role` itself, the host's `attributes` carry it. *(follow-up)*
- `/reissue` needs the current attestation and the JWK, so a client renews before `exp`, at
  `reissue_after`. A client whose attestation already expired enrols again.
- A principal the host's `AttestationStatusProvider` reports inactive is refused at `/reissue` with
  `403`. Today the body is the OAuth-shaped `{"error": "access_denied", …}`; profile v1's
  `device_revoked` there is a follow-up. Clients SHOULD read a `403` from `/reissue` as revoked.

## 7. Conformance vectors

`conformance/devsig-profile-v1/vectors.json` holds the verifier configuration, the issuer's public
keys, the refusal table above, the legacy aliases, and 44 vectors (43 required; the EdDSA device
key is optional). Each vector is a request (method, path, query, body, headers), the replay state
(`seen_jtis`, or an unavailable store), the instant `now` it is checked at, and the expected
verdict: the identity (`sub`, `did`, `jkt`, `role`) or the refusal (status, error, body,
challenge).

The file is generated by `crates/authkestra-devsig/tests/profile_v1.rs` from fixed test keys with
deterministic signatures, and the same test fails when the committed file is stale and runs every
vector against `authkestra_devsig::verify_at`. The expectations are written by hand in the
generator, never computed from the verifier.

Other projects copy the file, pinned by commit, and run every vector through their own verifier
(see the README next to it).

## 8. Breaking changes

Pre-1.0, called out here so a consumer can find them:

1. **Refusal bodies** from `DeviceSignatureLayer` (axum) and `DeviceSignatureAuth` (actix) are
   JSON `{"error":"<code>"}` with `Content-Type: application/json`, plus a `WWW-Authenticate`
   challenge on a `401`. They were plain text (the bare code). The statuses are unchanged.
2. **A stray `qsh` or `bdh` is refused** (`query_mismatch` / `body_mismatch`). It was accepted.
3. **A non-object `att`** is `malformed`. It was `device_not_active`.
4. **An empty `X-Signature`/`X-Attestation`** is `missing_credential`. It was `malformed`.
5. `VerifierConfig` gains a `device_algs` field (the struct is `#[non_exhaustive]`; `new` sets it
   to `None`, which keeps the old behaviour of one list for both credentials).

New, non-breaking: `verify_at`, `VerifierConfig::profile_v1` / `with_device_algs` /
`device_algs()`, `KeyRole`, `DeviceIdentity::key_role`, `Refusal`, `VerifyError::refusal`, the
profile constants, and each adapter's `devsig::refusal_response`.

## 9. Not in v1

- Hardware attestation (Play Integrity, App Attest).
- A per-request revocation hook inside `verify()`; applications answer `device_revoked` themselves.
- The OP minting key roles, and `device_revoked` at `/reissue` (§6).
