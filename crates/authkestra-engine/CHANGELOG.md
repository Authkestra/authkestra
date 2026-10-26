# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.2](https://github.com/Authkestra/authkestra/compare/authkestra-engine-v0.13.1...authkestra-engine-v0.13.2) - 2026-10-26

### Added

- *(mcp)* add authkestra-mcp crate, Axum/Actix adapters, and AI agent security ([#415](https://github.com/Authkestra/authkestra/pull/415))

## [0.13.1](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.13.0...authkestra-engine-v0.13.1) - 2026-09-26

### Other

- give every published crate its own crates.io keywords/categories ([#412](https://github.com/marcjazz/authkestra/pull/412))

## [0.13.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.12.0...authkestra-engine-v0.13.0) - 2026-09-23

### Added

- *(engine)* magic-link authentication behind a feature flag ([#400](https://github.com/marcjazz/authkestra/pull/400))

### Fixed

- *(op)* make the amr pass-through a decision, not a default ([#396](https://github.com/marcjazz/authkestra/pull/396))

### Other

- Bring the READMEs up to v0.13 ([#409](https://github.com/marcjazz/authkestra/pull/409))
- Recovery codes as a look-up secret authenticator ([#404](https://github.com/marcjazz/authkestra/pull/404))
- An opt-in resend cooldown for one-time codes ([#406](https://github.com/marcjazz/authkestra/pull/406))
- A conformance suite for CredentialStore ([#405](https://github.com/marcjazz/authkestra/pull/405))
- Email and SMS one-time codes ([#402](https://github.com/marcjazz/authkestra/pull/402))

## [0.12.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.11.1...authkestra-engine-v0.12.0) - 2026-09-19

### Other

- Gate factor enrolment behind a fresh re-proof of identity ([#392](https://github.com/marcjazz/authkestra/pull/392))

## [0.11.1](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.11.0...authkestra-engine-v0.11.1) - 2026-09-15

### Added

- *(policy)* Cedar policy engine proof of concept + RFC-005 ([#310](https://github.com/marcjazz/authkestra/pull/310))
- *(ssf)* ingest and validate Security Event Tokens (RFC 8417) with typed CAEP events ([#309](https://github.com/marcjazz/authkestra/pull/309))

## [0.11.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.10.2...authkestra-engine-v0.11.0) - 2026-09-14

### Added

- *(engine)* [**breaking**] make Flow trait GNAP-shaped (RFC-004 §11) ([#371](https://github.com/marcjazz/authkestra/pull/371))

### Fixed

- *(engine)* de-feature token — always compile token machinery in ([#377](https://github.com/marcjazz/authkestra/pull/377))
- *(engine)* [**breaking**] remove authkestra-engine's no-op `session` feature ([#375](https://github.com/marcjazz/authkestra/pull/375))

### Other

- Add acr/amr claims to authkestra-op's issued ID tokens ([#380](https://github.com/marcjazz/authkestra/pull/380))

## [0.10.1](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.10.0...authkestra-engine-v0.10.1) - 2026-09-14

### Fixed

- two Jwk test fixtures missed the r#use/key_ops fields from #342 ([#372](https://github.com/marcjazz/authkestra/pull/372))

## [0.10.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.9.5...authkestra-engine-v0.10.0) - 2026-09-14

### Fixed

- *(engine)* [**breaking**] enforce JWKS key-use separation when selecting a verification key ([#342](https://github.com/marcjazz/authkestra/pull/342))

## [0.9.5](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.9.4...authkestra-engine-v0.9.5) - 2026-09-13

### Other

- Move the docs out, put a landing page in their place ([#362](https://github.com/marcjazz/authkestra/pull/362))

## [0.9.3](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.9.2...authkestra-engine-v0.9.3) - 2026-09-07

### Added

- instrument the token-validation path, and fix flaky log-capture tests ([#358](https://github.com/marcjazz/authkestra/pull/358))
- *(engine)* instrument the authentication path ([#354](https://github.com/marcjazz/authkestra/pull/354))
- *(engine)* name and expose the clock-skew leeway JWT validation applies ([#351](https://github.com/marcjazz/authkestra/pull/351))

### Fixed

- *(engine)* state the MFA continuation token's clock-skew window ([#352](https://github.com/marcjazz/authkestra/pull/352))
- *(engine)* wait on a timer in DeviceFlow::poll_for_token instead of blocking ([#343](https://github.com/marcjazz/authkestra/pull/343))

## [0.9.1](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.9.0...authkestra-engine-v0.9.1) - 2026-09-06

### Fixed

- *(engine)* derive a stable WebAuthn user handle instead of a random one ([#334](https://github.com/marcjazz/authkestra/pull/334))

### Fixed

- *(engine)* WebAuthn `start_register` no longer substitutes a random UUID for the user handle when
  the application's `user_id` is not UUID-shaped. The handle is now derived deterministically with
  the new `auth::webauthn::derive_user_handle`: a `user_id` that already parses as a UUID is used
  verbatim (byte-identical to previous behaviour), and anything else is hashed into a UUIDv5 over
  the documented `auth::webauthn::USER_HANDLE_NAMESPACE`. Previously, an application with non-UUID
  user ids got a different, unstable handle on every registration, which silently broke discoverable
  ("usernameless") sign-in ([#333](https://github.com/marcjazz/authkestra/issues/333)).

  **This change is additive and does not re-map existing credentials.** A user handle is stored
  inside the authenticator at registration time and cannot be rewritten server-side, so passkeys
  already enrolled under a random handle keep that handle and must be re-enrolled to gain a stable
  one. Applications with UUID user ids are unaffected.

### Added

- *(engine)* `auth::webauthn::WebAuthnAuthMethod::start_register_with_handle`, for applications that
  allocate WebAuthn user handles themselves or need a display name distinct from the username
  (`start_register` passes the username for both).
- *(engine)* `auth::webauthn::derive_user_handle` and `auth::webauthn::USER_HANDLE_NAMESPACE`, so an
  application can reproduce the same handle out-of-band and index credentials by it.

## [0.9.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.8.1...authkestra-engine-v0.9.0) - 2026-09-05

### Fixed

- *(engine)* [**breaking**] replace stale TOTP secret on re-enrollment instead of accumulating it ([#330](https://github.com/marcjazz/authkestra/pull/330))

## [0.8.1](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.8.0...authkestra-engine-v0.8.1) - 2026-09-04

### Other

- Generate an OAuth2 nonce only when the provider validates one ([#318](https://github.com/marcjazz/authkestra/pull/318))

## [0.8.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.7.2...authkestra-engine-v0.8.0) - 2026-09-03

### Other

- Merge next into main: storage rework, DPoP, PKCE/scope hardening ([#300](https://github.com/marcjazz/authkestra/pull/300))

## [0.7.2](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.7.1...authkestra-engine-v0.7.2) - 2026-09-03

### Other

- refresh engine guides, provider docs and the book against current code ([#305](https://github.com/marcjazz/authkestra/pull/305))

## [0.7.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.6.3...authkestra-engine-v0.7.0) - 2026-08-31

### Fixed

- *(engine)* [**breaking**] reject `extra` keys that collide with named Claims fields ([#284](https://github.com/marcjazz/authkestra/pull/284))

### Other

- add coverage for auth strategies and flow orchestration ([#297](https://github.com/marcjazz/authkestra/pull/297)) ([#298](https://github.com/marcjazz/authkestra/pull/298))
- Merge next into main (DPoP, migrations, and fixes) ([#292](https://github.com/marcjazz/authkestra/pull/292))

## [0.6.2](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.6.1...authkestra-engine-v0.6.2) - 2026-08-28

### Other

- correct API drift across README, crate docs, website and book ([#269](https://github.com/marcjazz/authkestra/pull/269))

## [0.6.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.5.5...authkestra-engine-v0.6.0) - 2026-08-27

### Fixed

- *(crypto)* [**breaking**] harden authkestra-resource and authkestra-op against low-order Ed25519 keys ([#261](https://github.com/marcjazz/authkestra/pull/261))
- *(oidc)* [**breaking**] accept array-valued `aud` in ID tokens and verify `azp` ([#244](https://github.com/marcjazz/authkestra/pull/244)) ([#251](https://github.com/marcjazz/authkestra/pull/251))

### Other

- massive sweep to add non_exhaustive to all public structs ([#259](https://github.com/marcjazz/authkestra/pull/259))

## [0.5.5](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.5.4...authkestra-engine-v0.5.5) - 2026-08-24

### Added

- *(engine)* SD-JWT (selective disclosure) issuance and verification ([#238](https://github.com/marcjazz/authkestra/pull/238))

### Fixed

- *(engine)* gate webauthn-only test and totp_webauthn example on their features ([#240](https://github.com/marcjazz/authkestra/pull/240))

### Other

- *(engine)* add SD-JWT runnable example, doctests, and book/README docs ([#241](https://github.com/marcjazz/authkestra/pull/241))

## [0.5.4](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.5.3...authkestra-engine-v0.5.4) - 2026-08-24

### Added

- *(op)* RFC 8705 certificate-bound access tokens for client_credentials ([#231](https://github.com/marcjazz/authkestra/pull/231))

## [0.5.3](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.5.2...authkestra-engine-v0.5.3) - 2026-08-24

### Added

- *(engine)* add private_key_jwt client authentication to ClientCredentialsFlow ([#229](https://github.com/marcjazz/authkestra/pull/229))

### Other

- *(axum,actix)* add E2E integration tests for engine adapters ([#232](https://github.com/marcjazz/authkestra/pull/232))

## [0.5.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.4.0...authkestra-engine-v0.5.0) - 2026-08-15

### Fixed

- *(engine)* honor extra["jti"] as a jti override, stop emitting duplicate-key JWTs ([#215](https://github.com/marcjazz/authkestra/pull/215))
- *(engine,op)* accept array-shaped aud claims in token exchange ([#207](https://github.com/marcjazz/authkestra/pull/207))

## [0.4.0](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.3.4...authkestra-engine-v0.4.0) - 2026-08-13

### Added

- *(engine)* add Ed25519/EdDSA signing and OKP JWKS support ([#190](https://github.com/marcjazz/authkestra/pull/190))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.3.3...authkestra-engine-v0.3.4) - 2026-08-05

### Fixed

- *(engine)* derive the asymmetric decoding key from the public half ([#182](https://github.com/marcjazz/authkestra/pull/182))

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.3.2...authkestra-engine-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-engine-v0.3.1...authkestra-engine-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

### Other

- clean up scratch dir and bump documentation versions to 0.3.1 ([#173](https://github.com/marcjazz/authkestra/pull/173))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.5...v0.3.0) - 2026-07-31

### Other

- release v0.3.0 ([#166](https://github.com/marcjazz/authkestra/pull/166))
