# authkestra-devsig

Device-bound signature authentication for the `authkestra` framework: per-request proof of
possession of a device-bound private key, plus an Issuer-attested key binding, so that
verification needs no session store, no token introspection, and no per-request network call.

Proposed in [authkestra#137](https://github.com/marcjazz/authkestra/issues/137). See the crate
docs (`cargo doc -p authkestra-devsig --open`) for the full algorithm, the two credentials
(`X-Signature` and `X-Attestation`), and why the key-thumbprint binding check is the
security-critical step.

## Status

The verification core (`verify()`) is complete and covered by conformance tests. This crate is
deliberately framework-agnostic (per the workspace `AGENTS.md`'s "Framework Agnostic" rule) —
it does not depend on axum, actix, or any other web framework. Which `authkestra-engine` trait
(if any) framework integrations should eventually implement against is an open question for the
maintainer — see authkestra#137.

## Profile v1 and the shared vectors

The wire contract — the `att` claim (an object with `status` and an optional key `role`), the
issuer and device algorithms, the `qsh`/`bdh` presence rule, and the refusal table (a JSON body
`{"error": "<code>"}`, its status, and a `WWW-Authenticate: DeviceSignature` challenge on a
`401`) — is [RFC-014, device-signature profile v1](../../docs/rfc-014-devsig-profile-v1.md).
Its conformance vectors, [`conformance/devsig-profile-v1/vectors.json`](../../conformance/devsig-profile-v1/),
run against [`verify_at`] in `tests/profile_v1.rs`; client libraries vendor the same file.

```rust,ignore
use authkestra_devsig::{KeyRole, Refusal, VerifierConfig};

let config = VerifierConfig::profile_v1(["https://issuer.example"], "https://api.example");
// ... after verify():
if identity.key_role() != KeyRole::UserPresent {
    // answer in the profile's shape, e.g. with authkestra_axum::devsig::refusal_response
    let refusal = Refusal::insufficient_user_authentication();
}
```

## Usage

```rust,ignore
use authkestra_devsig::{IssuerJwks, InMemoryReplayStore, SignedRequest, VerifierConfig, verify};

let identity = verify(&request, &config, &jwks, &replay_store).await?;
```

### Testing your own principal mapping

`DeviceIdentity` is `#[non_exhaustive]`, so downstream crates cannot build one with a struct
expression. `DeviceIdentity::new(subject, device, key_thumbprint, attributes)` exists so that the
mapping from a verified identity onto your own principal/session type — where the
security-relevant defaults live, such as what an absent `role` attribute grants — stays unit
testable without minting a real attestation ([authkestra#282](https://github.com/marcjazz/authkestra/issues/282)):

```rust,ignore
let identity = DeviceIdentity::new(
    "usr_1".to_owned(),
    "vk_1".to_owned(),
    "jkt-1".to_owned(),
    serde_json::json!({}),
);
assert_eq!(my_mapping(&identity).role, "user");
```

`new` verifies nothing: a value built this way is test data, not an authentication result. Only
`verify()` produces a `DeviceIdentity` that means a request passed the algorithm.

### Framework integration

Framework wiring lives in the adapter crates, not here:

- **Axum**: enable the `devsig` feature on `authkestra-axum` and use
  `authkestra_axum::devsig::DeviceSignatureLayer` (a `tower::Layer`) plus the
  `authkestra_axum::devsig::AuthDeviceSignature` extractor. See
  [`authkestra-axum`'s README](../authkestra-axum/README.md) and
  `crates/authkestra/examples/axum_devsig/`
  (`cargo run -p authkestra --example axum_devsig --all-features`).
- **Actix Web**: enable the `devsig` feature on `authkestra-actix` and use
  `authkestra_actix::devsig::DeviceSignatureAuth` (an `actix_web::dev::Transform` middleware)
  plus the `authkestra_actix::devsig::AuthDeviceSignature` extractor. See
  [`authkestra-actix`'s README](../authkestra-actix/README.md) and
  `crates/authkestra/examples/actix_devsig/`
  (`cargo run -p authkestra --example actix_devsig --all-features`).

Both adapters buffer the request body ahead of their framework's own extraction (needed for the
`bdh` check) and call this crate's plain [`verify`] function underneath — see their `devsig`
module docs for why neither implements an `authkestra-engine` `AuthenticationStrategy<I>` today.
