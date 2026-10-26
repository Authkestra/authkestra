//! Issue #325: what the facade forwards, pinned from outside.
//!
//! The facade used to forward nine features while its sub-crates offered
//! roughly twice that. Passkeys, TOTP, captcha, every persistent store, the
//! OP server, device signatures and the `ActixState` derive were unreachable
//! through `authkestra`, so an application wanting any of them had to depend
//! on the sub-crates directly — which defeats the point of a facade, and is
//! why the documented advice was to skip it.
//!
//! # Why this lives in its own crate
//!
//! `crates/authkestra`'s own tests cannot check this. Its dev-dependencies
//! name the sub-crates directly, and Cargo unifies features across normal and
//! dev dependencies, so a sub-crate feature enabled there is on during the
//! test build whether or not the facade forwards it. An in-crate version of
//! this file passed with the forwarding entry deleted — confirmed by removing
//! `authkestra-engine/webauthn` from the facade's `webauthn` feature and
//! watching the suite stay green.
//!
//! This crate depends on `authkestra` and nothing else from the workspace, so
//! every path below resolves only if the facade genuinely forwarded the
//! feature. The feature list lives in `Cargo.toml`; there are no `cfg` gates
//! here, so a dropped or misspelled forwarding entry is a hard compile error
//! rather than a silently skipped test.
//!
//! Paths are named rather than values constructed: the assertion is
//! reachability, and constructing these types would drag in trait bounds that
//! have nothing to do with it. Each `use` sits in a named `#[test]` so a break
//! points at the feature that regressed.

#[test]
fn memory_store_is_reachable() {
    #[allow(unused_imports)]
    use authkestra::core::store::memory::MemoryStore;
}

#[test]
fn redis_store_is_reachable() {
    #[allow(unused_imports)]
    use authkestra::core::store::redis::RedisStore;
}

/// The SQL-backed credential store, which the engine gates on
/// `any(sql-*)` **and** `any(webauthn, totp)`. Naming it therefore asserts
/// that both families forward, not just the `sql-*` one — the shape an
/// application storing passkeys in Postgres actually needs.
#[test]
fn the_sql_credential_store_is_reachable() {
    #[allow(unused_imports)]
    use authkestra::core::store::sql::SqlxCredentialStore;
}

#[test]
fn webauthn_is_reachable() {
    #[allow(unused_imports)]
    use authkestra::core::auth::webauthn::WebAuthnAuthMethod;
}

#[test]
fn totp_is_reachable() {
    #[allow(unused_imports)]
    use authkestra::core::auth::totp::TotpAuthMethod;
}

#[test]
fn captcha_is_reachable() {
    let _ = authkestra::core::CaptchaProvider::Turnstile;
    #[allow(unused_imports)]
    use authkestra::core::CaptchaVerifier;
}

#[test]
fn the_op_server_is_reachable() {
    // Forwarding the adapters' `op` feature without this crate would leave
    // the routes mounted but unconfigurable: `OpConfig` lives here.
    #[allow(unused_imports)]
    use authkestra::core::oauth2::client::ClientRegistration;
    #[allow(unused_imports)]
    use authkestra::op::{config::OpConfig, CloneableOpStore};
}

#[test]
fn device_signatures_are_reachable() {
    #[allow(unused_imports)]
    use authkestra::devsig::DeviceIdentity;
}

/// The state derives. `macros` is the only route to `ActixState` through the
/// facade — the `axum` feature already carries `AxumState`, which is the
/// asymmetry this feature works around without changing it.
///
/// Reachability only: `derive_reachability.rs` exercises both derives properly.
#[test]
fn the_state_derives_are_reachable() {
    #[allow(unused_imports)]
    use authkestra::actix::ActixState;
    #[allow(unused_imports)]
    use authkestra::axum::AxumState;
}

#[test]
fn mcp_is_reachable() {
    #[allow(unused_imports)]
    use authkestra::mcp::{DownstreamTokenBroker, McpRouter, McpSecurityTier};
}
