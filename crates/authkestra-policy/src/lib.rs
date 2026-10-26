//! `authkestra-policy` — a **proof-of-concept** authorization policy engine built on
//! [AWS Cedar](https://www.cedarpolicy.com/).
//!
//! Authkestra answers "who are you?" in `authkestra-engine` and its adapters. This crate is an
//! experiment in answering the other half — "may you do this?" — with a real policy language
//! instead of hand-rolled `if role == "admin"` checks, so that authorization rules can live
//! outside the binary and change without a redeploy.
//!
//! Proposed in [authkestra#21](https://github.com/marcjazz/authkestra/issues/21). The full
//! integration plan — guards, extractors, where policies live, how principals are derived from
//! an `AuthSession` — is `docs/rfc-008-policy-engine.md`. **None of that integration exists
//! yet**: nothing in `authkestra-resource`, `authkestra-axum`, or `authkestra-actix` calls this
//! crate. It is usable on its own, and deliberately scoped to be judged on its own.
//!
//! ## The one structural rule
//!
//! The engine performs **no I/O**. Cedar needs an entity store (the principal, the resource,
//! their groups and attributes) to evaluate against, and every byte of it arrives through a
//! caller-supplied [`ResourceLoader`]:
//!
//! ```text
//!   AuthorizationRequest ──▶ PolicyEngine ──▶ ResourceLoader ──▶ your database
//!                                 │                              (never reached from here)
//!                                 ▼
//!                          cedar_policy::Authorizer ──▶ Decision
//! ```
//!
//! This keeps the crate database-agnostic in exactly the sense `AGENTS.md` requires of
//! `UserStore` and `SessionStore`: the engine cannot query storage even by accident, because it
//! holds no handle to any.
//!
//! ## The one security rule
//!
//! Cedar *skips* a policy that raises an evaluation error and finishes the request with the
//! rest. When the skipped policy is a `forbid`, the resulting `Allow` was only reached because
//! the denying rule never ran. [`PolicyEngine::is_authorized`] refuses to return that: it fails
//! closed with [`PolicyError::UnreliableDecision`]. See its docs for the full table.
//!
//! ## Example
//!
//! ```
//! use authkestra_policy::cedar_policy::RestrictedExpression;
//! use authkestra_policy::{
//!     AuthorizationRequest, EntityRecord, MemoryResourceLoader, PolicyEngine, parse_entity_uid,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Entities: alice is in the "eng" group; the doc is owned by engineering.
//! let loader = MemoryResourceLoader::new();
//! loader.extend([
//!     EntityRecord::new(parse_entity_uid(r#"User::"alice""#)?)
//!         .parent(parse_entity_uid(r#"Group::"eng""#)?),
//!     EntityRecord::new(parse_entity_uid(r#"Group::"eng""#)?),
//!     EntityRecord::new(parse_entity_uid(r#"Doc::"design""#)?)
//!         .attribute(
//!             "owner",
//!             RestrictedExpression::new_entity_uid(parse_entity_uid(r#"Group::"eng""#)?),
//!         ),
//! ]);
//!
//! // 2. Policies: engineers may read documents their group owns.
//! let engine = PolicyEngine::builder()
//!     .policies(r#"
//!         permit(principal in Group::"eng", action == Action::"read", resource)
//!         when { resource.owner == Group::"eng" };
//!     "#)
//!     .loader(loader)
//!     .build()?;
//!
//! // 3. Ask.
//! let request = AuthorizationRequest::builder()
//!     .principal_str(r#"User::"alice""#)
//!     .action_str(r#"Action::"read""#)
//!     .resource_str(r#"Doc::"design""#)
//!     .build()?;
//! assert!(engine.is_authorized(&request).await?.is_allowed());
//!
//! // 4. Policies can be swapped at runtime; a bad update leaves the old set serving traffic.
//! assert!(engine.reload("permit(principal").is_err());
//! engine.reload(r#"forbid(principal, action, resource);"#)?;
//! assert!(!engine.is_authorized(&request).await?.is_allowed());
//! # Ok(())
//! # }
//! # tokio::runtime::Runtime::new().unwrap().block_on(example()).unwrap();
//! ```
//!
//! ## What this crate deliberately does not do
//!
//! - **No framework wiring.** Per `AGENTS.md`'s framework-agnostic rule, any axum/actix
//!   integration belongs in the adapter crates; RFC-008 sketches it, this crate does not ship it.
//! - **No policy storage.** Policy *source text* comes from the caller — a file, a config value,
//!   a database column, an admin API. Where it should live is a maintainer decision recorded in
//!   RFC-008.
//! - **No mandatory schema.** A [`cedar_policy::Schema`] is optional; supplying one turns on
//!   validation of policies at load time and type-checking of the request context.

#![forbid(unsafe_code)]

mod engine;
mod error;
mod loader;
mod request;

pub use engine::{parse_policies, parse_schema, PolicyEngine, PolicyEngineBuilder};

/// Convenience alias matching standard Authkestra terminology.
pub type CedarPolicyEngine = PolicyEngine;
/// Convenience alias matching standard Authkestra terminology.
pub type CedarPolicyEngineBuilder = PolicyEngineBuilder;
pub use error::PolicyError;
pub use loader::{EntityRecord, MemoryResourceLoader, ResourceLoader, StaticResourceLoader};
pub use request::{parse_entity_uid, AuthorizationRequest, AuthorizationRequestBuilder, Decision};

/// Re-exported so that callers can name the Cedar types that appear in this crate's signatures
/// (`EntityUid`, `Entities`, `RestrictedExpression`, `Schema`) without adding — and having to
/// keep in version lockstep with — their own `cedar-policy` dependency.
pub use cedar_policy;
