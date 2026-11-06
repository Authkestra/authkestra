# authkestra-axum

Axum integration for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides Axum-specific extractors and helpers to easily integrate the `authkestra` authentication framework into Axum applications.

## Features

- **Extractors**:
  - `Auth<I>`: Unified extractor that uses a configured `Guard` to validate the request.
  - `AuthSession`: Extracts a validated session from cookies.
  - `AuthToken`: Extracts and validates a JWT from the `Authorization: Bearer` header.
- **OAuth Helpers**:
  - `initiate_oauth_login`: Generates authorization URLs and handles CSRF protection.
  - `handle_oauth_callback`: Finalizes OAuth login and creates a server-side session.
  - `handle_oauth_callback_jwt`: Finalizes OAuth login and returns a JWT.
- **Offline Validation**:
  - `Jwt<T>`: Extractor for validating JWTs from external OIDC providers using JWKS (via `authkestra-resource`).
- **Session Management**:
  - `logout`: Clears the session cookie and removes it from the store.
  - `SessionConfig`: Customizable session settings (cookie name, secure, http_only, etc.).
- **Macros** (`macros` feature):
  - `AxumState`: derive macro that generates the `axum::extract::FromRef` implementations your
    application state needs (re-exported from `authkestra-macros`).
- **Device-Bound Signature Authentication** (`devsig` feature):
  - `DeviceSignatureLayer`: a `tower::Layer` that verifies `X-Signature` + `X-Attestation`
    headers (per-request proof-of-possession, no session store, no per-request network call —
    see `authkestra-devsig`) ahead of axum's own extraction.
  - `AuthDeviceSignature`: extractor that reads the `DeviceIdentity` the layer already verified
    back out of request extensions.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-axum = { version = "0.13", features = ["macros", "session"] }
tower-cookies = "0.11" # Required for session support
```

### Quick Start with AxumState (Recommended)

The easiest way to integrate Authkestra with custom Axum state is using the `AxumState` derive
macro. Mark the engine field with `#[authkestra(engine)]`; the macro derives every `FromRef`
impl the extractors below require.

```rust,ignore
use axum::{routing::get, Router};
use authkestra_axum::{AuthSession, AxumExt, AxumState};
use authkestra_engine::AkWebAppEngine;
use tower_cookies::CookieManagerLayer;

#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkWebAppEngine,
    // other fields...
}

async fn protected_handler(AuthSession(session): AuthSession) -> String {
    format!("Welcome back, {}!", session.identity.username.unwrap_or_default())
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/protected", get(protected_handler))
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
```

### Manual Integration

If you prefer not to use the macro or need more control, you can manually implement the required
traits. Note that `AuthSession` asks the state for a `Result<Arc<dyn SessionStore>, AxumError>`,
not a bare `Arc<dyn SessionStore>` — that is what lets a typestate-incomplete engine surface a
runtime error instead of failing to compile at the extractor:

```rust,ignore
use axum::extract::FromRef;
use authkestra_axum::{AxumError, SessionConfig, SessionStore};
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    session_store: Arc<dyn SessionStore>,
    session_config: SessionConfig,
}

impl FromRef<AppState> for Result<Arc<dyn SessionStore>, AxumError> {
    fn from_ref(state: &AppState) -> Self {
        Ok(state.session_store.clone())
    }
}

impl FromRef<AppState> for SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.session_config.clone()
    }
}
```

### Example: Unified Authentication (Chained Strategies)

The `Auth<I>` extractor allows you to use a central `Guard` that can try multiple authentication methods in order.

```rust,ignore
use axum::{routing::get, Router, extract::FromRef};
use authkestra_axum::Auth;
use authkestra_resource::{Guard, AuthPolicy};
use authkestra_resource::jwt::JwtStrategy;
use authkestra_engine::auth::strategy::SessionStrategy;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct User { id: String }

#[derive(Clone)]
struct AppState {
    guard: Arc<Guard<User>>,
}

impl FromRef<AppState> for Arc<Guard<User>> {
    fn from_ref(state: &AppState) -> Self {
        state.guard.clone()
    }
}

fn app() -> Router {
    let guard = Guard::builder()
        .strategy(JwtStrategy::new(jwt_config))
        // The first argument is a `SessionProvider`, i.e. your own mapping from a
        // session id to your `User` type — not a raw `SessionStore`.
        .strategy(SessionStrategy::new(session_provider, "session_cookie"))
        .policy(AuthPolicy::FirstSuccess)
        .build();

    let state = AppState {
        guard: Arc::new(guard),
    };

    Router::new()
        .route("/protected", get(protected_handler))
        .layer(CookieManagerLayer::new())
        .with_state(state)
}

async fn protected_handler(Auth(user): Auth<User>) -> String {
    format!("Welcome, user {}!", user.id)
}
```

### Device-Bound Signature Authentication

Enable the `devsig` feature to protect a route with `authkestra-devsig`'s verifier: per-request
proof-of-possession of a device-bound private key, with no session store and no per-request
network call.

```toml
[dependencies]
authkestra-axum = { version = "0.13", features = ["devsig"] }
authkestra-devsig = "0.7"
```

```rust,ignore
use authkestra_axum::devsig::{AuthDeviceSignature, DeviceSignatureLayer};
use axum::{routing::post, Router};
use std::sync::Arc;

let layer = DeviceSignatureLayer::new(config, Arc::new(jwks), replay_store);

let app = Router::new()
    .route("/v1/payments/transfer", post(transfer_handler))
    .layer(layer);

async fn transfer_handler(AuthDeviceSignature(identity): AuthDeviceSignature) -> String {
    format!("Transfer accepted for device {}", identity.device)
}
```

A refused request is answered in [device-signature profile v1](../../docs/rfc-014-devsig-profile-v1.md)'s
shape: the status (`401`, or `413` for an oversized body), `Content-Type: application/json`, the
body `{"error": "<code>"}` (e.g. `{"error":"attestation_expired"}`), and on a `401` a
`WWW-Authenticate: DeviceSignature error="<code>"` challenge. A handler answers the two refusals
the verifier never produces in the same shape with `devsig::refusal_response`:
`Refusal::device_revoked()` (`403`) and `Refusal::insufficient_user_authentication()` (`401`,
when `identity.key_role()` is not `KeyRole::UserPresent`).

See
[`crates/authkestra/examples/axum_devsig/`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples/axum_devsig)
for a complete, runnable example (all examples live in the `authkestra` facade crate):

```bash
cargo run -p authkestra --example axum_devsig --all-features
```

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
