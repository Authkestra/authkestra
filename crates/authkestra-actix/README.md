# authkestra-actix

Actix-web integration for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides Actix-web specific extractors and utilities to integrate the `authkestra` authentication framework into Actix applications.

## Features

- **Extractors**: Easily access validated sessions or JWT claims in your request handlers.
- **OAuth2 Helpers**: Streamlined functions for initiating login, handling callbacks, and logging out.
- **Session Management**: Integration with `authkestra-engine` for server-side session storage.
- **Device-Bound Signature Authentication** (`devsig` feature): `DeviceSignatureAuth`, an
  `actix_web::dev::Transform` middleware that verifies `X-Signature` + `X-Attestation` headers
  (per-request proof-of-possession, no session store, no per-request network call — see
  `authkestra-devsig`) ahead of the handler, plus the `AuthDeviceSignature` extractor.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-actix = { version = "0.13", features = ["session", "token"] }
authkestra-engine = { version = "0.13", features = ["memory"] }
actix-web = "4"
```

`authkestra-engine`'s token machinery is always compiled in — it has no `token` feature of its
own to enable. `authkestra-actix`'s `token` feature only gates this crate's own token-issuing
helpers and extractors; there is no separate `authkestra-token` crate.

### Extractors

#### `AuthSession`

Extracts a validated session from a cookie. Requires `Arc<dyn SessionStore>` and `SessionConfig` to be registered in `app_data`.

```rust
use authkestra_actix::AuthSession;
use actix_web::{get, HttpResponse};

#[get("/profile")]
async fn profile(AuthSession(session): AuthSession) -> HttpResponse {
    HttpResponse::Ok().json(session.identity)
}
```

#### `AuthToken`

Extracts and validates a JWT from the `Authorization: Bearer <token>` header. Requires `Arc<TokenManager>` to be registered in `app_data`.

```rust
use authkestra_actix::AuthToken;
use actix_web::{get, HttpResponse};

#[get("/api/data")]
async fn protected_api(AuthToken(claims): AuthToken) -> HttpResponse {
    HttpResponse::Ok().json(claims)
}
```

#### `Jwt<T>` (Offline Validation)

Extracts and validates a JWT against a remote JWKS (e.g., Google, Auth0). Requires `Arc<JwksCache>` and `jsonwebtoken::Validation` to be registered in `app_data`.

```rust
use authkestra_actix::Jwt;
use authkestra_resource::jwt::JwksCache;
use actix_web::{get, HttpResponse, web};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
struct MyClaims {
    sub: String,
    // ...
}

#[get("/api/external")]
async fn external_api(Jwt(claims): Jwt<MyClaims>) -> HttpResponse {
    HttpResponse::Ok().json(claims)
}
```

#### `Auth<I>` and request extensions

`Auth<I>` runs the `Guard<I>` from `app_data` over the request. actix has no
`http::request::Parts` of its own (actix-http 3.x is still built on `http` 0.2),
so the adapter synthesises one from the request's method, URI and headers — and
that synthetic value starts with an **empty extension map**.

If your `AuthenticationStrategy` reads a request extension put there by another
middleware, register its type with `CarriedExtensions`:

```rust
use actix_web::{dev::Service as _, web, App, HttpMessage};
use authkestra_actix::CarriedExtensions;

#[derive(Clone)]
struct TenantId(String);

let app = App::new()
    .wrap_fn(|req, srv| {
        req.extensions_mut().insert(TenantId("acme".to_string()));
        srv.call(req)
    })
    .app_data(web::Data::new(
        CarriedExtensions::new().carry::<TenantId>(),
    ));
```

The strategy then reads `parts.extensions.get::<TenantId>()`.

Registration is required because `actix_http::Extensions` exposes no way to
enumerate its contents and stores `Box<dyn Any>`, while `http::Extensions`
accepts only `T: Clone + Send + Sync`; copying the whole map generically is not
expressible. See the `extensions` module docs for the full rationale.
`ClientCertificateDer` is carried unconditionally and needs no registration, so
RFC 8705 certificate-bound token checks keep working out of the box.

### OAuth2 Helpers

The crate provides helpers to manage the OAuth2 flow lifecycle.

#### SPA vs Server-Side Rendering

For **SPA (Single Page Application)** use cases where you want to receive a JWT on the frontend:

1. The `redirect_uri` in your OAuth provider configuration should point to a **frontend route** (e.g., `https://myapp.com/callback`).
2. Your frontend route should extract the `code` and `state` from the URL.
3. The frontend then performs a **POST** (or GET) request to your backend's callback endpoint (e.g., `/api/auth/callback`) with these parameters.
4. The backend uses `handle_oauth_callback_jwt` to exchange the code for a JWT and returns it to the frontend.

These live in the `helpers` module (`authkestra_actix::helpers::*`); only the pre-built
`actix_login_handler` / `actix_callback_handler` / `actix_logout_handler` are re-exported at the
crate root.

```rust,ignore
use authkestra_actix::helpers::{
    handle_oauth_callback, initiate_oauth_login, logout, OAuthCallbackParams, SessionConfig,
};
use actix_web::{web, HttpRequest, HttpResponse, get};
use std::sync::Arc;

// `OAuth2Flow` is generic over the provider and an optional user mapper (which
// defaults to `()`); the alias keeps the handler signatures readable.
type GithubFlow = OAuth2Flow<GithubProvider>;

// 1. Initiate Login
#[get("/login")]
async fn login(flow: web::Data<GithubFlow>, config: web::Data<SessionConfig>) -> HttpResponse {
    // (flow, scopes, config, success_url)
    initiate_oauth_login(&flow, &["user:email"], &config, None)
}

// 2. Handle Callback (Server-Side Session)
#[get("/callback")]
async fn callback(
    req: HttpRequest,
    params: web::Query<OAuthCallbackParams>,
    flow: web::Data<GithubFlow>,
    store: web::Data<Arc<dyn SessionStore>>,
    config: web::Data<SessionConfig>,
) -> Result<HttpResponse, actix_web::Error> {
    handle_oauth_callback(
        req,
        &flow,
        params.into_inner(),
        store.get_ref().clone(),
        config.get_ref().clone(),
        "/dashboard"
    ).await
}

// 3. Logout
#[get("/logout")]
async fn sign_out(
    req: HttpRequest,
    store: web::Data<Arc<dyn SessionStore>>,
    config: web::Data<SessionConfig>,
) -> Result<HttpResponse, actix_web::Error> {
    logout(req, store.get_ref().clone(), config.get_ref().clone(), "/").await
}
```

### Setup

To use the extractors and helpers, you must configure your Actix app with the necessary data:

```rust,ignore
use actix_web::{web, App, HttpServer};
use authkestra_actix::{SessionConfig, SessionStore, TokenManager};
use authkestra_engine::store::memory::MemoryStore;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());
    // `TokenManager::new(secret: &[u8], issuer: Option<String>)`
    let token_manager = Arc::new(TokenManager::new(b"your-secret", None));
    let session_config = SessionConfig::default();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(session_store.clone()))
            .app_data(web::Data::new(token_manager.clone()))
            .app_data(web::Data::new(session_config.clone()))
            // ... routes
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Device-Bound Signature Authentication

Enable the `devsig` feature to protect a route with `authkestra-devsig`'s verifier: per-request
proof-of-possession of a device-bound private key, with no session store and no per-request
network call.

```toml
[dependencies]
authkestra-actix = { version = "0.13", features = ["devsig"] }
authkestra-devsig = "0.7"
```

```rust,ignore
use authkestra_actix::devsig::{AuthDeviceSignature, DeviceSignatureAuth};
use actix_web::{post, web, App, HttpServer};
use std::sync::Arc;

#[post("/v1/payments/transfer")]
async fn transfer_handler(identity: AuthDeviceSignature) -> web::Json<serde_json::Value> {
    let AuthDeviceSignature(identity) = identity;
    web::Json(serde_json::json!({ "device": identity.device }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(move || {
        let auth = DeviceSignatureAuth::new(config.clone(), jwks.clone(), replay_store.clone());
        App::new().wrap(auth).service(transfer_handler)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
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
[`crates/authkestra/examples/actix_devsig/`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples/actix_devsig)
for a complete, runnable example (all examples live in the `authkestra` facade crate):

```bash
cargo run -p authkestra --example actix_devsig --all-features
```

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
