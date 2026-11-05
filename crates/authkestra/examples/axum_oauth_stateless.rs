//! # Axum + GitHub OAuth2 (stateless / JWT)
//!
//! The golden path for an API with no server-side session state. The same
//! [`Engine::builder`] is given a `jwt_secret` instead of a `session_store`,
//! and [`AxumStatelessExt::axum_router_stateless`] wires a callback that
//! returns a JWT as JSON rather than setting a cookie.
//!
//! The typestate builder is what makes the difference safe: because no session
//! store was configured, the session-only APIs simply do not exist on this
//! engine, so there is no way to accidentally mix the two modes.
//!
//! ```sh
//! AUTHKESTRA_GITHUB_CLIENT_ID=... AUTHKESTRA_GITHUB_CLIENT_SECRET=... \
//!   cargo run -p authkestra --example axum_oauth_stateless --all-features
//! ```
//!
//! 1. Start the flow at `/auth/login/github`.
//! 2. The callback (`/auth/callback/github`) responds with a JWT.
//! 3. Call `/api/user` with `Authorization: Bearer <token>`.

use authkestra::Authkestra;
use authkestra_axum::{AuthToken, AxumError, AxumState, AxumStatelessExt};
use authkestra_engine::{AkApiEngine, OAuth2Flow};
use authkestra_providers::github::GithubProvider;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;

/// `AkApiEngine` is the alias for a token-configured engine with no session
/// store — the stateless counterpart of `AkWebAppEngine`.
#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkApiEngine,
}

#[tokio::main]
async fn main() {
    // `RUST_LOG=authkestra=debug` surfaces the engine's own instrumentation.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,authkestra=debug".into()),
        )
        .init();

    dotenvy::dotenv().ok();

    let port = port_from_env();

    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| format!("http://localhost:{port}/auth/callback/github"));

    let github_provider = github_provider(client_id, client_secret, redirect_uri);

    // Stateless mode: `jwt_secret` configures the token manager and leaves the
    // session-store slot `Missing`. In production, load your secret from a
    // secret manager. Here we resolve dynamically from env or generate a fresh key.
    let token_secret = resolve_token_secret();
    let engine = Authkestra::builder()
        .provider(OAuth2Flow::new(github_provider))
        .jwt_secret(&token_secret)
        .build();

    let state = AppState { auth: engine };

    let app = Router::new()
        .route("/api/user", get(get_user))
        .merge(state.auth.axum_router_stateless())
        // The OAuth `state`/`nonce` round-trip rides in encrypted cookies even
        // in stateless mode, so the cookie layer is still required.
        .layer(tower_cookies::CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind example server");

    tracing::info!(%port, "Axum stateless OAuth listening on http://localhost:{port}");
    tracing::info!("1. start the flow at http://localhost:{port}/auth/login/github");
    tracing::info!("2. the callback returns JSON containing a JWT");
    tracing::info!("3. call /api/user with 'Authorization: Bearer <token>'");
    axum::serve(listener, app).await.unwrap();
}

/// Builds the provider, redirecting to a mock server when the e2e harness has
/// set `AUTHKESTRA_GITHUB_BASE_URL`. Real deployments never set these.
fn github_provider(
    client_id: String,
    client_secret: String,
    redirect_uri: String,
) -> GithubProvider {
    match std::env::var("AUTHKESTRA_GITHUB_BASE_URL") {
        Ok(base_url) => {
            let api_url =
                std::env::var("AUTHKESTRA_GITHUB_API_URL").unwrap_or_else(|_| base_url.clone());
            tracing::warn!(%base_url, "using overridden GitHub endpoints (test mode)");
            GithubProvider::new(client_id, client_secret, redirect_uri).with_test_urls(
                format!("{base_url}/login/oauth/authorize"),
                format!("{base_url}/login/oauth/access_token"),
                format!("{api_url}/user"),
            )
        }
        Err(_) => GithubProvider::new(client_id, client_secret, redirect_uri),
    }
}

/// Protected endpoint using the `AuthToken` extractor (bearer token, no cookie).
async fn get_user(auth: Result<AuthToken, AxumError>) -> impl IntoResponse {
    match auth {
        Ok(AuthToken(claims)) => match claims.identity.as_ref() {
            Some(identity) => {
                tracing::debug!(user = %identity.external_id, "bearer token accepted");
                (
                    StatusCode::OK,
                    Json(json!({
                        "id": identity.external_id,
                        "username": identity.username,
                        "email": identity.email,
                        "provider": identity.provider_id,
                    })),
                )
            }
            // A token signed by this engine but carrying no identity claim —
            // e.g. a client-credentials token. Report it rather than panicking.
            None => {
                tracing::warn!("token validated but carries no identity claim");
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "Token carries no user identity" })),
                )
            }
        },
        Err(err) => {
            tracing::debug!(%err, "bearer token rejected");
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Not authenticated" })),
            )
        }
    }
}

/// Bind port, overridable via `PORT` so several examples (and the e2e test
/// harness, which passes a port it has already confirmed to be free) can run
/// without colliding on 3000.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000)
}

/// Resolves the token signing secret dynamically: checks `AUTHKESTRA_TOKEN_SECRET` then
/// `JWT_SECRET` for the first valid secret of at least 32 bytes, falling back to a securely
/// generated random 32-byte secret at startup so no static source literal can forge tokens (CWE-321).
pub fn resolve_token_secret() -> Vec<u8> {
    for var_name in ["AUTHKESTRA_TOKEN_SECRET", "JWT_SECRET"] {
        if let Ok(val) = std::env::var(var_name) {
            let bytes = val.into_bytes();
            if bytes.len() >= 32 {
                tracing::info!(
                    var = var_name,
                    "Using token signing secret from environment variable"
                );
                return bytes;
            }
            tracing::warn!(
                var = var_name,
                "Configured token secret from environment is shorter than 32 bytes; checking fallback or ephemeral key"
            );
        }
    }
    tracing::info!("Generating random 32-byte secret for example token signing");
    let mut key = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    key
}
