//! # Actix + GitHub OAuth2 (stateless / JWT)
//!
//! The Actix counterpart of `axum_oauth_stateless.rs`. The same
//! [`Engine::builder`] is given a `jwt_secret` instead of a `session_store`,
//! and [`ActixStatelessExt::actix_scope_stateless`] wires a callback that
//! returns a JWT as JSON rather than setting a session cookie.
//!
//! The typestate builder is what makes the difference safe: because no session
//! store was configured, the session-only APIs simply do not exist on this
//! engine, so there is no way to accidentally mix the two modes.
//!
//! ```sh
//! AUTHKESTRA_GITHUB_CLIENT_ID=... AUTHKESTRA_GITHUB_CLIENT_SECRET=... \
//!   cargo run -p authkestra --example actix_oauth_stateless --all-features
//! ```
//!
//! 1. Start the flow at `/auth/login/github`.
//! 2. The callback (`/auth/callback/github`) responds with a JWT.
//! 3. Call `/api/user` with `Authorization: Bearer <token>`.

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra::Authkestra;
use authkestra_actix::{ActixState, ActixStatelessExt, AuthToken};
use authkestra_engine::{AkApiEngine, OAuth2Flow};
use authkestra_providers::github::GithubProvider;
use serde_json::json;

/// `AkApiEngine` is the alias for a token-configured engine with no session
/// store — the stateless counterpart of `AkWebAppEngine`.
#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkApiEngine,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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

    tracing::info!(%port, "Actix stateless OAuth listening on http://localhost:{port}");
    tracing::info!("1. start the flow at http://localhost:{port}/auth/login/github");
    tracing::info!("2. the callback returns JSON containing a JWT");
    tracing::info!("3. call /api/user with 'Authorization: Bearer <token>'");

    HttpServer::new(move || {
        let app_state = state.clone();
        let scope_state = app_state.clone();
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .configure(move |cfg| app_state.configure_authkestra(cfg))
            .service(scope_state.auth.actix_scope_stateless())
            .service(get_user)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
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
#[get("/api/user")]
async fn get_user(auth: Option<AuthToken>) -> impl Responder {
    match auth {
        Some(AuthToken(claims)) => match claims.identity.as_ref() {
            Some(identity) => {
                tracing::debug!(user = %identity.external_id, "bearer token accepted");
                HttpResponse::Ok().json(json!({
                    "id": identity.external_id,
                    "username": identity.username,
                    "email": identity.email,
                    "provider": identity.provider_id,
                }))
            }
            // A token signed by this engine but carrying no identity claim —
            // e.g. a client-credentials token. Report it rather than panicking.
            None => {
                tracing::warn!("token validated but carries no identity claim");
                HttpResponse::Forbidden().json(json!({
                    "error": "Token carries no user identity"
                }))
            }
        },
        None => {
            tracing::debug!("bearer token missing or rejected");
            HttpResponse::Unauthorized().json(json!({ "error": "Not authenticated" }))
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

/// Resolves the token signing secret dynamically: checks `AUTHKESTRA_TOKEN_SECRET` or
/// `JWT_SECRET` in the environment, falling back to a securely generated random 32-byte
/// secret at startup so no static source literal can forge tokens (CWE-321).
fn resolve_token_secret() -> Vec<u8> {
    if let Ok(val) =
        std::env::var("AUTHKESTRA_TOKEN_SECRET").or_else(|_| std::env::var("JWT_SECRET"))
    {
        let bytes = val.into_bytes();
        if bytes.len() >= 32 {
            tracing::info!("Using token signing secret from environment variable");
            return bytes;
        }
        tracing::warn!(
            "Configured token secret from environment is shorter than 32 bytes; falling back to ephemeral random key"
        );
    }
    tracing::info!("Generating random 32-byte secret for example token signing");
    let mut key = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    key
}
