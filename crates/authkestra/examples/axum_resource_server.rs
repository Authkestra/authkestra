//! # Axum resource server — manual JWKS wiring (lower level)
//!
//! Protects endpoints with JWTs issued by an external OIDC provider, wiring
//! [`JwksCache`] and `jsonwebtoken::Validation` into the state by hand and
//! extracting with `Jwt<T>`.
//!
//! Reach for this when you need direct control over `Validation`. For the
//! common case prefer `axum_resource_server_strategy.rs`, which hides all of
//! the below behind a `Guard`.
//!
//! ```sh
//! OIDC_ISSUER=https://accounts.google.com OIDC_AUDIENCE=my-api \
//!   cargo run -p authkestra --example axum_resource_server --all-features
//! ```

use authkestra_axum::Jwt;
use authkestra_resource::jwt::{JwksCache, ValidationConfig};
use axum::{
    extract::FromRef,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct MyClaims {
    sub: String,
    email: Option<String>,
    scope: Option<String>,
}

#[derive(Clone)]
struct AppState {
    jwks_cache: Arc<JwksCache>,
    validation: jsonwebtoken::Validation,
}

impl FromRef<AppState> for Arc<JwksCache> {
    fn from_ref(state: &AppState) -> Self {
        state.jwks_cache.clone()
    }
}

impl FromRef<AppState> for jsonwebtoken::Validation {
    fn from_ref(state: &AppState) -> Self {
        state.validation.clone()
    }
}

struct Config {
    issuer: String,
    audience: Option<String>,
    port: u16,
}

impl Config {
    fn from_env() -> Self {
        Self {
            issuer: std::env::var("OIDC_ISSUER")
                .unwrap_or_else(|_| "https://accounts.google.com".to_string()),
            audience: std::env::var("OIDC_AUDIENCE").ok(),
            port: std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `RUST_LOG=authkestra=debug` surfaces the engine's own instrumentation.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,authkestra=debug".into()),
        )
        .init();

    dotenvy::dotenv().ok();
    let config = Config::from_env();

    // 1. Configure Offline Validation components using the builder
    let validation_config = ValidationConfig::builder()
        .jwks_url(format!("{}/.well-known/jwks.json", config.issuer)) // Simplified for the example
        .issuer(&config.issuer)
        .audience(config.audience.as_deref().unwrap_or_default())
        .build();

    let jwks_cache = Arc::new(JwksCache::new(
        validation_config.jwks_url,
        validation_config.refresh_interval,
    ));

    let mut validation = jsonwebtoken::Validation::new(validation_config.algorithms[0]);
    validation.algorithms = validation_config.algorithms;
    if let Some(iss) = validation_config.issuer {
        validation.set_issuer(&[iss]);
        validation.required_spec_claims.insert("iss".to_string());
    }
    if let Some(aud) = config.audience.as_deref() {
        validation.set_audience(&[aud]);
        validation.required_spec_claims.insert("aud".to_string());
    }

    let state = AppState {
        jwks_cache,
        validation,
    };

    // 2. Build Axum Router
    let app = Router::new()
        .route("/", get(index))
        .route("/api/protected", get(protected))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    tracing::info!(
        port = config.port,
        issuer = %config.issuer,
        "Axum resource server listening on http://localhost:{}",
        config.port
    );

    axum::serve(listener, app).await?;

    Ok(())
}

async fn index() -> impl IntoResponse {
    "Axum Resource Server. Use a Bearer token to access /api/protected"
}

async fn protected(Jwt(claims): Jwt<MyClaims>) -> impl IntoResponse {
    tracing::debug!(sub = %claims.sub, "bearer token accepted");
    Json(json!({
        "message": "You have access to this protected resource.",
        "user_id": claims.sub,
        "email": claims.email,
        "scope": claims.scope,
    }))
}
