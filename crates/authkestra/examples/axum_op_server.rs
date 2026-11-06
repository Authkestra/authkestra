//! # Axum OP Server Example
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Axum.
//! This example uses `RedisStore` for both the engine session and the OP data.
//!
//! To run this example, you'll need:
//! - A running Redis instance
//! - `REDIS_URL` environment variable (e.g., `redis://127.0.0.1/`)
//!
//! ```sh
//! REDIS_URL=redis://127.0.0.1/ \
//!   cargo run -p authkestra --example axum_op_server --all-features
//! ```
//!
//! Set `PORT` to bind somewhere other than 8080; `issuer` follows it, because
//! relying parties resolve `/.well-known/openid-configuration` against the
//! issuer URL and a mismatch breaks discovery.
use authkestra::Authkestra;
use authkestra_axum::{AxumState, OpExt};
use authkestra_engine::store::redis::RedisStore;
use authkestra_engine::store::KvStore;
use authkestra_engine::{AkEngine, SessionConfig, SessionStore, TokenManager};
use authkestra_op::{client::ClientRegistration, config::OpConfig};
use axum::Router;
use std::sync::Arc;

/// `AkEngine` is the alias for an engine with *both* a session store and a
/// token manager — an OP needs the session to authenticate the end user at
/// `/authorize` and the token manager to sign what it hands back.
#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkEngine,

    #[authkestra(store)]
    op_store: Arc<dyn authkestra_op::CloneableOpStore>,

    #[authkestra(store)]
    config: OpConfig,
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
    let issuer = format!("http://localhost:{port}");
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");

    // The token manager's `iss` claim must equal `OpConfig::issuer` below, or
    // relying parties will reject every id_token this OP mints.
    let token_secret = resolve_token_secret();
    let token_manager = Arc::new(TokenManager::new(&token_secret, Some(issuer.clone())));

    // Open a single Redis client and share it across all stores via different key prefixes.
    // This avoids opening multiple TCP connections to Redis.
    let redis_client = redis::Client::open(redis_url.as_str()).expect("Failed to connect to Redis");

    let clients = RedisStore::with_client(redis_client.clone(), "op_clients".into());
    #[allow(deprecated)] // require_pkce (authkestra#273) — PKCE is mandatory unconditionally now
    clients
        .set(
            "test-client",
            ClientRegistration {
                client_id: "test-client".to_string(),
                client_secret_hash: None,
                // The RP's callback, not this server's — an OP redirects back
                // to the client application. This is the path the sibling RP
                // examples actually serve (`/auth/callback/{provider}`), so the
                // OP on :8080 and an RP on :3000 compose without editing either.
                redirect_uris: vec!["http://localhost:3000/auth/callback/github".to_string()],
                require_pkce: true,
                scopes: vec!["openid".to_string(), "profile".to_string()],
                grant_types: vec![authkestra_op::client::GrantType::AuthorizationCode],
                allowed_audiences: vec![],
                token_endpoint_auth_method: None,
                jwks: None,
            },
            std::time::Duration::from_secs(31536000),
        )
        .await
        .unwrap();

    let auth_codes = RedisStore::with_client(redis_client.clone(), "op_codes".into());
    let refresh_tokens = RedisStore::with_client(redis_client.clone(), "op_refresh".into());
    let device_codes = RedisStore::with_client(redis_client.clone(), "op_device".into());

    let op_store: Arc<dyn authkestra_op::CloneableOpStore> =
        Arc::new(authkestra_op::store::CompositeOpStore::new(
            clients,
            auth_codes,
            refresh_tokens,
            device_codes,
        ));

    let session_store: Arc<dyn SessionStore> = Arc::new(RedisStore::with_client(
        redis_client,
        "engine_session".into(),
    ));

    let session_config = SessionConfig {
        cookie_name: "authkestra_sid".to_string(),
        ..Default::default()
    };

    let auth = Authkestra::builder()
        .session_store(session_store)
        .session_config(session_config)
        .token_manager(token_manager)
        .build();

    let state = AppState {
        auth,
        op_store,
        config: OpConfig {
            issuer: issuer.clone(),
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            access_token_ttl_secs: 3600,
            authorization_code_ttl_secs: 600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: true,
        },
    };

    let app = Router::new()
        .merge(state.op_axum_router())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind example server");

    tracing::info!(%issuer, "Axum OP server listening on {issuer}");
    tracing::info!("discovery: {issuer}/.well-known/openid-configuration");
    axum::serve(listener, app).await.unwrap();
}

/// Bind port, overridable via `PORT`. Defaults to 8080 so an OP and a relying
/// party (which the other examples run on 3000) can be started side by side.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080)
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
