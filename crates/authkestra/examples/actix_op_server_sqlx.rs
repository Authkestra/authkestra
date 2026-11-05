//! # Actix OP Server Example with Native SqlxOpStore
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Actix.
//! It uses the batteries-included `SqlxOpStore` for a production-ready relational database schema.
//!
//! Unlike `actix_op_server.rs` (which composes four `KvStore`s), `SqlxOpStore`
//! is a single normalised schema with foreign keys and `ON DELETE CASCADE` —
//! prefer it for OP data over composing generic KV stores by hand.
//!
//! ```sh
//! cargo run -p authkestra --example actix_op_server_sqlx --all-features
//! ```
//!
//! Set `PORT` to bind somewhere other than 8080; `issuer` follows it, because
//! relying parties resolve `/.well-known/openid-configuration` against the
//! issuer URL and a mismatch breaks discovery.
use actix_web::{App, HttpServer};
use authkestra::Authkestra;
use authkestra_actix::{ActixState, OpExt};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{AkEngine, SessionConfig, SessionStore, TokenManager};
use authkestra_op::config::OpConfig;
use authkestra_store_sqlx::SqlxOpStore;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;

#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkEngine,

    #[authkestra(store)]
    op_store: Arc<dyn authkestra_op::CloneableOpStore>,

    #[authkestra(store)]
    config: OpConfig,
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

    let port = port_from_env();
    let issuer = format!("http://localhost:{port}");

    // The token manager's `iss` claim must equal `OpConfig::issuer` below, or
    // relying parties will reject every id_token this OP mints.
    let token_secret = resolve_token_secret();
    let token_manager = Arc::new(TokenManager::new(&token_secret, Some(issuer.clone())));

    // Create a SQLite connection pool (in-memory for the example, but can be a file path).
    // Capped to a single connection: SQLite's `:memory:` URI gives every
    // connection its own private, independent database, so a multi-connection
    // pool would scatter this store's rows across several unrelated
    // in-memory databases — `migrate()` would create tables in whichever one
    // it happens to check out, and a second concurrent request could hit a
    // different, un-migrated connection and see "no such table". A real
    // (file-backed) database has no such problem and should drop this.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // Use the batteries-included native SQL store (SqlxOpStore)
    // This provides a highly opinionated schema with cascading deletes and strict relational integrity
    let sqlx_store = SqlxOpStore::<sqlx::Sqlite>::new(pool.clone());

    // Automatically run schema migrations to create the required tables
    sqlx_store.migrate().await.unwrap();

    // Seed a demo OAuth client. `ClientStore` is read-only by design —
    // registration is the deployment's business — so the example writes the
    // row directly. `redirect_uris` is the *relying party's* callback, not
    // this server's.
    sqlx::query(
        "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind("test-client")
    .bind(None::<String>)
    .bind(true)
    .bind(sqlx::types::Json(vec!["http://localhost:3000/auth/callback/github"]))
    .bind(sqlx::types::Json(vec!["authorization_code"]))
    .bind(sqlx::types::Json(vec!["openid", "profile"]))
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .execute(&pool)
    .await
    .unwrap();

    let op_store: Arc<dyn authkestra_op::CloneableOpStore> = Arc::new(sqlx_store);

    let config = OpConfig {
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
    };

    // Only the OP data lives in SQL here; the end-user login session can use
    // any `SessionStore`, so the example keeps that part dependency-free.
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());

    let auth = Authkestra::builder()
        .session_store(session_store)
        .session_config(SessionConfig {
            cookie_name: "authkestra_sid".to_string(),
            ..Default::default()
        })
        .token_manager(token_manager)
        .build();

    let app_state = AppState {
        auth,
        op_store,
        config,
    };

    tracing::info!(%issuer, "Actix OP server (SqlxOpStore) listening on {issuer}");
    tracing::info!("discovery: {issuer}/.well-known/openid-configuration");

    HttpServer::new(move || {
        let state = app_state.clone();
        let config_state = state.clone();
        App::new()
            .app_data(actix_web::web::Data::new(state.clone()))
            .configure(move |cfg| config_state.configure_authkestra(cfg))
            .service(state.op_actix_scope())
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
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
