//! # Axum OP Server with Custom Grant Type Example
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Axum.
use authkestra::Authkestra;
use authkestra_engine::store::KvStore;

use authkestra_axum::OpExt;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_op::client::ClientStore;
use authkestra_op::code::AuthorizationCodeStore;
use authkestra_op::device::DeviceCodeStore;
use authkestra_op::refresh::RefreshTokenStore;
use authkestra_op::store::OpStore;

use authkestra_engine::{AkEngine, TokenManager};
use authkestra_op::{client::ClientRegistration, config::OpConfig};
use axum::Router;

use std::sync::Arc;

use authkestra_axum::AxumState;

#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkEngine,

    #[authkestra(store)]
    op_store: Arc<dyn authkestra_op::CloneableOpStore>,

    #[authkestra(store)]
    config: OpConfig,
}

// -------------------------------------------------------------------------
// CUSTOM GRANT TYPE EXAMPLE
// We wrap `CompositeOpStore` so we can override `handle_custom_grant`.
// -------------------------------------------------------------------------
#[derive(Clone)]
struct MyCustomOpStore<C, A, R, D> {
    inner: authkestra_op::store::CompositeOpStore<C, A, R, D>,
}

#[async_trait::async_trait]
impl<C: ClientStore + Send + Sync, A: Send + Sync, R: Send + Sync, D: Send + Sync> ClientStore
    for MyCustomOpStore<C, A, R, D>
{
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<
        Option<authkestra_op::client::ClientRegistration>,
        authkestra_engine::store::StoreError,
    > {
        self.inner.find_client(client_id).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: AuthorizationCodeStore + Send + Sync, R: Send + Sync, D: Send + Sync>
    AuthorizationCodeStore for MyCustomOpStore<C, A, R, D>
{
    async fn store_code(
        &mut self,
        code: authkestra_op::code::AuthorizationCode,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        self.inner.store_code(code).await
    }
    async fn consume_code(
        &mut self,
        code: &str,
    ) -> Result<Option<authkestra_op::code::AuthorizationCode>, authkestra_engine::store::StoreError>
    {
        self.inner.consume_code(code).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: Send + Sync, R: RefreshTokenStore + Send + Sync, D: Send + Sync>
    RefreshTokenStore for MyCustomOpStore<C, A, R, D>
{
    async fn store_token(
        &mut self,
        token: authkestra_op::refresh::RefreshToken,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        self.inner.store_token(token).await
    }
    async fn consume_token(
        &mut self,
        token: &str,
    ) -> Result<Option<authkestra_op::refresh::RefreshToken>, authkestra_engine::store::StoreError>
    {
        self.inner.consume_token(token).await
    }
    async fn get_token(
        &mut self,
        token: &str,
    ) -> Result<Option<authkestra_op::refresh::RefreshToken>, authkestra_engine::store::StoreError>
    {
        self.inner.get_token(token).await
    }
    async fn revoke_token(
        &mut self,
        token: &str,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        self.inner.revoke_token(token).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: Send + Sync, R: Send + Sync, D: DeviceCodeStore + Send + Sync>
    DeviceCodeStore for MyCustomOpStore<C, A, R, D>
{
    async fn store_device_code(
        &mut self,
        session: authkestra_op::device::DeviceCodeSession,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        self.inner.store_device_code(session).await
    }
    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<
        Option<authkestra_op::device::DeviceCodeSession>,
        authkestra_engine::store::StoreError,
    > {
        self.inner.get_device_code(device_code).await
    }
    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<
        Option<authkestra_op::device::DeviceCodeSession>,
        authkestra_engine::store::StoreError,
    > {
        self.inner.get_by_user_code(user_code).await
    }
    async fn update_device_code(
        &mut self,
        session: authkestra_op::device::DeviceCodeSession,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        self.inner.update_device_code(session).await
    }
    async fn delete_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        self.inner.delete_device_code(device_code).await
    }
    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<
        Option<authkestra_op::device::DeviceCodeSession>,
        authkestra_engine::store::StoreError,
    > {
        self.inner.consume_device_code(device_code).await
    }
}

#[async_trait::async_trait]
impl<
        C: ClientStore + Send + Sync,
        A: AuthorizationCodeStore + Send + Sync,
        R: RefreshTokenStore + Send + Sync,
        D: DeviceCodeStore + Send + Sync,
    > OpStore for MyCustomOpStore<C, A, R, D>
{
    async fn handle_custom_grant(
        &mut self,
        grant_type: &str,
        _req: authkestra_op::handlers::token::TokenRequest,
        client_id: String,
        _client: authkestra_op::client::ClientRegistration,
        _config: &authkestra_op::config::OpConfig,
        tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<
        authkestra_op::handlers::token::TokenResponse,
        authkestra_op::handlers::token::TokenErrorResponse,
    > {
        if grant_type == "urn:example:custom" {
            // Safe to issue here: the framework already verified this client is authorized
            // for "urn:example:custom" (via `client.allows_grant_type`) before dispatching
            // to this method, so no extra grant-type check is needed.
            //
            // In a real implementation you would validate the custom payload here
            // (e.g. a signed assertion, a license key, a device attestation, etc.)
            // before issuing the token. This demo intentionally skips that step because
            // it only exists to illustrate the wiring pattern, not a real credential exchange.
            let access_token = tokens
                .issue_client_token(&client_id, 3600, None, None)
                .unwrap();
            return Ok(authkestra_op::handlers::token::TokenResponse::new(
                access_token,
                "Bearer".to_string(),
                3600,
            ));
        }

        Err(authkestra_op::handlers::token::TokenErrorResponse::new(
            "unsupported_grant_type".to_string(),
            "Unsupported custom grant".to_string(),
        ))
    }
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

    let port = port_from_env();
    let issuer = format!("http://localhost:{port}");

    // The token manager's `iss` claim must equal `OpConfig::issuer` below, or
    // relying parties will reject every id_token this OP mints.
    let token_secret = resolve_token_secret();
    let token_manager = Arc::new(TokenManager::new(&token_secret, Some(issuer.clone())));

    let clients = MemoryStore::new();
    #[allow(deprecated)] // require_pkce (authkestra#273) — PKCE is mandatory unconditionally now
    clients
        .set(
            "test-client",
            ClientRegistration {
                client_id: "test-client".to_string(),
                client_secret_hash: None,
                redirect_uris: vec!["http://localhost:3000/auth/callback/github".to_string()],
                require_pkce: true,
                scopes: vec!["openid".to_string(), "profile".to_string()],
                grant_types: vec![
                    authkestra_op::client::GrantType::AuthorizationCode,
                    authkestra_op::client::GrantType::Custom("urn:example:custom".to_string()),
                ],
                allowed_audiences: vec![],
                token_endpoint_auth_method: None,
                jwks: None,
            },
            std::time::Duration::from_secs(31536000),
        )
        .await
        .unwrap();

    let auth_codes = MemoryStore::new();
    let refresh_tokens = MemoryStore::new();
    let device_codes = MemoryStore::new();

    let op_store: Arc<dyn authkestra_op::CloneableOpStore> = Arc::new(MyCustomOpStore {
        inner: authkestra_op::store::CompositeOpStore::new(
            clients,
            auth_codes,
            refresh_tokens,
            device_codes,
        ),
    });

    // TIP: authkestra uses traits (like `SessionStore`) for storage.
    // This makes it easy to swap out backends! You could easily replace `MemoryStore`
    // with `RedisStore` simply by changing the struct instantiated here.
    let session_store: Arc<dyn authkestra_engine::auth::SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::new());
    let session_config = authkestra_engine::SessionConfig {
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

    tracing::info!(%issuer, "Axum OP server (custom grant) listening on {issuer}");
    tracing::info!("custom grant_type: urn:example:custom");
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
