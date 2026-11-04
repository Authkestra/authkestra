//! Adapter-level integration tests for the Axum OpenID Provider handlers.
//!
//! `authkestra-op` tests `handle_authorize` and friends directly, but nothing
//! exercised the Axum wiring around them: state extraction of `OpConfig` and
//! `CloneableOpStore` via `FromRef`, the session lookup that gates
//! `/authorize`, and the mapping of `AuthorizeOutcome` onto real HTTP
//! responses. That gap already cost something — #327 changed redirect statuses
//! in `op.rs` and no test could observe it (#329).
//!
//! These build the real router an application gets from `op_axum_router()` and
//! drive it with `tower::ServiceExt::oneshot`, asserting on status codes,
//! `Location` headers and JSON bodies. The sibling
//! `authkestra-actix/tests/op_integration.rs` mirrors this file case for case:
//! covering one adapter alone is what produced the asymmetry in the first
//! place.

use async_trait::async_trait;
use authkestra_axum::{AxumState, OpExt};
use authkestra_engine::auth::{AuthError, Identity, Session, SessionStore};
use authkestra_engine::flow::Engine;
use authkestra_engine::oauth2::client::{ClientRegistration, GrantType};
use authkestra_engine::oauth2::code::AuthorizationCode;
use authkestra_engine::oauth2::device::{DeviceCodeSession, DeviceCodeStatus};
use authkestra_engine::oauth2::refresh::RefreshToken;
use authkestra_engine::store::traits::{
    AuthorizationCodeStore, ClientStore, DeviceCodeStore, RefreshTokenStore,
};
use authkestra_engine::store::StoreError;
use authkestra_engine::{AkEngine, SessionConfig, TokenManager};
use authkestra_op::{store::OpStore, CloneableOpStore, OpConfig};
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use tower_cookies::CookieManagerLayer;

const CLIENT_ID: &str = "test-client";
const REDIRECT_URI: &str = "https://rp.example.com/callback";
const SESSION_ID: &str = "test-session-id";
const DEVICE_CODE: &str = "test-device-code";
const USER_CODE: &str = "WDJB-MJHT";
/// Any valid S256 challenge; PKCE is mandatory on this grant (authkestra#273).
const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

// --- Fixtures -------------------------------------------------------------

/// An in-memory `OpStore`, written out rather than reusing a backend behind a
/// feature flag so this test needs only the features it declares.
#[derive(Clone, Default)]
struct TestOpStore {
    clients: Arc<Mutex<HashMap<String, ClientRegistration>>>,
    codes: Arc<Mutex<HashMap<String, AuthorizationCode>>>,
    refresh: Arc<Mutex<HashMap<String, RefreshToken>>>,
    devices: Arc<Mutex<HashMap<String, DeviceCodeSession>>>,
}

#[async_trait]
impl ClientStore for TestOpStore {
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, StoreError> {
        Ok(self.clients.lock().unwrap().get(client_id).cloned())
    }
}

#[async_trait]
impl AuthorizationCodeStore for TestOpStore {
    async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), StoreError> {
        self.codes.lock().unwrap().insert(code.code.clone(), code);
        Ok(())
    }

    async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, StoreError> {
        Ok(self.codes.lock().unwrap().remove(code))
    }
}

#[async_trait]
impl RefreshTokenStore for TestOpStore {
    async fn store_token(&mut self, token: RefreshToken) -> Result<(), StoreError> {
        self.refresh
            .lock()
            .unwrap()
            .insert(token.token.clone(), token);
        Ok(())
    }

    async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        Ok(self.refresh.lock().unwrap().get(token).cloned())
    }

    async fn revoke_token(&mut self, token: &str) -> Result<(), StoreError> {
        self.refresh.lock().unwrap().remove(token);
        Ok(())
    }

    async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        Ok(self.refresh.lock().unwrap().remove(token))
    }
}

#[async_trait]
impl DeviceCodeStore for TestOpStore {
    async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        self.devices
            .lock()
            .unwrap()
            .insert(session.device_code.clone(), session);
        Ok(())
    }

    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        Ok(self.devices.lock().unwrap().get(device_code).cloned())
    }

    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        Ok(self
            .devices
            .lock()
            .unwrap()
            .values()
            .find(|s| s.user_code == user_code)
            .cloned())
    }

    async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let mut devices = self.devices.lock().unwrap();
        match devices.get(&session.device_code) {
            Some(existing)
                if matches!(
                    existing.status,
                    authkestra_op::device::DeviceCodeStatus::Pending
                ) =>
            {
                devices.insert(session.device_code.clone(), session);
                Ok(())
            }
            _ => Err(StoreError::NotFound),
        }
    }

    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), StoreError> {
        self.devices.lock().unwrap().remove(device_code);
        Ok(())
    }

    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        Ok(self.devices.lock().unwrap().remove(device_code))
    }
}

impl OpStore for TestOpStore {}

#[derive(Default)]
struct TestSessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

#[async_trait]
impl SessionStore for TestSessionStore {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        Ok(self.sessions.lock().unwrap().get(id).cloned())
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id.clone(), session.clone());
        Ok(())
    }

    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        self.sessions.lock().unwrap().remove(id);
        Ok(())
    }
}

#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkEngine,
    #[authkestra(store)]
    op_store: Arc<dyn CloneableOpStore>,
    #[authkestra(store)]
    config: OpConfig,
}

fn test_client() -> ClientRegistration {
    #[allow(deprecated)] // require_pkce (authkestra#273): PKCE is unconditional now
    ClientRegistration {
        client_id: CLIENT_ID.to_string(),
        client_secret_hash: None,
        redirect_uris: vec![REDIRECT_URI.to_string()],
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: vec!["openid".to_string()],
        require_pkce: true,
        allowed_audiences: vec![],
        token_endpoint_auth_method: None,
        jwks: None,
    }
}

/// Builds the OP router. `logged_in` decides whether the session the requests
/// present actually exists in the store — the only thing separating the
/// authenticated and unauthenticated paths through `/authorize`.
fn build_app(logged_in: bool) -> Router {
    let session_store = TestSessionStore::default();
    if logged_in {
        session_store.sessions.lock().unwrap().insert(
            SESSION_ID.to_string(),
            Session::new(
                SESSION_ID.to_string(),
                Identity {
                    provider_id: "test".to_string(),
                    external_id: "user-1".to_string(),
                    email: Some("user@example.com".to_string()),
                    username: None,
                    attributes: HashMap::new(),
                },
                chrono::Utc::now() + chrono::Duration::hours(1),
            ),
        );
    }

    let op_store = TestOpStore::default();
    op_store
        .clients
        .lock()
        .unwrap()
        .insert(CLIENT_ID.to_string(), test_client());
    op_store.devices.lock().unwrap().insert(
        DEVICE_CODE.to_string(),
        DeviceCodeSession::new(
            DEVICE_CODE.to_string(),
            USER_CODE.to_string(),
            CLIENT_ID.to_string(),
            "openid".to_string(),
            chrono::Utc::now() + chrono::Duration::minutes(10),
            DeviceCodeStatus::Pending,
        ),
    );

    let engine = Engine::builder()
        .session_store(Arc::new(session_store) as Arc<dyn SessionStore>)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .token_manager(Arc::new(TokenManager::new(
            b"a-test-signing-key-that-is-32-bytes!!",
            Some("https://op.example.com".to_string()),
        )))
        .build();

    let state = AppState {
        auth: engine.clone(),
        op_store: Arc::new(op_store),
        config: OpConfig {
            issuer: "https://op.example.com".to_string(),
            scopes_supported: vec!["openid".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            access_token_ttl_secs: 3600,
            authorization_code_ttl_secs: 600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: false,
        },
    };

    Router::new()
        .merge(engine.op_axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state)
}

fn authorize_uri(client_id: &str) -> String {
    format!(
        "/authorize?client_id={client_id}&redirect_uri={REDIRECT_URI}\
         &response_type=code&scope=openid&state=xyz\
         &code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
    )
}

fn with_session(req: axum::http::request::Builder, body: Body) -> Request<Body> {
    // Read the cookie name off the config rather than hardcoding it, so a
    // change to the default cannot silently turn every authenticated case
    // below into an unauthenticated one that still passes its own assertions.
    let cookie_name = SessionConfig::default().cookie_name;
    req.header(header::COOKIE, format!("{cookie_name}={SESSION_ID}"))
        .body(body)
        .unwrap()
}

fn location(resp: &axum::response::Response) -> &str {
    resp.headers()
        .get(header::LOCATION)
        .expect("a redirect must carry a Location header")
        .to_str()
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// --- Tests ----------------------------------------------------------------

#[tokio::test]
async fn authorize_without_a_session_redirects_to_login() {
    let resp = build_app(false)
        .oneshot(
            Request::builder()
                .uri(authorize_uri(CLIENT_ID))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Pinned exactly, not just `is_redirection()`. #327 moved actix's OP
    // redirects from 302 to 303 with no test able to observe it, which is the
    // hole #329 exists to close -- and the two adapters must agree.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/login");
}

/// A session cookie naming a session the store does not have must be treated
/// as no session at all, not as an error page.
#[tokio::test]
async fn authorize_with_an_unknown_session_cookie_redirects_to_login() {
    let resp = build_app(false)
        .oneshot(with_session(
            Request::builder().uri(authorize_uri(CLIENT_ID)),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/login");
}

/// The `AuthorizeOutcome::Redirect` arm: back to the client's registered
/// A session that exists but is not *fresh enough* — `prompt=login` demands a
/// new authentication regardless of age (#381) — must reach the host app's
/// `/login`, not the client's `redirect_uri` with a code.
///
/// This pins the adapter's `ReauthenticationRequired` arm specifically. With a
/// valid session present the request would otherwise return a code, and if
/// that arm were missing the now-`#[non_exhaustive]` `AuthorizeOutcome` match
/// would fall through to the catch-all and answer 500 — so neither the
/// no-session path nor a broken mapping can make this pass.
#[tokio::test]
async fn authorize_with_prompt_login_redirects_to_login_despite_a_session() {
    let resp = build_app(true)
        .oneshot(with_session(
            Request::builder().uri(format!("{}&prompt=login", authorize_uri(CLIENT_ID))),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "re-authentication must redirect, not 500 through the catch-all arm"
    );
    assert_eq!(location(&resp), "/login");
}

/// The same for `max_age`: the fixture session carries no `auth_time`, which
/// cannot satisfy a freshness requirement, so the OP fails closed and the
/// adapter must route that to `/login` too.
#[tokio::test]
async fn authorize_with_max_age_redirects_to_login_despite_a_session() {
    let resp = build_app(true)
        .oneshot(with_session(
            Request::builder().uri(format!("{}&max_age=60", authorize_uri(CLIENT_ID))),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/login");
}

/// `redirect_uri`, carrying a code and echoing `state`.
#[tokio::test]
async fn authorize_with_a_session_redirects_back_to_the_client_with_a_code() {
    let resp = build_app(true)
        .oneshot(with_session(
            Request::builder().uri(authorize_uri(CLIENT_ID)),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "the authorization response redirect must keep its exact status"
    );

    let location = location(&resp);
    assert!(
        location.starts_with(REDIRECT_URI),
        "must redirect to the registered URI, got {location}"
    );
    assert!(
        location.contains("code="),
        "no authorization code: {location}"
    );
    assert!(
        location.contains("state=xyz"),
        "state must be echoed back: {location}"
    );
}

/// The `AuthorizeOutcome::DirectError` arm. An unverifiable `client_id` must
/// **not** redirect — that would hand an authorization response to an
/// unvalidated URI — so it renders 400 directly instead.
#[tokio::test]
async fn authorize_with_an_unknown_client_returns_400_and_does_not_redirect() {
    let resp = build_app(true)
        .oneshot(with_session(
            Request::builder().uri(authorize_uri("no-such-client")),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        resp.headers().get(header::LOCATION).is_none(),
        "an unverifiable client must never be redirected"
    );

    let body = body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"].is_string(),
        "the error body should describe the failure: {body}"
    );
}

/// The device-verification endpoint gates on the session exactly as
/// `/authorize` does.
#[tokio::test]
async fn device_verify_without_a_session_redirects_to_login() {
    let resp = build_app(false)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/device/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("user_code={USER_CODE}&approve=true")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/login");
}

/// The unauthenticated endpoints stay reachable without a session — proof the
/// session gate is on the endpoints that need it rather than the whole router.
#[tokio::test]
async fn discovery_and_jwks_need_no_session() {
    let app = build_app(false);

    let discovery = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(discovery.status(), StatusCode::OK);
    assert_eq!(
        body_json(discovery).await["issuer"],
        "https://op.example.com"
    );

    let jwks = app
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::OK);
}

/// The consent path: an authenticated user approving a pending device code.
/// This is the `/device/verify` arm that actually reaches the handler, as
/// opposed to the session gate in front of it.
#[tokio::test]
async fn device_verify_with_a_session_records_the_users_approval() {
    let resp = build_app(true)
        .oneshot(with_session(
            Request::builder()
                .method("POST")
                .uri("/device/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded"),
            Body::from(format!("user_code={USER_CODE}&approve=true")),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["success"], true);
}
