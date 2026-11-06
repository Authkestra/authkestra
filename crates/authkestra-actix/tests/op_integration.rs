//! Adapter-level integration tests for the Actix OpenID Provider handlers.
//!
//! Mirrors `authkestra-axum/tests/op_integration.rs` case for case. Covering
//! one adapter alone is exactly what produced the gap #329 is about: #327
//! moved three actix OP redirects from 302 to 303 and nothing could observe
//! it, because `actix_authorize_handler` appeared in no test file.
//!
//! A real `actix_web::App` is built the way an application builds one —
//! `configure_authkestra` for the state, `op_actix_scope()` for the routes —
//! and driven through `actix_web::test::call_service`.

use actix_web::{
    http::{header, StatusCode},
    test, App,
};
use async_trait::async_trait;
use authkestra_actix::{ActixState, OpExt};
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
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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

#[derive(Clone, ActixState)]
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

/// Builds the app state. `logged_in` decides whether the session the requests
/// present actually exists in the store — the only thing separating the
/// authenticated and unauthenticated paths through `/authorize`.
fn build_state(logged_in: bool) -> AppState {
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

    AppState {
        auth: engine,
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
    }
}

/// The same shape an application builds: state through
/// `configure_authkestra`, routes through `op_actix_scope()`.
macro_rules! op_app {
    ($logged_in:expr) => {{
        let state = build_state($logged_in);
        let scope_source = state.clone();
        test::init_service(
            App::new()
                .configure(move |cfg| state.configure_authkestra(cfg))
                .service(scope_source.op_actix_scope()),
        )
        .await
    }};
}

fn authorize_uri(client_id: &str) -> String {
    format!(
        "/authorize?client_id={client_id}&redirect_uri={REDIRECT_URI}\
         &response_type=code&scope=openid&state=xyz\
         &code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
    )
}

fn session_cookie() -> (String, String) {
    // Read the cookie name off the config rather than hardcoding it, so a
    // change to the default cannot silently turn every authenticated case
    // below into an unauthenticated one that still passes its own assertions.
    (SessionConfig::default().cookie_name, SESSION_ID.to_string())
}

fn location(resp: &actix_web::dev::ServiceResponse) -> &str {
    resp.headers()
        .get(header::LOCATION)
        .expect("a redirect must carry a Location header")
        .to_str()
        .unwrap()
}

// --- Tests ----------------------------------------------------------------

#[actix_web::test]
async fn authorize_without_a_session_redirects_to_login() {
    let app = op_app!(false);
    let req = test::TestRequest::get()
        .uri(&authorize_uri(CLIENT_ID))
        .to_request();
    let resp = test::call_service(&app, req).await;

    // Pinned exactly, not just `is_redirection()`. #327 moved these from 302
    // to 303 with no test able to observe it, which is the hole #329 exists
    // to close -- and the two adapters must agree on the value.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/login");
}

/// A session cookie naming a session the store does not have must be treated
/// as no session at all, not as an error page.
#[actix_web::test]
async fn authorize_with_an_unknown_session_cookie_redirects_to_login() {
    let app = op_app!(false);
    let (name, value) = session_cookie();
    let req = test::TestRequest::get()
        .uri(&authorize_uri(CLIENT_ID))
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/login");
}

/// A session that exists but is not *fresh enough* — `prompt=login` demands a
/// new authentication regardless of age (#381) — must reach the host app's
/// `/login`, not the client's `redirect_uri` with a code.
///
/// This pins the adapter's `ReauthenticationRequired` arm specifically. With a
/// valid session present the request would otherwise return a code, and if
/// that arm were missing the now-`#[non_exhaustive]` `AuthorizeOutcome` match
/// would fall through to the catch-all and answer 500 — so neither the
/// no-session path nor a broken mapping can make this pass. The axum adapter
/// has the identical pair; the two must agree, which is the hole #329 exists
/// to close.
#[actix_web::test]
async fn authorize_with_prompt_login_redirects_to_login_despite_a_session() {
    let app = op_app!(true);
    let (name, value) = session_cookie();
    let req = test::TestRequest::get()
        .uri(&format!("{}&prompt=login", authorize_uri(CLIENT_ID)))
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .to_request();
    let resp = test::call_service(&app, req).await;

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
#[actix_web::test]
async fn authorize_with_max_age_redirects_to_login_despite_a_session() {
    let app = op_app!(true);
    let (name, value) = session_cookie();
    let req = test::TestRequest::get()
        .uri(&format!("{}&max_age=60", authorize_uri(CLIENT_ID)))
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/login");
}

/// The `AuthorizeOutcome::Redirect` arm: back to the client's registered
/// `redirect_uri`, carrying a code and echoing `state`.
#[actix_web::test]
async fn authorize_with_a_session_redirects_back_to_the_client_with_a_code() {
    let app = op_app!(true);
    let (name, value) = session_cookie();
    let req = test::TestRequest::get()
        .uri(&authorize_uri(CLIENT_ID))
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .to_request();
    let resp = test::call_service(&app, req).await;

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
#[actix_web::test]
async fn authorize_with_an_unknown_client_returns_400_and_does_not_redirect() {
    let app = op_app!(true);
    let (name, value) = session_cookie();
    let req = test::TestRequest::get()
        .uri(&authorize_uri("no-such-client"))
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        resp.headers().get(header::LOCATION).is_none(),
        "an unverifiable client must never be redirected"
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"].is_string(),
        "the error body should describe the failure: {body}"
    );
}

/// The device-verification endpoint gates on the session exactly as
/// `/authorize` does.
#[actix_web::test]
async fn device_verify_without_a_session_redirects_to_login() {
    let app = op_app!(false);
    let req = test::TestRequest::post()
        .uri("/device/verify")
        .set_form(serde_json::json!({ "user_code": USER_CODE, "approve": "true" }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/login");
}

/// The consent path: an authenticated user approving a pending device code.
/// This is the `/device/verify` arm that actually reaches the handler, as
/// opposed to the session gate in front of it.
#[actix_web::test]
async fn device_verify_with_a_session_records_the_users_approval() {
    let app = op_app!(true);
    let (name, value) = session_cookie();
    let req = test::TestRequest::post()
        .uri("/device/verify")
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .set_form(serde_json::json!({ "user_code": USER_CODE, "approve": "true" }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["success"], true);
}

/// The unauthenticated endpoints stay reachable without a session — proof the
/// session gate is on the endpoints that need it rather than the whole scope.
#[actix_web::test]
async fn discovery_and_jwks_need_no_session() {
    let app = op_app!(false);

    let req = test::TestRequest::get()
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["issuer"], "https://op.example.com");

    let req = test::TestRequest::get().uri("/jwks.json").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Cross-site `/device/verify` requests with `Sec-Fetch-Site: cross-site` are rejected.
#[actix_web::test]
async fn device_verify_rejects_cross_site_fetch_metadata_actix() {
    let app = op_app!(true);
    let (name, value) = session_cookie();
    let req = test::TestRequest::post()
        .uri("/device/verify")
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .insert_header(("sec-fetch-site", "cross-site"))
        .set_form(serde_json::json!({ "user_code": USER_CODE, "approve": "true" }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "access_denied");
}

/// `/device/verify` requests whose `Origin` header mismatches the configured issuer origin are rejected.
#[actix_web::test]
async fn device_verify_rejects_origin_mismatch_actix() {
    let app = op_app!(true);
    let (name, value) = session_cookie();
    let req = test::TestRequest::post()
        .uri("/device/verify")
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .insert_header((header::ORIGIN, "https://attacker.example.com"))
        .set_form(serde_json::json!({ "user_code": USER_CODE, "approve": "true" }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "access_denied");
}

/// `/device/verify` requests with a matching `Origin` header succeed.
#[actix_web::test]
async fn device_verify_accepts_matching_origin_actix() {
    let app = op_app!(true);
    let (name, value) = session_cookie();
    let req = test::TestRequest::post()
        .uri("/device/verify")
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .insert_header((header::ORIGIN, "https://op.example.com"))
        .set_form(serde_json::json!({ "user_code": USER_CODE, "approve": "true" }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["success"], true);
}

/// `/device/verify` requests supplying an invalid `csrf_token` are rejected.
#[actix_web::test]
async fn device_verify_rejects_invalid_csrf_token_actix() {
    let app = op_app!(true);
    let (name, value) = session_cookie();
    let req = test::TestRequest::post()
        .uri("/device/verify")
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .set_form(serde_json::json!({
            "user_code": USER_CODE,
            "approve": "true",
            "csrf_token": "invalid-token"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "access_denied");
}

/// `/device/verify` requests supplying a valid session-bound `csrf_token` succeed.
#[actix_web::test]
async fn device_verify_accepts_valid_csrf_token_actix() {
    let key = [99u8; 32];
    let session_store = TestSessionStore::default();
    session_store.sessions.lock().unwrap().insert(
        SESSION_ID.to_string(),
        Session::new(
            SESSION_ID.to_string(),
            Identity {
                provider_id: "test".to_string(),
                external_id: "user-123".to_string(),
                email: Some("user@example.com".to_string()),
                username: Some("user".to_string()),
                attributes: HashMap::new(),
            },
            chrono::Utc::now() + chrono::Duration::hours(1),
        ),
    );

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

    let mut sess_cfg = SessionConfig::new(key);
    sess_cfg.secure = false;

    let engine = Engine::builder()
        .session_store(Arc::new(session_store) as Arc<dyn SessionStore>)
        .session_config(sess_cfg)
        .token_manager(Arc::new(TokenManager::new(
            b"a-test-signing-key-that-is-32-bytes!!",
            Some("https://op.example.com".to_string()),
        )))
        .build();

    let state = AppState {
        auth: engine,
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

    let scope_source = state.clone();
    let app = test::init_service(
        App::new()
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(scope_source.op_actix_scope()),
    )
    .await;

    let (name, value) = session_cookie();
    let valid_token = authkestra_op::handlers::device_verify::generate_csrf_token(&key, &value);
    let req = test::TestRequest::post()
        .uri("/device/verify")
        .cookie(actix_web::cookie::Cookie::new(name, value))
        .set_form(serde_json::json!({
            "user_code": USER_CODE,
            "approve": "true",
            "csrf_token": valid_token
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["success"], true);
}
