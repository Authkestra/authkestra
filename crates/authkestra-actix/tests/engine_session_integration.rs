//! Integration tests for the Actix adapter's stateful (session-based) wiring.
//!
//! Mirrors `authkestra-axum`'s `engine_session_integration.rs`: a real
//! `actix_web::App` is built with `Engine::actix_scope()` and driven through
//! `actix_web::test::call_service`, asserting on actual HTTP responses
//! rather than calling engine internals directly. See that file's module doc
//! for the rationale (adapter-level regressions — `app_data` wiring,
//! `configure_authkestra`, `AuthSession` extraction, cookie handling — can't
//! be caught by `authkestra-engine`'s own unit tests).
//!
//! The OAuth provider is a fully in-process mock (no network, no wiremock),
//! matching the axum test's approach.

use actix_web::{
    cookie::Cookie,
    http::{header, StatusCode},
    test, web, App, HttpResponse, Responder,
};
use async_trait::async_trait;
use authkestra_actix::{ActixExt, ActixState, AuthSession};
use authkestra_engine::auth::{
    AuthError, Identity, OAuthProvider, OAuthToken, Provider, ProviderConfig, Session, SessionStore,
};
use authkestra_engine::flow::{Engine, OAuth2Flow};
use authkestra_engine::{AkWebAppEngine, SessionConfig};
use std::collections::HashMap;
use std::sync::Mutex;

/// A deterministic, in-process stand-in for a real OAuth2 provider. Only
/// `"valid-code"` exchanges successfully.
struct MockOAuthProvider;

#[async_trait]
impl Provider for MockOAuthProvider {
    async fn config(&self) -> ProviderConfig {
        ProviderConfig {
            id: "mock".to_string(),
            name: "Mock".to_string(),
            extra: HashMap::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for MockOAuthProvider {
    fn provider_id(&self) -> &str {
        "mock"
    }

    fn get_authorization_url(
        &self,
        state: &str,
        _scopes: &[&str],
        _code_challenge: Option<&str>,
        _nonce: Option<&str>,
    ) -> String {
        format!("https://mock.example.com/authorize?state={state}")
    }

    async fn exchange_code_for_identity(
        &self,
        code: &str,
        _code_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        if code != "valid-code" {
            return Err(AuthError::Token("invalid code".to_string()));
        }

        let mut attributes = HashMap::new();
        // OAuth2Flow::finalize_login rejects the exchange if the identity
        // doesn't echo back the nonce it generated.
        if let Some(n) = nonce {
            attributes.insert("nonce".to_string(), n.to_string());
        }

        Ok((
            Identity {
                provider_id: "mock".to_string(),
                external_id: "user-42".to_string(),
                email: Some("user@example.com".to_string()),
                username: Some("mockuser".to_string()),
                attributes,
            },
            OAuthToken {
                access_token: "at-123".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: Some(3600),
                refresh_token: None,
                scope: None,
                id_token: None,
            },
        ))
    }
}

/// A minimal in-memory `SessionStore`, independent of
/// `authkestra_engine::store::memory::MemoryStore` (which sits behind the
/// `memory` feature) so this test only needs the features it declares via
/// `required-features` in `Cargo.toml`.
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
    auth: AkWebAppEngine,
}

async fn protected(session: AuthSession) -> impl Responder {
    let AuthSession(session) = session;
    HttpResponse::Ok().json(serde_json::json!({
        "external_id": session.identity.external_id,
        "email": session.identity.email,
        "provider": session.identity.provider_id,
    }))
}

fn build_engine() -> AkWebAppEngine {
    let session_store: std::sync::Arc<dyn SessionStore> =
        std::sync::Arc::new(TestSessionStore::default());
    Engine::builder()
        .provider(OAuth2Flow::new(MockOAuthProvider))
        .session_store(session_store)
        .session_config(SessionConfig {
            // Tests talk plain HTTP; a `Secure` cookie would never
            // round-trip back to the server.
            secure: false,
            ..Default::default()
        })
        .build()
}

/// Extracts the value of the first `Set-Cookie` header matching `name`.
fn set_cookie_value(resp: &actix_web::dev::ServiceResponse, name: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let (key, value) = raw.split_once(';').unwrap_or((raw, "")).0.split_once('=')?;
            (key == name).then(|| value.to_string())
        })
}

#[actix_web::test]
async fn protected_route_rejects_request_without_session_cookie() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let req = test::TestRequest::get().uri("/protected").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn full_login_callback_session_and_logout_round_trip() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    // 1. Login initiates the flow: a redirect to the provider, plus an
    //    encrypted `ak_state` CSRF cookie the callback must see again.
    let login_req = test::TestRequest::get()
        .uri("/auth/login/mock")
        .to_request();
    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);

    let location = login_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.starts_with("https://mock.example.com/authorize?state="),
        "unexpected redirect location: {location}"
    );
    let csrf_state = location.rsplit('=').next().unwrap().to_string();
    let ak_state_cookie =
        set_cookie_value(&login_resp, "ak_state").expect("login must set the ak_state CSRF cookie");

    // 2. Callback: present the CSRF cookie, the matching `state`, and a code
    //    the mock provider accepts.
    let callback_req = test::TestRequest::get()
        .uri(&format!(
            "/auth/callback/mock?code=valid-code&state={csrf_state}"
        ))
        .cookie(Cookie::new("ak_state", ak_state_cookie))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;
    assert_eq!(callback_resp.status(), StatusCode::SEE_OTHER);

    let session_cookie = set_cookie_value(&callback_resp, "authkestra_session")
        .expect("a successful callback must set the session cookie");

    // 3. The protected route now succeeds and returns the identity that came
    //    back from the (mock) provider.
    let protected_req = test::TestRequest::get()
        .uri("/protected")
        .cookie(Cookie::new("authkestra_session", session_cookie.clone()))
        .to_request();
    let protected_resp = test::call_service(&app, protected_req).await;
    assert_eq!(protected_resp.status(), StatusCode::OK);
    let json: serde_json::Value = test::read_body_json(protected_resp).await;
    assert_eq!(json["external_id"], "user-42");
    assert_eq!(json["email"], "user@example.com");
    assert_eq!(json["provider"], "mock");

    // 4. Logout deletes the session server-side...
    let logout_req = test::TestRequest::get()
        .uri("/auth/logout")
        .cookie(Cookie::new("authkestra_session", session_cookie.clone()))
        .to_request();
    let logout_resp = test::call_service(&app, logout_req).await;
    assert_eq!(logout_resp.status(), StatusCode::SEE_OTHER);

    // 5. ...so presenting the very same session cookie again is rejected.
    let after_logout_req = test::TestRequest::get()
        .uri("/protected")
        .cookie(Cookie::new("authkestra_session", session_cookie))
        .to_request();
    let after_logout_resp = test::call_service(&app, after_logout_req).await;
    assert_eq!(after_logout_resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn callback_rejects_mismatched_csrf_state() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let login_req = test::TestRequest::get()
        .uri("/auth/login/mock")
        .to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let ak_state_cookie = set_cookie_value(&login_resp, "ak_state").unwrap();

    // The `state` query param doesn't match the one encrypted into the
    // `ak_state` cookie: this must be treated as a CSRF failure.
    let callback_req = test::TestRequest::get()
        .uri("/auth/callback/mock?code=valid-code&state=not-the-real-state")
        .cookie(Cookie::new("ak_state", ak_state_cookie))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;

    assert_eq!(callback_resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn callback_rejects_missing_csrf_cookie() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    // No `ak_state` cookie at all.
    let callback_req = test::TestRequest::get()
        .uri("/auth/callback/mock?code=valid-code&state=whatever")
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;

    assert_eq!(callback_resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn callback_rejects_provider_exchange_failure() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let login_req = test::TestRequest::get()
        .uri("/auth/login/mock")
        .to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let location = login_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let csrf_state = location.rsplit('=').next().unwrap().to_string();
    let ak_state_cookie = set_cookie_value(&login_resp, "ak_state").unwrap();

    // A code the mock provider doesn't recognize as valid.
    let callback_req = test::TestRequest::get()
        .uri(&format!(
            "/auth/callback/mock?code=wrong-code&state={csrf_state}"
        ))
        .cookie(Cookie::new("ak_state", ak_state_cookie))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;

    assert_eq!(callback_resp.status(), StatusCode::UNAUTHORIZED);
}

/// An unregistered provider is a client error, and the body that names it must
/// not be sniffable as HTML.
///
/// The actix adapter has always answered 404 here — issue #320 was that axum
/// answered 500 for the same request. What was missing on this side is the
/// content type: `HttpResponseBuilder::body` sets none, and a typeless response
/// echoing a URL-decoded path segment is sniffed as HTML by browsers, which
/// makes this message a reflected-XSS sink reachable from a plain link.
#[actix_web::test]
async fn an_unknown_provider_is_not_found_and_not_sniffable() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope()),
    )
    .await;

    // A payload that is inert as text and executable as HTML.
    let req = test::TestRequest::get()
        .uri("/auth/login/%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string())
        .expect("a body echoing a path segment must declare its content type");
    assert!(
        content_type.starts_with("text/plain"),
        "the 404 body must be text/plain, got {content_type:?}"
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff"),
        "without nosniff a browser may still sniff the echoed name as HTML"
    );
}

/// The 404 body echoes the provider name, so the reflection has to be bounded.
/// `authkestra-axum` bounds it identically; this is the test that keeps the two
/// in step, rather than a pair of doc comments asserting it.
#[actix_web::test]
async fn a_long_provider_name_is_truncated_in_the_body() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope()),
    )
    .await;

    let long = "a".repeat(5_000);
    let req = test::TestRequest::get()
        .uri(&format!("/auth/login/{long}"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = test::read_body(resp).await;
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body.len() < 200,
        "the body reflected {} bytes: {body:.120?}",
        body.len()
    );
    assert!(
        body.contains('\u{2026}'),
        "truncation should be visible: {body:?}"
    );
}

/// The login redirect is a 303, matching `authkestra-axum`.
///
/// This adapter answered 302 until the parity sweep: the same request produced
/// a different status code depending on which adapter an application happened
/// to be built on, which is the class of divergence issue #320 was filed about.
/// Every route here is a GET, so both codes send the browser to the same place
/// — but 303 says "fetch the other resource with GET" without relying on the
/// method-rewriting that made 302 ambiguous in the first place.
///
/// The axum suite pins the same code in
/// `a_registered_provider_still_redirects`. Both are needed: a comment saying
/// the adapters agree is not a thing that can fail.
#[actix_web::test]
async fn the_login_redirect_is_a_see_other_like_axum() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope()),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/auth/login/mock")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        resp.headers().contains_key(header::LOCATION),
        "a redirect must carry a Location header"
    );
}

// --- OAuth callback failure diagnosis (#353) ---
//
// Mirrors `authkestra-axum`'s tests of the same name, case for case. The
// three ways a callback can fail all return 401 with a message the client
// sees, so the only thing telling a missing state cookie apart from an
// undecryptable one — the shape a rotated `state_encryption_key` takes — is
// the log line.

/// Routes each thread's `tracing` output to that thread's own buffer, and
/// discards it on threads that are not capturing.
///
/// A **global** subscriber, installed once, rather than a thread-local one.
/// `tracing` caches callsite interest globally and a thread-local subscriber
/// does not invalidate that cache, so any test reaching a callsite while no
/// subscriber is installed gets its interest cached as "never" — and a later
/// thread-local capture there sees nothing. Rebuilding the cache does not fix
/// it either, because the non-capturing tests run concurrently and re-cache
/// "never" immediately after. Both were tried; both produced a capture that
/// passed alone and failed in a parallel run (#353).
mod capture {
    use std::cell::RefCell;
    use std::io;
    use std::sync::{Arc, Mutex, Once};

    thread_local! {
        static SINK: RefCell<Option<Arc<Mutex<Vec<u8>>>>> = const { RefCell::new(None) };
    }

    #[derive(Clone, Copy, Default)]
    pub struct ThreadSink;

    impl io::Write for ThreadSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            SINK.with(|sink| {
                if let Some(target) = sink.borrow().as_ref() {
                    target.lock().unwrap().extend_from_slice(buf);
                }
            });
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ThreadSink {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            *self
        }
    }

    static INSTALL: Once = Once::new();

    fn install() {
        INSTALL.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_writer(ThreadSink)
                .with_max_level(tracing::Level::TRACE)
                .without_time()
                .try_init();
        });
    }

    /// Starts capturing on this thread; the returned handle yields the output.
    pub struct Handle(Arc<Mutex<Vec<u8>>>);

    impl Handle {
        pub fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            SINK.with(|sink| *sink.borrow_mut() = None);
        }
    }

    pub fn start() -> Handle {
        install();
        let buffer = Arc::new(Mutex::new(Vec::new()));
        SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buffer)));
        Handle(buffer)
    }
}

/// Drives a callback carrying `state_cookie` (if any) and returns the status
/// alongside everything logged while doing it.
async fn callback_with_state(state_cookie: Option<&str>) -> (StatusCode, String) {
    let captured = capture::start();

    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope()),
    )
    .await;

    let mut req =
        test::TestRequest::get().uri("/auth/callback/mock?code=valid-code&state=whatever");
    if let Some(cookie) = state_cookie {
        req = req.cookie(Cookie::new("ak_state", cookie));
    }
    let resp = test::call_service(&app, req.to_request()).await;

    let status = resp.status();
    let logs = captured.contents();
    (status, logs)
}

#[actix_web::test]
async fn a_callback_with_no_state_cookie_says_so() {
    let (status, logs) = callback_with_state(None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        logs.contains("carries no state cookie"),
        "an absent state cookie should be named as such; got:\n{logs}"
    );
    assert!(
        !logs.contains("could not be decrypted"),
        "an absent cookie must not be reported as an undecryptable one:\n{logs}"
    );
}

/// The case worth separating: this is what a rotated `state_encryption_key`
/// looks like, and it is indistinguishable from the one above over HTTP.
#[actix_web::test]
async fn a_callback_whose_state_cookie_will_not_decrypt_says_so() {
    let (status, logs) = callback_with_state(Some("not-a-valid-encrypted-state")).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        logs.contains("could not be decrypted"),
        "an unreadable state cookie should be named as such; got:\n{logs}"
    );
    assert!(
        logs.contains("state encryption key"),
        "the log should point at key rotation, which is the usual cause; got:\n{logs}"
    );
    assert!(
        !logs.contains("carries no state cookie"),
        "a present-but-unreadable cookie must not be reported as absent:\n{logs}"
    );
}

/// A session store that refuses every write, for the paths a working store
/// never reaches. Mirrors `authkestra-axum`'s store of the same name.
#[derive(Default)]
struct FailingSessionStore;

#[async_trait]
impl SessionStore for FailingSessionStore {
    async fn load_session(&self, _id: &str) -> Result<Option<Session>, AuthError> {
        Ok(None)
    }
    async fn save_session(&self, _session: &Session) -> Result<(), AuthError> {
        Err(AuthError::Session("store unavailable".to_string()))
    }
    async fn delete_session(&self, _id: &str) -> Result<(), AuthError> {
        Err(AuthError::Session("store unavailable".to_string()))
    }
}

fn engine_with_failing_store() -> AkWebAppEngine {
    let session_store: std::sync::Arc<dyn SessionStore> = std::sync::Arc::new(FailingSessionStore);
    Engine::builder()
        .provider(OAuth2Flow::new(MockOAuthProvider))
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .build()
}

/// Drives `build` against a freshly-built app with logging captured.
async fn drive_capturing(
    engine: AkWebAppEngine,
    request: test::TestRequest,
) -> (StatusCode, String) {
    let captured = capture::start();

    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope()),
    )
    .await;

    let resp = test::call_service(&app, request.to_request()).await;
    let status = resp.status();
    let logs = captured.contents();
    (status, logs)
}

/// A store that cannot persist the session turns a successful authentication
/// into a 500. The user authenticated fine; the failure is ours.
#[actix_web::test]
async fn a_store_that_cannot_save_fails_the_login_and_says_why() {
    let engine = engine_with_failing_store();

    // A login first, to obtain a genuine state cookie and CSRF value.
    let state = AppState {
        auth: engine.clone(),
    };
    let login_engine = engine.clone();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(login_engine.actix_scope()),
    )
    .await;
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/auth/login/mock")
            .to_request(),
    )
    .await;
    let ak_state = set_cookie_value(&login_resp, "ak_state").expect("login sets ak_state");
    let csrf_state = login_resp
        .headers()
        .get(header::LOCATION)
        .and_then(|l| l.to_str().ok())
        .and_then(|l| l.split("state=").nth(1))
        .expect("the redirect carries a state parameter")
        .to_string();

    let (status, logs) = drive_capturing(
        engine,
        test::TestRequest::get()
            .uri(&format!(
                "/auth/callback/mock?code=valid-code&state={csrf_state}"
            ))
            .cookie(Cookie::new("ak_state", ak_state)),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        logs.contains("failed to persist the session after a successful login"),
        "the store failure should be reported, and distinguished from an auth failure; got:\n{logs}"
    );
}

/// Logging out without a session cookie clears the cookie and succeeds. It is
/// a no-op, not a failure.
#[actix_web::test]
async fn logging_out_without_a_session_is_a_no_op_and_says_so() {
    let (status, logs) =
        drive_capturing(build_engine(), test::TestRequest::get().uri("/auth/logout")).await;

    assert!(
        status.is_redirection(),
        "a logout with no session should still redirect, got {status}"
    );
    assert!(
        logs.contains("logout with no session cookie present"),
        "the no-op case should be visible; got:\n{logs}"
    );
}

/// A store that cannot delete turns logout into a 500 rather than silently
/// leaving the session live.
#[actix_web::test]
async fn a_store_that_cannot_delete_fails_the_logout_and_says_why() {
    let cookie_name = SessionConfig::default().cookie_name;
    let (status, logs) = drive_capturing(
        engine_with_failing_store(),
        test::TestRequest::get()
            .uri("/auth/logout")
            .cookie(Cookie::new(cookie_name, "some-session-id")),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        logs.contains("failed to delete the session during logout"),
        "a failed deletion must not pass for a successful logout; got:\n{logs}"
    );
}

/// Expired sessions are rejected with 401 and removed from the session store by the Actix extractor.
#[actix_web::test]
async fn expired_session_in_actix_extractor_is_rejected_and_cleaned_up() {
    let session_store = std::sync::Arc::new(TestSessionStore::default());
    let expired_session = Session::new(
        "expired-session-id".to_string(),
        Identity {
            provider_id: "mock".to_string(),
            external_id: "user-42".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        },
        chrono::Utc::now() - chrono::Duration::minutes(5),
    );
    session_store.save_session(&expired_session).await.unwrap();

    let engine = Engine::builder()
        .provider(OAuth2Flow::new(MockOAuthProvider))
        .session_store(session_store.clone() as std::sync::Arc<dyn SessionStore>)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .build();

    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let cookie_name = SessionConfig::default().cookie_name;
    let req = test::TestRequest::get()
        .uri("/protected")
        .cookie(Cookie::new(cookie_name, "expired-session-id"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(session_store
        .sessions
        .lock()
        .unwrap()
        .get("expired-session-id")
        .is_none());
}

/// Unsafe `success_url` query values are ignored during login and fall back to `/` on callback.
#[actix_web::test]
async fn unsafe_success_url_is_sanitized_to_default_redirect_actix() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/auth/login/mock?success_url=https://attacker.com")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let state_cookie = set_cookie_value(&resp, "ak_state").expect("must set ak_state cookie");
    let state_param = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|l| l.to_str().ok())
        .and_then(|l| l.split("state=").nth(1))
        .expect("the redirect carries a state parameter")
        .to_string();

    let callback_req = test::TestRequest::get()
        .uri(&format!(
            "/auth/callback/mock?code=valid-code&state={state_param}"
        ))
        .cookie(Cookie::new("ak_state", state_cookie))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;
    assert_eq!(callback_resp.status(), StatusCode::SEE_OTHER);
    let location = callback_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(location, "/");
}

/// Safe relative `success_url` query values are preserved and redirected to on callback.
#[actix_web::test]
async fn safe_success_url_is_preserved_on_callback_actix() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/auth/login/mock?success_url=/dashboard/home")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let state_cookie = set_cookie_value(&resp, "ak_state").expect("must set ak_state cookie");
    let state_param = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|l| l.to_str().ok())
        .and_then(|l| l.split("state=").nth(1))
        .expect("the redirect carries a state parameter")
        .to_string();

    let callback_req = test::TestRequest::get()
        .uri(&format!(
            "/auth/callback/mock?code=valid-code&state={state_param}"
        ))
        .cookie(Cookie::new("ak_state", state_cookie))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;
    assert_eq!(callback_resp.status(), StatusCode::SEE_OTHER);
    let location = callback_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(location, "/dashboard/home");
}

/// Cross-site logout requests carrying `Sec-Fetch-Site: cross-site` are rejected with 401.
#[actix_web::test]
async fn logout_rejects_cross_site_fetch_metadata_actix() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;
    let cookie_name = SessionConfig::default().cookie_name;

    // Cross-site GET
    let req = test::TestRequest::get()
        .uri("/auth/logout")
        .cookie(Cookie::new(cookie_name.clone(), "test-session-id"))
        .insert_header(("sec-fetch-site", "cross-site"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Cross-site POST
    let req_post = test::TestRequest::post()
        .uri("/auth/logout")
        .cookie(Cookie::new(cookie_name, "test-session-id"))
        .insert_header(("sec-fetch-site", "cross-site"))
        .to_request();
    let resp_post = test::call_service(&app, req_post).await;
    assert_eq!(resp_post.status(), StatusCode::UNAUTHORIZED);
}

/// Same-origin POST requests to `/auth/logout` delete the session and redirect.
#[actix_web::test]
async fn logout_via_post_succeeds_for_same_origin_actix() {
    let session_store = std::sync::Arc::new(TestSessionStore::default());
    let valid_session = Session::new(
        "post-session-id".to_string(),
        Identity {
            provider_id: "mock".to_string(),
            external_id: "user-42".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        },
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session_store.save_session(&valid_session).await.unwrap();

    let engine = Engine::builder()
        .provider(OAuth2Flow::new(MockOAuthProvider))
        .session_store(session_store.clone() as std::sync::Arc<dyn SessionStore>)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .build();

    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let cookie_name = SessionConfig::default().cookie_name;
    let req = test::TestRequest::post()
        .uri("/auth/logout")
        .cookie(Cookie::new(cookie_name, "post-session-id"))
        .insert_header(("sec-fetch-site", "same-origin"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(session_store
        .sessions
        .lock()
        .unwrap()
        .get("post-session-id")
        .is_none());
}
