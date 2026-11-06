use crate::auth::session::{Session, SessionStore};
use crate::auth::{AuthError, AuthInput, AuthMethod, Identity, Provider, ProviderConfig};
use crate::flow::{Flow, FlowContext, FlowResult};
use async_trait::async_trait;
use std::collections::HashMap;

struct MockAuthMethod;
#[async_trait]
impl AuthMethod for MockAuthMethod {
    fn name(&self) -> &str {
        "mock"
    }
    async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
        Ok(Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: Some("mock@example.com".to_string()),
            username: Some("Mock User".to_string()),
            attributes: HashMap::new(),
        })
    }
    async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
        Ok(true) // pretend everyone is enrolled for testing
    }
}

struct MockProvider;
#[async_trait]
impl Provider for MockProvider {
    async fn config(&self) -> ProviderConfig {
        ProviderConfig {
            id: "mock-provider".to_string(),
            name: "Mock Provider".to_string(),
            extra: HashMap::new(),
        }
    }
}

struct MockFlow;
#[async_trait]
impl Flow for MockFlow {
    fn id(&self) -> &str {
        "mock-flow"
    }
    async fn execute(&self, _ctx: FlowContext) -> Result<FlowResult, AuthError> {
        Ok(FlowResult::Complete(Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: Some("mock@example.com".to_string()),
            username: Some("Mock User".to_string()),
            attributes: HashMap::new(),
        }))
    }
}

struct MockSessionStore;
#[async_trait]
impl SessionStore for MockSessionStore {
    async fn load_session(&self, _id: &str) -> Result<Option<Session>, AuthError> {
        Ok(None)
    }
    async fn save_session(&self, _session: &Session) -> Result<(), AuthError> {
        Ok(())
    }
    async fn delete_session(&self, _id: &str) -> Result<(), AuthError> {
        Ok(())
    }
}

#[tokio::test]
async fn test_auth_method_mock() {
    let method = MockAuthMethod;
    let identity = method
        .authenticate(AuthInput::Token("test".to_string()))
        .await
        .unwrap();
    assert_eq!(identity.external_id, "user123");
}

#[tokio::test]
async fn test_provider_mock() {
    let provider = MockProvider;
    assert_eq!(provider.config().await.id, "mock-provider");
}

#[tokio::test]
async fn test_flow_mock() {
    let flow = MockFlow;
    let ctx = FlowContext::new("test".to_string(), HashMap::new());
    let result = flow.execute(ctx).await.unwrap();
    if let FlowResult::Complete(identity) = result {
        assert_eq!(identity.external_id, "user123");
    } else {
        panic!("Expected FlowResult::Complete");
    }
}

#[tokio::test]
async fn test_session_store_mock() {
    let store = MockSessionStore;
    let session = store.load_session("test").await.unwrap();
    assert!(session.is_none());
}

#[test]
fn test_authkestra_builder_typestate() {
    use crate::engine::Engine;
    use std::sync::Arc;

    let builder = Engine::builder();
    let _engine = builder.build();

    let store = MockSessionStore;
    let engine_with_session = Engine::builder().session_store(Arc::new(store)).build();

    let _s = engine_with_session.session_store();
}

struct MockMfaMethod;
#[async_trait]
impl AuthMethod for MockMfaMethod {
    fn name(&self) -> &str {
        "mock_mfa"
    }
    async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
        Ok(Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: Some("mock@example.com".to_string()),
            username: Some("Mock User".to_string()),
            attributes: HashMap::new(),
        })
    }
    async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
        Ok(true) // enrolled
    }
}

#[tokio::test]
async fn test_primary_method_requires_mfa() {
    use crate::auth::AuthResult;
    use crate::Engine;

    struct TestPasswordMethod;
    #[async_trait]
    impl AuthMethod for TestPasswordMethod {
        fn name(&self) -> &str {
            "password"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "password".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
    }

    let engine = Engine::builder()
        .with_auth_method(TestPasswordMethod)
        .with_mfa_method(MockMfaMethod)
        .build();

    let res = engine
        .authenticate(AuthInput::Password {
            identifier: "".to_string(),
            password: "".to_string(),
        })
        .await
        .unwrap();

    match res {
        AuthResult::MfaRequired {
            allowed_methods, ..
        } => {
            assert_eq!(allowed_methods, vec!["mock_mfa"]);
        }
        _ => panic!("Expected MFA required"),
    }
}

#[tokio::test]
#[cfg(feature = "webauthn")]
async fn test_mfa_equivalent_bypasses_mfa() {
    use crate::auth::AuthResult;
    use crate::Engine;

    struct TestWebAuthnMethod;
    #[async_trait]
    impl AuthMethod for TestWebAuthnMethod {
        fn name(&self) -> &str {
            "webauthn"
        }
        fn is_mfa_equivalent(&self) -> bool {
            true
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "webauthn".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
    }

    let engine = Engine::builder()
        .with_auth_method(TestWebAuthnMethod)
        .with_mfa_method(MockMfaMethod)
        .build();

    let res = engine
        .authenticate(AuthInput::WebAuthnAuthentication {
            user_id: "".to_string(),
            credential_id: "".to_string(),
            client_data_json: "".to_string(),
            authenticator_data: "".to_string(),
            signature: "".to_string(),
            user_handle: None,
            auth_state_json: None,
        })
        .await
        .unwrap();

    match res {
        AuthResult::Success(identity) => {
            // No step-up ran, but an `is_mfa_equivalent` primary satisfies
            // this engine's (binary) step-up tier on its own — see
            // `IDENTITY_ATTR_STEP_UP_SATISFIED`.
            assert_eq!(
                identity.attributes.get(crate::auth::IDENTITY_ATTR_AMR),
                Some(&"webauthn".to_string())
            );
            assert_eq!(
                identity
                    .attributes
                    .get(crate::auth::IDENTITY_ATTR_STEP_UP_SATISFIED),
                Some(&"true".to_string())
            );
        }
        _ => panic!("Expected Success"),
    }
}

#[tokio::test]
#[cfg(feature = "totp")]
async fn test_totp_primary_requires_mfa() {
    use crate::auth::AuthResult;
    use crate::Engine;

    struct TestTotpMethod;
    #[async_trait]
    impl AuthMethod for TestTotpMethod {
        fn name(&self) -> &str {
            "totp"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "totp".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
    }

    let engine = Engine::builder()
        .with_auth_method(TestTotpMethod)
        .with_mfa_method(MockMfaMethod)
        .build();

    let res = engine
        .authenticate(AuthInput::Totp {
            user_id: "user123".to_string(),
            code: "123456".to_string(),
        })
        .await
        .unwrap();

    match res {
        AuthResult::MfaRequired {
            allowed_methods, ..
        } => {
            assert_eq!(allowed_methods, vec!["mock_mfa"]);
        }
        _ => panic!("Expected MFA required for TOTP primary"),
    }
}

// --- MFA continuation token: clock-skew window (#350 follow-up) ---
//
// `Engine::authenticate` validates the MFA token that resumes a
// half-completed login. That validation used to take `jsonwebtoken`'s
// 60-second `exp` tolerance silently; it is now stated explicitly. These
// characterize the window rather than a change, because the value did not
// move — the point is that the boundary is now visible in the suite, so
// tightening or widening it later has to be a deliberate edit with a failing
// test attached rather than an invisible consequence of a dependency bump.
//
// `Totp` is the `challenge_input`, not `Password`: `authenticate` maps only
// `Totp`/`WebAuthnAuthentication` to an MFA method and returns
// `InvalidInput` for anything else *before* it ever looks at `exp`. A first
// draft of these tests used `Password`, which made the "beyond the leeway"
// case pass for entirely the wrong reason — it would have passed with the
// expiry check deleted outright.
#[cfg(feature = "totp")]
mod mfa_token_leeway {
    use super::*;
    use crate::auth::AuthResult;
    use crate::Engine;

    /// An MFA method registered under the name the `Totp` challenge maps to,
    /// returning the same `external_id` the MFA token's `sub` carries so the
    /// post-validation user check passes.
    struct MockTotpMethod;
    #[async_trait]
    impl AuthMethod for MockTotpMethod {
        fn name(&self) -> &str {
            "totp"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "totp".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
        async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
            Ok(true)
        }
    }

    fn engine() -> crate::Engine<crate::engine::Missing, crate::engine::Missing> {
        Engine::builder().with_mfa_method(MockTotpMethod).build()
    }

    /// Mints an MFA continuation token whose `exp` is `seconds_ago` in the
    /// past, signed with the engine's own secret so that expiry is the only
    /// thing wrong with it.
    fn expired_mfa_token<S, T>(engine: &crate::Engine<S, T>, seconds_ago: i64) -> String {
        let exp = chrono::Utc::now() - chrono::Duration::seconds(seconds_ago);
        let claims = crate::auth::state::MfaTokenClaims::new(
            "user123",
            exp.timestamp() as usize,
            "password",
        );
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&engine.mfa_jwt_secret),
        )
        .expect("signing the MFA token should succeed")
    }

    fn challenge(mfa_token: String) -> AuthInput {
        AuthInput::MfaChallenge {
            mfa_token,
            challenge_input: Box::new(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: "000000".to_string(),
            }),
        }
    }

    /// A live token resumes the login. Establishes that everything *other*
    /// than expiry is wired correctly, so the rejection below is attributable
    /// to the window and not to the fixture.
    #[tokio::test]
    async fn a_live_mfa_token_resumes_the_login() {
        let engine = engine();
        // Negative "seconds ago" puts `exp` in the future.
        let token = expired_mfa_token(&engine, -600);

        let result = engine.authenticate(challenge(token)).await;
        assert!(
            matches!(result, Ok(AuthResult::Success(_))),
            "a live MFA token should resume the login, got {result:?}"
        );
    }

    #[tokio::test]
    async fn an_mfa_token_expired_within_the_leeway_still_resumes_the_login() {
        let engine = engine();
        let token = expired_mfa_token(&engine, 30);

        let result = engine.authenticate(challenge(token)).await;
        assert!(
            matches!(result, Ok(AuthResult::Success(_))),
            "within DEFAULT_LEEWAY_SECS the token is still honoured, got {result:?}"
        );
    }

    #[tokio::test]
    async fn an_mfa_token_expired_beyond_the_leeway_is_refused() {
        let engine = engine();
        // Comfortably past the tolerance, so this does not sit on the boundary.
        let token = expired_mfa_token(&engine, crate::token::DEFAULT_LEEWAY_SECS as i64 + 60);

        let result = engine.authenticate(challenge(token)).await;
        assert!(
            matches!(result, Err(AuthError::InvalidInput)),
            "past the tolerance a stale MFA token must not resume a login, got {result:?}"
        );
    }
}

// --- Tracing on the authentication path (#353) ---
//
// `Engine::authenticate` was entirely silent: 161 lines covering primary
// dispatch, MFA continuation and four error paths, with no span and no
// events, directly above two fully-instrumented methods. These assert the
// instrumentation exists *and* that it cannot leak what it is handed —
// `AuthInput` carries passwords and TOTP codes, so the span skips the
// argument rather than formatting it.
#[cfg(test)]
mod authenticate_tracing {
    use super::*;
    use crate::test_support::capture;
    use crate::Engine;

    /// A password method that always rejects, so the interesting path (a
    /// failed login) is the one exercised.
    struct RejectingPasswordMethod;
    #[async_trait]
    impl AuthMethod for RejectingPasswordMethod {
        fn name(&self) -> &str {
            "password"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Err(AuthError::Credentials("no such user".into()))
        }
    }

    const SECRET_PASSWORD: &str = "correct-horse-battery-staple-9f3a";

    fn capture_failed_login() -> String {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("building a runtime should succeed");

        let (result, logs) = capture(|| {
            runtime.block_on(async {
                let engine = Engine::builder()
                    .with_auth_method(RejectingPasswordMethod)
                    .build();
                engine
                    .authenticate(AuthInput::Password {
                        identifier: "someone@example.com".to_string(),
                        password: SECRET_PASSWORD.to_string(),
                    })
                    .await
            })
        });
        assert!(result.is_err(), "the fixture must produce a failed login");
        logs
    }

    /// A rejected login has to leave a trace. Before #353 it left none, which
    /// is the whole complaint: successful sessions logged three events and
    /// failed logins logged nothing.
    #[test]
    fn a_rejected_login_is_logged() {
        let logs = capture_failed_login();

        assert!(
            !logs.is_empty(),
            "a failed authentication emitted no log output at all"
        );
        assert!(
            logs.contains("primary authentication rejected"),
            "the rejection itself should be reported; got:\n{logs}"
        );
        assert!(
            logs.contains("no such user"),
            "the underlying reason should be carried through; got:\n{logs}"
        );
    }

    /// The property worth protecting. `AuthInput` carries the password, so
    /// the span skips the argument; if someone later adds it to the span or
    /// logs `input` directly, this fails.
    #[test]
    fn the_password_never_reaches_a_log_line() {
        let logs = capture_failed_login();

        assert!(
            !logs.contains(SECRET_PASSWORD),
            "the password appeared in emitted tracing output:\n{logs}"
        );
    }
}

// --- `Engine::authenticate` error paths (#353) ---
//
// Instrumenting `authenticate` surfaced that almost none of its rejection
// branches had a test: `codecov/patch` flagged ten added lines as uncovered,
// and every one sat on a path that predated the instrumentation. The log
// lines were new; the untested branches were not. These cover the behaviour,
// so the branches are exercised rather than merely annotated.
#[cfg(all(test, feature = "totp"))]
mod authenticate_error_paths {
    use super::*;
    use crate::auth::AuthResult;
    use crate::Engine;

    /// Returns the given identity, whatever it is asked.
    struct FixedTotpMethod(&'static str);
    #[async_trait]
    impl AuthMethod for FixedTotpMethod {
        fn name(&self) -> &str {
            "totp"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "totp".to_string(),
                external_id: self.0.to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
        async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
            Ok(true)
        }
    }

    /// Always refuses the second factor.
    struct RejectingTotpMethod;
    #[async_trait]
    impl AuthMethod for RejectingTotpMethod {
        fn name(&self) -> &str {
            "totp"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Err(AuthError::Credentials("wrong code".into()))
        }
        async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
            Ok(true)
        }
    }

    fn mfa_token<S, T>(engine: &Engine<S, T>, sub: &str, mfa_pending: bool) -> String {
        let mut claims = crate::auth::state::MfaTokenClaims::new(
            sub,
            (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp() as usize,
            "password",
        );
        // `new` sets the only value a real MFA token carries; assigning here
        // is how a test reaches the shape `authenticate` is supposed to reject.
        claims.mfa_pending = mfa_pending;
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&engine.mfa_jwt_secret),
        )
        .expect("signing should succeed")
    }

    fn totp_challenge(mfa_token: String) -> AuthInput {
        AuthInput::MfaChallenge {
            mfa_token,
            challenge_input: Box::new(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: "000000".to_string(),
            }),
        }
    }

    /// A validly-signed, unexpired token is still not a continuation ticket
    /// unless it says so — otherwise any token minted with this secret for
    /// another purpose would resume a half-completed login.
    #[tokio::test]
    async fn a_token_not_marked_mfa_pending_is_refused() {
        let engine = Engine::builder()
            .with_mfa_method(FixedTotpMethod("user123"))
            .build();
        let token = mfa_token(&engine, "user123", false);

        assert!(matches!(
            engine.authenticate(totp_challenge(token)).await,
            Err(AuthError::InvalidInput)
        ));
    }

    /// Only `Totp` and `WebAuthnAuthentication` dispatch as second factors.
    /// Worth pinning: I wrote a test against this path earlier assuming
    /// `Password` would reach the expiry check, and it silently did not.
    #[tokio::test]
    async fn a_challenge_whose_input_is_not_a_second_factor_is_refused() {
        let engine = Engine::builder()
            .with_mfa_method(FixedTotpMethod("user123"))
            .build();
        let token = mfa_token(&engine, "user123", true);

        let result = engine
            .authenticate(AuthInput::MfaChallenge {
                mfa_token: token,
                challenge_input: Box::new(AuthInput::Password {
                    identifier: "user123".to_string(),
                    password: "irrelevant".to_string(),
                }),
            })
            .await;
        assert!(matches!(result, Err(AuthError::InvalidInput)));
    }

    /// A misconfiguration, not a bad credential — hence `Internal` rather
    /// than `InvalidInput`, and `error!` rather than `warn!` in the log.
    #[tokio::test]
    async fn a_second_factor_that_is_not_registered_is_an_internal_error() {
        let engine = Engine::builder().build();
        let token = mfa_token(&engine, "user123", true);

        assert!(matches!(
            engine.authenticate(totp_challenge(token)).await,
            Err(AuthError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn a_refused_second_factor_propagates_the_methods_error() {
        let engine = Engine::builder()
            .with_mfa_method(RejectingTotpMethod)
            .build();
        let token = mfa_token(&engine, "user123", true);

        assert!(matches!(
            engine.authenticate(totp_challenge(token)).await,
            Err(AuthError::Credentials(_))
        ));
    }

    /// The second factor verified, but for somebody else. Accepting this
    /// would let anyone holding a continuation token for user A complete the
    /// login by presenting their own valid second factor.
    #[tokio::test]
    async fn a_second_factor_verifying_a_different_user_is_refused() {
        let engine = Engine::builder()
            .with_mfa_method(FixedTotpMethod("someone-else"))
            .build();
        let token = mfa_token(&engine, "user123", true);

        let err = engine
            .authenticate(totp_challenge(token))
            .await
            .expect_err("a mismatched user must not complete the login");
        assert!(
            matches!(&err, AuthError::Credentials(m) if m.contains("user mismatch")),
            "expected a user-mismatch rejection, got {err:?}"
        );
    }

    #[tokio::test]
    async fn an_input_that_maps_to_no_primary_method_is_refused() {
        let engine = Engine::builder()
            .with_mfa_method(FixedTotpMethod("user123"))
            .build();

        let result = engine
            .authenticate(AuthInput::OAuthCode {
                code: "abc".to_string(),
                code_verifier: None,
            })
            .await;
        assert!(matches!(result, Err(AuthError::InvalidInput)));
    }

    /// `Totp` maps to a primary method name too, so an engine that registers
    /// it only as a step-up factor has no *primary* method under that name.
    #[tokio::test]
    async fn a_primary_method_registered_only_as_step_up_is_an_internal_error() {
        let engine = Engine::builder()
            .with_mfa_method(FixedTotpMethod("user123"))
            .build();

        let result = engine
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: "000000".to_string(),
            })
            .await;
        assert!(
            matches!(result, Err(AuthError::Internal(_))),
            "expected an Internal error, got {result:?}"
        );
    }

    /// The happy path through the same fixtures, so the rejections above are
    /// attributable to what each test varies rather than to the setup.
    #[tokio::test]
    async fn the_fixture_completes_a_login_when_nothing_is_wrong() {
        let engine = Engine::builder()
            .with_mfa_method(FixedTotpMethod("user123"))
            .build();
        let token = mfa_token(&engine, "user123", true);

        assert!(matches!(
            engine.authenticate(totp_challenge(token)).await,
            Ok(AuthResult::Success(_))
        ));
    }

    /// Mints an MFA continuation token with custom `primary_method` and `allowed_methods` claims.
    fn mfa_token_custom<S, T>(
        engine: &Engine<S, T>,
        sub: &str,
        mfa_pending: bool,
        primary_method: &str,
        allowed_methods: Vec<String>,
    ) -> String {
        let mut claims = crate::auth::state::MfaTokenClaims::new(
            sub,
            (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp() as usize,
            primary_method,
        );
        claims.mfa_pending = mfa_pending;
        claims.allowed_methods = allowed_methods;
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&engine.mfa_jwt_secret),
        )
        .expect("signing should succeed")
    }

    /// Verifies that MFA continuation refuses a second factor that matches the primary method.
    #[tokio::test]
    async fn mfa_continuation_rejects_matching_primary_method() {
        let engine = Engine::builder()
            .with_mfa_method(FixedTotpMethod("user123"))
            .build();
        // Claims specify primary_method was "totp"
        let token = mfa_token_custom(&engine, "user123", true, "totp", vec!["totp".to_string()]);

        let result = engine.authenticate(totp_challenge(token)).await;
        assert!(matches!(result, Err(AuthError::InvalidInput)));
    }

    /// Verifies that MFA continuation refuses a second factor not listed in `allowed_methods`.
    #[tokio::test]
    async fn mfa_continuation_rejects_method_not_in_allowed_methods() {
        let engine = Engine::builder()
            .with_mfa_method(FixedTotpMethod("user123"))
            .build();
        // Claims specify allowed_methods only contains "webauthn"
        let token = mfa_token_custom(
            &engine,
            "user123",
            true,
            "password",
            vec!["webauthn".to_string()],
        );

        let result = engine.authenticate(totp_challenge(token)).await;
        assert!(matches!(result, Err(AuthError::InvalidInput)));
    }

    struct FailingStoreTotpMethod;
    #[async_trait]
    impl AuthMethod for FailingStoreTotpMethod {
        fn name(&self) -> &str {
            "totp"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "totp".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
        async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
            Err(AuthError::Internal("store is unreachable".to_string()))
        }
    }

    struct SuccessfulPrimaryMethod;
    #[async_trait]
    impl AuthMethod for SuccessfulPrimaryMethod {
        fn name(&self) -> &str {
            "password"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "password".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
    }

    /// Verifies that an error from `has_enrolled` propagates instead of failing open.
    #[tokio::test]
    async fn mfa_has_enrolled_error_propagates_and_does_not_fail_open() {
        let engine = Engine::builder()
            .with_auth_method(SuccessfulPrimaryMethod)
            .with_mfa_method(FailingStoreTotpMethod)
            .build();

        let result = engine
            .authenticate(AuthInput::Password {
                identifier: "user123".to_string(),
                password: "secret".to_string(),
            })
            .await;

        match result {
            Err(AuthError::Internal(msg)) => assert!(msg.contains("store is unreachable")),
            other => panic!("expected Err(AuthError::Internal), got {:?}", other),
        }
    }
}

// --- `amr`/step-up bookkeeping stamped onto `Identity::attributes` ---
//
// `Engine::authenticate` is the only place that knows which `AuthMethod`(s)
// actually ran for a given login, so it is responsible for recording that
// onto the returned `Identity` (see `IDENTITY_ATTR_AMR` /
// `IDENTITY_ATTR_STEP_UP_SATISFIED`) — `authkestra-op` reads it back out to
// populate the `amr`/`acr` ID token claims. These pin the three cases that
// claim derivation distinguishes: primary-only, a completed step-up, and an
// `is_mfa_equivalent` primary that skips step-up entirely (covered by
// `test_mfa_equivalent_bypasses_mfa` above).
#[cfg(all(test, feature = "totp"))]
mod amr_step_up_bookkeeping {
    use super::*;
    use crate::auth::{AuthResult, IDENTITY_ATTR_AMR, IDENTITY_ATTR_STEP_UP_SATISFIED};
    use crate::Engine;

    struct TestPasswordMethod;
    #[async_trait]
    impl AuthMethod for TestPasswordMethod {
        fn name(&self) -> &str {
            "password"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "password".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
    }

    struct TestTotpStepUpMethod;
    #[async_trait]
    impl AuthMethod for TestTotpStepUpMethod {
        fn name(&self) -> &str {
            "totp"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "totp".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
        async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
            Ok(true)
        }
    }

    /// A plain password login with no MFA enrolled: `amr` names the single
    /// primary method, and the step-up marker is absent (not `"false"` —
    /// see `IDENTITY_ATTR_STEP_UP_SATISFIED`'s doc comment).
    #[tokio::test]
    async fn primary_only_login_stamps_amr_and_no_step_up_marker() {
        let engine = Engine::builder()
            .with_auth_method(TestPasswordMethod)
            .build();

        let res = engine
            .authenticate(AuthInput::Password {
                identifier: "user123".to_string(),
                password: "irrelevant".to_string(),
            })
            .await
            .unwrap();

        match res {
            AuthResult::Success(identity) => {
                assert_eq!(
                    identity.attributes.get(IDENTITY_ATTR_AMR),
                    Some(&"password".to_string())
                );
                assert_eq!(
                    identity.attributes.get(IDENTITY_ATTR_STEP_UP_SATISFIED),
                    None
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// Primary auth followed by a completed step-up: `amr` names *both*
    /// methods, primary first, and the step-up marker is set — this is the
    /// case that must look visibly different from the primary-only case
    /// above once `authkestra-op` turns it into `acr`/`amr` claims.
    #[tokio::test]
    async fn completed_step_up_stamps_amr_with_both_methods() {
        let engine = Engine::builder()
            .with_auth_method(TestPasswordMethod)
            .with_mfa_method(TestTotpStepUpMethod)
            .build();

        let primary = engine
            .authenticate(AuthInput::Password {
                identifier: "user123".to_string(),
                password: "irrelevant".to_string(),
            })
            .await
            .unwrap();

        let mfa_token = match primary {
            AuthResult::MfaRequired { mfa_token, .. } => mfa_token,
            other => panic!("expected MfaRequired (TOTP is enrolled), got {other:?}"),
        };

        let res = engine
            .authenticate(AuthInput::MfaChallenge {
                mfa_token,
                challenge_input: Box::new(AuthInput::Totp {
                    user_id: "user123".to_string(),
                    code: "000000".to_string(),
                }),
            })
            .await
            .unwrap();

        match res {
            AuthResult::Success(identity) => {
                assert_eq!(
                    identity.attributes.get(IDENTITY_ATTR_AMR),
                    Some(&"password totp".to_string())
                );
                assert_eq!(
                    identity.attributes.get(IDENTITY_ATTR_STEP_UP_SATISFIED),
                    Some(&"true".to_string())
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// `auth_time` must reflect the *step-up* completing, not the primary
    /// factor that ran a round-trip earlier: a re-authentication gate asking
    /// "did you prove yourself in the last N seconds" means the most recent
    /// proof. Pinned by checking the stamped value lands at or after a
    /// timestamp taken *after* the primary factor already ran.
    #[tokio::test]
    async fn step_up_stamps_auth_time_at_the_step_up_not_the_primary() {
        use crate::auth::IDENTITY_ATTR_AUTH_TIME;

        let engine = Engine::builder()
            .with_auth_method(TestPasswordMethod)
            .with_mfa_method(TestTotpStepUpMethod)
            .build();

        let primary = engine
            .authenticate(AuthInput::Password {
                identifier: "user123".to_string(),
                password: "irrelevant".to_string(),
            })
            .await
            .unwrap();

        let mfa_token = match primary {
            AuthResult::MfaRequired { mfa_token, .. } => mfa_token,
            other => panic!("expected MfaRequired, got {other:?}"),
        };

        // Taken after the primary factor has already completed, so a stamp
        // from the primary would fall strictly before this.
        let after_primary = chrono::Utc::now().timestamp();

        let res = engine
            .authenticate(AuthInput::MfaChallenge {
                mfa_token,
                challenge_input: Box::new(AuthInput::Totp {
                    user_id: "user123".to_string(),
                    code: "000000".to_string(),
                }),
            })
            .await
            .unwrap();

        match res {
            AuthResult::Success(identity) => {
                let stamped: i64 = identity
                    .attributes
                    .get(IDENTITY_ATTR_AUTH_TIME)
                    .expect("auth_time must be stamped on a completed step-up")
                    .parse()
                    .expect("auth_time must be a parseable Unix timestamp");
                assert!(
                    stamped >= after_primary,
                    "auth_time ({stamped}) should mark the step-up completing, \
                     not the earlier primary factor (>= {after_primary})"
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// A primary-only login stamps `auth_time` too — freshness is not
    /// step-up-specific.
    #[tokio::test]
    async fn primary_only_login_also_stamps_auth_time() {
        use crate::auth::IDENTITY_ATTR_AUTH_TIME;

        let before = chrono::Utc::now().timestamp();
        let engine = Engine::builder()
            .with_auth_method(TestPasswordMethod)
            .build();

        let res = engine
            .authenticate(AuthInput::Password {
                identifier: "user123".to_string(),
                password: "irrelevant".to_string(),
            })
            .await
            .unwrap();

        match res {
            AuthResult::Success(identity) => {
                let stamped: i64 = identity
                    .attributes
                    .get(IDENTITY_ATTR_AUTH_TIME)
                    .expect("auth_time must be stamped on a primary-only login")
                    .parse()
                    .expect("auth_time must be a parseable Unix timestamp");
                assert!(stamped >= before);
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// An MFA continuation token minted *before* `primary_method` existed
    /// must still complete step-up after an upgrade. Without
    /// `#[serde(default)]` on that field, anyone mid-step-up when a new
    /// binary rolls out would get an opaque "missing field" rejection and
    /// have to restart the login — a 15-minute window, but a needlessly
    /// confusing one. The resulting `amr` names only the factor this call
    /// actually verified, since the primary genuinely isn't recoverable
    /// from such a token.
    #[tokio::test]
    async fn a_pre_upgrade_mfa_token_without_primary_method_still_completes() {
        let engine = Engine::builder()
            .with_auth_method(TestPasswordMethod)
            .with_mfa_method(TestTotpStepUpMethod)
            .build();

        // The old claim shape: no `primary_method` key at all.
        let legacy_claims = serde_json::json!({
            "sub": "user123",
            "mfa_pending": true,
            "exp": (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp(),
        });
        let legacy_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &legacy_claims,
            &jsonwebtoken::EncodingKey::from_secret(&engine.mfa_jwt_secret),
        )
        .unwrap();

        let res = engine
            .authenticate(AuthInput::MfaChallenge {
                mfa_token: legacy_token,
                challenge_input: Box::new(AuthInput::Totp {
                    user_id: "user123".to_string(),
                    code: "000000".to_string(),
                }),
            })
            .await
            .expect("a pre-upgrade MFA token must still decode and complete");

        match res {
            AuthResult::Success(identity) => {
                assert_eq!(
                    identity.attributes.get(IDENTITY_ATTR_AMR),
                    Some(&"totp".to_string()),
                    "only the verified factor should be reported; the primary \
                     is not recoverable from a pre-upgrade token"
                );
                assert_eq!(
                    identity.attributes.get(IDENTITY_ATTR_STEP_UP_SATISFIED),
                    Some(&"true".to_string())
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }
}

/// A recovery code must be usable as a step-up, not merely advertised as one.
///
/// Review on #404 found the two halves disagreed: the enrolment probe lists
/// any registered method whose `has_enrolled` is true — which recovery codes
/// are, whenever unredeemed codes exist — while the MFA continuation dispatch
/// recognised only `Totp` and `WebAuthnAuthentication` and rejected everything
/// else as `InvalidInput`. So the engine would offer `recovery-code` in
/// `allowed_methods` and then refuse the reply, leaving the advertised
/// fallback unusable at exactly the moment an account needs it.
///
/// Magic link and OTP never hit this because their `has_enrolled` is false, so
/// they are never advertised. Recovery codes are the first method for which
/// both halves are live, which is why this only surfaced now.
#[cfg(feature = "recovery-codes")]
mod recovery_code_step_up {
    use super::*;
    use crate::auth::AuthResult;
    use crate::Engine;

    struct StubPasswordMethod;

    #[async_trait]
    impl AuthMethod for StubPasswordMethod {
        fn name(&self) -> &str {
            "password"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "password".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
    }

    struct StubRecoveryMethod;

    #[async_trait]
    impl AuthMethod for StubRecoveryMethod {
        fn name(&self) -> &str {
            crate::auth::state::METHOD_NAME_RECOVERY_CODE
        }
        async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError> {
            let AuthInput::RecoveryCode { user_id, .. } = input else {
                return Err(AuthError::InvalidInput);
            };
            Ok(Identity {
                provider_id: crate::auth::state::METHOD_NAME_RECOVERY_CODE.to_string(),
                external_id: user_id,
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
        async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
            Ok(true)
        }
    }

    fn mfa_token<S, T>(engine: &Engine<S, T>, sub: &str) -> String {
        let exp = chrono::Utc::now() + chrono::Duration::seconds(600);
        let claims =
            crate::auth::state::MfaTokenClaims::new(sub, exp.timestamp() as usize, "password");
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&engine.mfa_jwt_secret),
        )
        .expect("signing the MFA token should succeed")
    }

    /// The half that was already true: the engine offers it.
    #[tokio::test]
    async fn an_enrolled_recovery_set_is_advertised_as_a_second_factor() {
        let engine = Engine::builder()
            .with_auth_method(StubPasswordMethod)
            .with_mfa_method(StubRecoveryMethod)
            .build();

        let res = engine
            .authenticate(AuthInput::Password {
                identifier: "user123".to_string(),
                password: "password".to_string(),
            })
            .await
            .unwrap();

        match res {
            AuthResult::MfaRequired {
                allowed_methods, ..
            } => assert_eq!(allowed_methods, vec!["recovery-code"]),
            other => panic!("expected MfaRequired, got {other:?}"),
        }
    }

    /// The half that was not: redeeming what was offered has to work.
    #[tokio::test]
    async fn a_recovery_code_completes_the_step_up_it_was_offered_for() {
        let engine = Engine::builder()
            .with_mfa_method(StubRecoveryMethod)
            .build();
        let token = mfa_token(&engine, "user123");

        let result = engine
            .authenticate(AuthInput::MfaChallenge {
                mfa_token: token,
                challenge_input: Box::new(AuthInput::RecoveryCode {
                    user_id: "user123".to_string(),
                    code: "ABCD-EFGH-IJKL-MNOP".to_string(),
                }),
            })
            .await;

        assert!(
            matches!(result, Ok(AuthResult::Success(_))),
            "an advertised recovery code must be dispatchable, got {result:?}"
        );
    }

    /// The generic guard still applies: a code that verifies somebody else
    /// must not satisfy this token.
    #[tokio::test]
    async fn a_recovery_code_for_another_user_is_refused() {
        let engine = Engine::builder()
            .with_mfa_method(StubRecoveryMethod)
            .build();
        let token = mfa_token(&engine, "user123");

        let result = engine
            .authenticate(AuthInput::MfaChallenge {
                mfa_token: token,
                challenge_input: Box::new(AuthInput::RecoveryCode {
                    user_id: "somebody-else".to_string(),
                    code: "ABCD-EFGH-IJKL-MNOP".to_string(),
                }),
            })
            .await;

        assert!(
            matches!(result, Err(AuthError::Credentials(_))),
            "got {result:?}"
        );
    }
}
