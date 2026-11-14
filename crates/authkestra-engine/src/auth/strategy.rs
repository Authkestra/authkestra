use crate::error::AuthError;
use async_trait::async_trait;
use http::request::Parts;
use std::marker::PhantomData;

/// Trait for an authentication strategy.
///
/// A strategy is responsible for extracting credentials from a request
/// and validating them to produce an identity.
#[async_trait]
pub trait AuthenticationStrategy<I>: Send + Sync {
    /// Attempt to authenticate the request.
    ///
    /// Returns:
    /// - `Ok(Some(identity))` if authentication was successful.
    /// - `Ok(None)` if the strategy did not find relevant credentials (e.g., missing header).
    /// - `Err(AuthError)` if authentication failed (e.g., invalid token, DB error).
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError>;

    /// Attempt to authenticate the request, returning a structured
    /// [`ResourceRefusal`](crate::token::refusal::ResourceRefusal) when
    /// presented credentials are rejected (e.g. RFC 6750 `invalid_token`,
    /// RFC 9449 `invalid_dpop_proof` / `use_dpop_nonce` with `DPoP-Nonce`, or
    /// RFC 9470 `insufficient_user_authentication` with `acr_values` / `max_age`).
    ///
    /// The default implementation delegates to [`Self::authenticate`].
    async fn authenticate_with_refusal(
        &self,
        parts: &Parts,
    ) -> Result<Option<I>, crate::token::refusal::ResourceRefusal> {
        match self.authenticate(parts).await {
            Ok(opt) => Ok(opt),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "strategy returned error during default authenticate_with_refusal conversion"
                );
                Err(crate::token::refusal::ResourceRefusal::internal_error(
                    e.to_string(),
                ))
            }
        }
    }
}

/// Reports a strategy's outcome, so the three cases a caller collapses stay
/// distinguishable in the logs.
///
/// The distinction is load-bearing rather than cosmetic: under a
/// first-success policy, "I found no credentials of my kind" and "I found
/// credentials and they were wrong" both let the next strategy run, and an
/// operator looking at a 401 needs to know which strategies declined and
/// which actually rejected something. None of these log the credential.
fn log_outcome<I>(strategy: &'static str, outcome: &Result<Option<I>, AuthError>) {
    match outcome {
        Ok(Some(_)) => tracing::debug!(strategy, "strategy authenticated the request"),
        Ok(None) => tracing::debug!(strategy, "credentials were present but yielded no identity"),
        Err(error) => tracing::warn!(
            strategy,
            %error,
            "strategy rejected the request's credentials"
        ),
    }
}

/// Trait for a provider that validates username and password (Basic Auth).
#[async_trait]
pub trait BasicAuthenticator: Send + Sync {
    /// The type of identity returned by this authenticator.
    type Identity;
    /// Validate the credentials.
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<Self::Identity>, AuthError>;
}

/// Strategy for Basic authentication.
#[non_exhaustive]
pub struct BasicStrategy<P, I> {
    authenticator: P,
    _marker: PhantomData<I>,
}

impl<P, I> BasicStrategy<P, I> {
    /// Create a new BasicStrategy with the given authenticator.
    pub fn new(authenticator: P) -> Self {
        Self {
            authenticator,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<P, I> AuthenticationStrategy<I> for BasicStrategy<P, I>
where
    P: BasicAuthenticator<Identity = I> + Send + Sync,
    I: Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some((username, password)) = utils::extract_basic_credentials(&parts.headers) {
            let outcome = self.authenticator.authenticate(&username, &password).await;
            log_outcome("basic", &outcome);
            outcome
        } else {
            tracing::debug!(
                strategy = "basic",
                "no Basic credentials present; declining"
            );
            Ok(None)
        }
    }
}

/// Trait for a validator that verifies a token.
#[async_trait]
pub trait TokenValidator: Send + Sync {
    /// The type of identity returned by this validator.
    type Identity;
    /// Validate the token.
    async fn validate(&self, token: &str) -> Result<Option<Self::Identity>, AuthError>;
}

/// Strategy for Token (Bearer) authentication.
#[non_exhaustive]
pub struct TokenStrategy<V, I> {
    validator: V,
    _marker: PhantomData<I>,
}

impl<V, I> TokenStrategy<V, I> {
    /// Create a new TokenStrategy with the given validator.
    pub fn new(validator: V) -> Self {
        Self {
            validator,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<V, I> AuthenticationStrategy<I> for TokenStrategy<V, I>
where
    V: TokenValidator<Identity = I> + Send + Sync,
    I: Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some(token) = utils::extract_bearer_token(&parts.headers) {
            let outcome = self.validator.validate(token).await;
            log_outcome("bearer", &outcome);
            outcome
        } else {
            tracing::debug!(strategy = "bearer", "no Bearer token present; declining");
            Ok(None)
        }
    }
}

/// Strategy for custom header authentication.
#[non_exhaustive]
pub struct HeaderStrategy<F, I> {
    header_name: http::header::HeaderName,
    validator: F,
    _marker: PhantomData<I>,
}

impl<F, I> HeaderStrategy<F, I> {
    /// Create a new HeaderStrategy.
    pub fn new(header_name: http::header::HeaderName, validator: F) -> Self {
        Self {
            header_name,
            validator,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<F, I, Fut> AuthenticationStrategy<I> for HeaderStrategy<F, I>
where
    F: Fn(String) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<Option<I>, AuthError>> + Send,
    I: Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some(value) = parts.headers.get(&self.header_name) {
            match value.to_str() {
                Ok(value_str) => {
                    let outcome = (self.validator)(value_str.to_string()).await;
                    log_outcome("header", &outcome);
                    return outcome;
                }
                // Present but not valid UTF-8, which is not the same as absent.
                Err(error) => tracing::warn!(
                    strategy = "header",
                    header = %self.header_name,
                    %error,
                    "header is present but is not valid ASCII; declining"
                ),
            }
        } else {
            tracing::debug!(
                strategy = "header",
                header = %self.header_name,
                "header not present; declining"
            );
        }
        Ok(None)
    }
}

/// Trait for a session store that can load an identity.
#[async_trait]
pub trait SessionProvider: Send + Sync {
    /// The type of identity returned by this provider.
    type Identity;
    /// Load the identity associated with the session ID.
    async fn load_session(&self, session_id: &str) -> Result<Option<Self::Identity>, AuthError>;
}

/// Strategy for Session authentication.
#[non_exhaustive]
pub struct SessionStrategy<P, I> {
    provider: P,
    cookie_name: String,
    _marker: PhantomData<I>,
}

impl<P, I> SessionStrategy<P, I> {
    /// Create a new SessionStrategy.
    pub fn new(provider: P, cookie_name: impl Into<String>) -> Self {
        Self {
            provider,
            cookie_name: cookie_name.into(),
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<P, I> AuthenticationStrategy<I> for SessionStrategy<P, I>
where
    P: SessionProvider<Identity = I> + Send + Sync,
    I: Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some(session_id) = utils::extract_cookie(&parts.headers, &self.cookie_name) {
            // The cookie value is the session credential, so it is not
            // logged; only that one was found.
            let outcome = self.provider.load_session(session_id).await;
            log_outcome("session", &outcome);
            outcome
        } else {
            tracing::debug!(
                strategy = "session",
                cookie = %self.cookie_name,
                "no session cookie present; declining"
            );
            Ok(None)
        }
    }
}

/// Utility functions for common authentication tasks.
pub mod utils {
    use http::header::{HeaderMap, AUTHORIZATION};

    /// Extract the Bearer token from the Authorization header.
    pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
        headers
            .get(AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")
            .map(|s| s.trim())
    }

    /// Extract Basic credentials from the Authorization header.
    pub fn extract_basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
        let auth_header = headers.get(AUTHORIZATION)?.to_str().ok()?;
        if !auth_header.starts_with("Basic ") {
            return None;
        }
        let encoded = auth_header.strip_prefix("Basic ")?.trim();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let mut parts = decoded_str.splitn(2, ':');
        let username = parts.next()?.to_string();
        let password = parts.next()?.to_string();
        Some((username, password))
    }

    /// Extract a cookie value by name.
    pub fn extract_cookie<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
        let cookie_header = headers.get(http::header::COOKIE)?.to_str().ok()?;
        for cookie in cookie_header.split(';') {
            let mut parts = cookie.splitn(2, '=');
            let k = parts.next()?.trim();
            let v = parts.next()?.trim();
            if k == name {
                return Some(v);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{
        header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, COOKIE},
        Request,
    };

    #[derive(Debug, PartialEq)]
    struct DummyIdentity(String);

    struct DummyBasic;
    #[async_trait]
    impl BasicAuthenticator for DummyBasic {
        type Identity = DummyIdentity;
        async fn authenticate(
            &self,
            u: &str,
            p: &str,
        ) -> Result<Option<Self::Identity>, AuthError> {
            if u == "user" && p == "pass" {
                Ok(Some(DummyIdentity(u.to_string())))
            } else {
                Ok(None)
            }
        }
    }

    struct DummyToken;
    #[async_trait]
    impl TokenValidator for DummyToken {
        type Identity = DummyIdentity;
        async fn validate(&self, t: &str) -> Result<Option<Self::Identity>, AuthError> {
            if t == "valid_token" {
                Ok(Some(DummyIdentity("user".to_string())))
            } else {
                Ok(None)
            }
        }
    }

    struct DummySession;
    #[async_trait]
    impl SessionProvider for DummySession {
        type Identity = DummyIdentity;
        async fn load_session(&self, sid: &str) -> Result<Option<Self::Identity>, AuthError> {
            if sid == "valid_sid" {
                Ok(Some(DummyIdentity("user".to_string())))
            } else {
                Ok(None)
            }
        }
    }

    #[tokio::test]
    async fn test_basic_strategy() {
        let strategy = BasicStrategy::new(DummyBasic);
        let req = Request::builder().uri("/").body(()).unwrap();

        let res = strategy.authenticate(&req.into_parts().0).await.unwrap();
        assert_eq!(res, None);

        let req2 = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(())
            .unwrap();
        let res2 = strategy.authenticate(&req2.into_parts().0).await.unwrap();
        assert_eq!(res2.unwrap(), DummyIdentity("user".to_string()));
    }

    #[tokio::test]
    async fn test_token_strategy() {
        let strategy = TokenStrategy::new(DummyToken);
        let req = Request::builder().uri("/").body(()).unwrap();

        let res = strategy.authenticate(&req.into_parts().0).await.unwrap();
        assert_eq!(res, None);

        let req2 = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, "Bearer valid_token")
            .body(())
            .unwrap();
        let res2 = strategy.authenticate(&req2.into_parts().0).await.unwrap();
        assert_eq!(res2.unwrap(), DummyIdentity("user".to_string()));
    }

    #[tokio::test]
    async fn test_header_strategy() {
        let strategy = HeaderStrategy::new(
            HeaderName::from_static("x-api-key"),
            |key: String| async move {
                if key == "secret" {
                    Ok(Some(DummyIdentity("user".to_string())))
                } else {
                    Ok(None)
                }
            },
        );
        let req = Request::builder().uri("/").body(()).unwrap();

        let res = strategy.authenticate(&req.into_parts().0).await.unwrap();
        assert_eq!(res, None);

        let req2 = Request::builder()
            .uri("/")
            .header("x-api-key", "secret")
            .body(())
            .unwrap();
        let res2 = strategy.authenticate(&req2.into_parts().0).await.unwrap();
        assert_eq!(res2.unwrap(), DummyIdentity("user".to_string()));
    }

    #[tokio::test]
    async fn test_session_strategy() {
        let strategy = SessionStrategy::new(DummySession, "sid");
        let req = Request::builder().uri("/").body(()).unwrap();

        let res = strategy.authenticate(&req.into_parts().0).await.unwrap();
        assert_eq!(res, None);

        let req2 = Request::builder()
            .uri("/")
            .header(COOKIE, "sid=valid_sid")
            .body(())
            .unwrap();
        let res2 = strategy.authenticate(&req2.into_parts().0).await.unwrap();
        assert_eq!(res2.unwrap(), DummyIdentity("user".to_string()));
    }

    #[test]
    fn test_utils_extractors() {
        let mut headers = HeaderMap::new();
        assert_eq!(utils::extract_bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        assert_eq!(utils::extract_bearer_token(&headers), Some("token"));

        let mut headers2 = HeaderMap::new();
        headers2.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(
            utils::extract_basic_credentials(&headers2),
            Some(("user".to_string(), "pass".to_string()))
        );

        let mut headers3 = HeaderMap::new();
        headers3.insert(COOKIE, HeaderValue::from_static("foo=bar; sid=123"));
        assert_eq!(utils::extract_cookie(&headers3, "sid"), Some("123"));
    }

    /// No existing test produced an `Err` from a delegate, so the strategies'
    /// *rejection* path was untested — which is the case `log_outcome` exists
    /// to keep distinguishable from a decline (#353). Under a first-success
    /// policy both let the next strategy run, so the difference lives only in
    /// the logs and in what the caller sees.
    struct RejectingValidator;
    #[async_trait]
    impl TokenValidator for RejectingValidator {
        type Identity = DummyIdentity;
        async fn validate(&self, _t: &str) -> Result<Option<Self::Identity>, AuthError> {
            Err(AuthError::Token("expired".into()))
        }
    }

    #[tokio::test]
    async fn a_rejected_token_is_an_error_not_a_decline() {
        let strategy = TokenStrategy::new(RejectingValidator);
        let req = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, "Bearer whatever")
            .body(())
            .unwrap();

        let result = strategy.authenticate(&req.into_parts().0).await;
        assert!(
            matches!(result, Err(AuthError::Token(_))),
            "a credential this strategy owns and refuses must surface as Err, \
             not as Ok(None) — the latter reads as \"not mine\" to the caller"
        );
    }

    /// A header that is present but not ASCII is neither absent nor readable.
    /// It declines, so another strategy may still succeed, but it is logged
    /// distinctly because it is not the same as absent.
    #[tokio::test]
    async fn a_non_ascii_header_value_declines_rather_than_erroring() {
        let strategy = HeaderStrategy::new(
            HeaderName::from_static("x-api-key"),
            // Returns `Ok(Some(..))` for any input, which is what makes the
            // assertion below meaningful: had the unreadable header reached
            // this validator, the result would be `Ok(Some(..))`, so
            // `Ok(None)` proves the strategy declined without calling it.
            // The body is consequently expected to show as uncovered.
            |_key: String| async move { Ok(Some(DummyIdentity("user".to_string()))) },
        );
        let mut req = Request::builder().uri("/").body(()).unwrap();
        req.headers_mut().insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );

        let result = strategy.authenticate(&req.into_parts().0).await;
        assert!(matches!(result, Ok(None)));
    }

    /// The third outcome, distinct from both a decline and a rejection: the
    /// strategy found credentials of its kind, handed them to its delegate,
    /// and the delegate recognised nobody. `DummyBasic` returns `Ok(None)`
    /// for an unknown user, but no existing test presented one — so this arm
    /// of the outcome reporting was never exercised (#353).
    #[tokio::test]
    async fn credentials_that_resolve_to_nobody_are_a_decline_not_an_error() {
        // base64("nobody:whatever")
        let strategy = BasicStrategy::new(DummyBasic);
        let req = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, "Basic bm9ib2R5OndoYXRldmVy")
            .body(())
            .unwrap();

        let result: Result<Option<DummyIdentity>, AuthError> =
            strategy.authenticate(&req.into_parts().0).await;
        assert!(
            matches!(result, Ok(None)),
            "an unrecognised user is not an error; another strategy may still succeed"
        );
    }
}
