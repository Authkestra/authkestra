#![allow(unused_imports)]
pub use authkestra_engine::auth::{Session, SessionConfig, SessionStore};
#[cfg(feature = "token")]
use authkestra_engine::TokenManager;
use authkestra_engine::{
    pkce::Pkce,
    state::{Identity, OAuth2State, OAuthToken},
};
use authkestra_engine::{Engine, ErasedOAuthFlow, OAuth2Flow};
#[cfg(feature = "token")]
use axum::Json;
#[allow(unused_imports)]
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
#[allow(unused_imports)]
use std::sync::Arc;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

#[cfg(feature = "session")]
use super::cookie::create_axum_cookie;

#[derive(serde::Deserialize)]
#[non_exhaustive]
pub struct OAuthCallbackParams {
    pub code: String,
    pub state: String,
}

#[derive(serde::Deserialize)]
#[non_exhaustive]
pub struct OAuthLoginParams {
    pub scope: Option<String>,
    pub success_url: Option<String>,
}

/// The cookie carrying the encrypted OAuth state between the authorization
/// redirect and the callback. Named once rather than repeated as a literal,
/// matching `authkestra-actix` (#356).
const STATE_COOKIE: &str = "ak_state";

/// Helper to initiate the OAuth2 login flow.
///
/// This generates the authorization URL and sets a CSRF state cookie.
pub fn initiate_oauth_login(
    flow: &dyn ErasedOAuthFlow,
    cookies: &Cookies,
    scopes: &[&str],
    config: &SessionConfig,
    success_url: Option<String>,
) -> Redirect {
    let pkce = Pkce::new();
    let (url, mut auth_state) = flow.initiate_login(scopes, Some(&pkce.code_challenge));

    auth_state.code_verifier = Some(pkce.code_verifier);
    auth_state.success_url = success_url;

    let encrypted = auth_state
        .encrypt(&config.state_encryption_key)
        .expect("Failed to encrypt OAuth state");

    let mut cookie = Cookie::new(STATE_COOKIE, encrypted);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(true);
    cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::minutes(15)));

    cookies.add(cookie);

    // Bound above the event rather than computed in the fields: a call inside
    // a `tracing` field expands into regions no test can fully execute, so it
    // reads as permanently uncovered however well the function is exercised.
    let scope_count = scopes.len();
    let has_success_url = auth_state.success_url.is_some();
    tracing::debug!(
        scopes = scope_count,
        has_success_url,
        "issued an OAuth authorization redirect and set the state cookie"
    );
    Redirect::to(&url)
}

/// Internal helper to finalize the OAuth flow by validating state and exchanging the code.
#[cfg(any(feature = "session", feature = "token"))]
async fn finalize_callback_erased(
    flow: &dyn ErasedOAuthFlow,
    cookies: &Cookies,
    params: &OAuthCallbackParams,
    config: &SessionConfig,
) -> Result<(Identity, OAuthToken, OAuth2State), (StatusCode, String)> {
    let encrypted_state = cookies
        .get(STATE_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or_else(|| {
            // No cookie at all, which is usually the browser rather than the
            // user: a `SameSite`/`Secure` mismatch, or a callback arriving
            // after the fifteen-minute lifetime. Distinct from a cookie that
            // arrived and could not be read, below.
            tracing::warn!("OAuth callback carries no state cookie; cannot validate CSRF");
            (
                StatusCode::UNAUTHORIZED,
                "CSRF validation failed or session expired".to_string(),
            )
        })?;

    let expected_state = OAuth2State::decrypt(&encrypted_state, &config.state_encryption_key)
        .map_err(|e| {
            // The cookie arrived but would not decrypt. The reason worth
            // separating from the case above: a rotated
            // `state_encryption_key` fails every in-flight login exactly
            // like this, and nothing else in the system would say so.
            tracing::warn!(
                error = %e,
                "OAuth state cookie could not be decrypted; if the state encryption key \
                 was rotated, logins started before the rotation will all fail this way"
            );
            (
                StatusCode::UNAUTHORIZED,
                format!("Invalid state cookie: {e}"),
            )
        })?;

    // Remove cookie after use
    let mut remove_cookie = Cookie::new(STATE_COOKIE, "");
    remove_cookie.set_path("/");
    remove_cookie.set_secure(true);

    cookies.remove(remove_cookie);

    let (identity, token) = flow
        .finalize_login(&params.code, &params.state, &expected_state)
        .await
        .map_err(|e| {
            // The state checked out; the provider exchange is what failed.
            tracing::warn!(error = %e, "OAuth code exchange failed after state validation");
            (
                StatusCode::UNAUTHORIZED,
                format!("Authentication failed: {e}"),
            )
        })?;

    tracing::debug!(
        external_id = %identity.external_id,
        "OAuth callback validated and exchanged for an identity"
    );
    Ok((identity, token, expected_state))
}

/// Helper to handle the OAuth2 callback and create a server-side session.
#[cfg(feature = "session")]
pub async fn handle_oauth_callback_erased(
    flow: &dyn ErasedOAuthFlow,
    cookies: Cookies,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    _success_url: &str,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (mut identity, token, auth_state) =
        finalize_callback_erased(flow, &cookies, &params, &config).await?;

    // Store tokens in identity attributes for convenience
    identity
        .attributes
        .insert("access_token".to_string(), token.access_token);

    if let Some(expires_in) = token.expires_in {
        let expires_at = chrono::Utc::now().timestamp() + expires_in as i64;
        identity
            .attributes
            .insert("expires_at".to_string(), expires_at.to_string());
    }

    if let Some(rt) = token.refresh_token {
        identity.attributes.insert("refresh_token".to_string(), rt);
    }

    let session_duration = config.max_age.unwrap_or(chrono::Duration::hours(24));
    let session = Session::new(
        uuid::Uuid::new_v4().to_string(),
        identity,
        chrono::Utc::now() + session_duration,
    );

    let session_id = session.id.clone();
    let user_id = session.identity.external_id.clone();
    store.save_session(&session).await.map_err(|e| {
        tracing::error!(error = %e, "failed to persist the session after a successful login");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save session: {e}"),
        )
    })?;
    tracing::info!(%session_id, %user_id, "OAuth login completed; session created");

    let cookie = create_axum_cookie(&config, session.id);
    cookies.add(cookie);

    let redirect_url = auth_state.success_url.unwrap_or_else(|| "/".to_string());
    Ok(Redirect::to(&redirect_url).into_response())
}

/// Helper to handle the OAuth2 callback and create a server-side session.
#[cfg(feature = "session")]
pub async fn handle_oauth_callback<P, M>(
    flow: &OAuth2Flow<P, M>,
    cookies: Cookies,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    P: authkestra_engine::OAuthProvider + Send + Sync + 'static,
    M: authkestra_engine::UserMapper + Send + Sync + 'static,
{
    handle_oauth_callback_erased(flow, cookies, params, store, config, success_url).await
}

/// Helper to handle the OAuth2 callback and return a JWT for stateless auth.
#[cfg(feature = "token")]
pub async fn handle_oauth_callback_jwt_erased(
    flow: &dyn ErasedOAuthFlow,
    cookies: Cookies,
    params: OAuthCallbackParams,
    token_manager: Arc<TokenManager>,
    expires_in_secs: u64,
    config: SessionConfig,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (identity, _token, _auth_state) =
        finalize_callback_erased(flow, &cookies, &params, &config).await?;

    let user_id = identity.external_id.clone();
    let jwt = token_manager
        .issue_user_token(identity, expires_in_secs, None, None)
        // Not covered by a test, deliberately: signing with a fixed secret
        // has no reachable failure mode, so exercising this would mean
        // contriving one. Logged rather than dropped because if it ever does
        // fire, the login has failed for a reason nothing else would explain.
        .map_err(|e| {
            tracing::error!(error = %e, "failed to issue a token after a successful login");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Token error: {e}"),
            )
        })?;
    // The token itself is a credential and is not logged.
    tracing::info!(
        %user_id,
        expires_in_secs,
        "OAuth login completed; token issued"
    );

    Ok(Json(serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": expires_in_secs
    })))
}

/// Helper to handle the OAuth2 callback and return a JWT for stateless auth.
#[cfg(feature = "token")]
pub async fn handle_oauth_callback_jwt<P, M>(
    flow: &OAuth2Flow<P, M>,
    cookies: Cookies,
    params: OAuthCallbackParams,
    token_manager: Arc<TokenManager>,
    expires_in_secs: u64,
    config: SessionConfig,
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    P: authkestra_engine::OAuthProvider + Send + Sync + 'static,
    M: authkestra_engine::UserMapper + Send + Sync + 'static,
{
    handle_oauth_callback_jwt_erased(
        flow,
        cookies,
        params,
        token_manager,
        expires_in_secs,
        config,
    )
    .await
}

/// Helper to handle logout by deleting the session from the store and clearing the cookie.
///
/// Returns a redirect to the specified URL.
#[cfg(feature = "session")]
pub async fn logout(
    cookies: Cookies,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    redirect_to: &str,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = cookies
        .get(&config.cookie_name)
        .map(|c| c.value().to_string());

    if let Some(id) = session_id {
        store.delete_session(&id).await.map_err(|e| {
            tracing::error!(error = %e, "failed to delete the session during logout");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;
        tracing::info!(session_id = %id, "session deleted on logout");
    } else {
        // Still clears the cookie below, so this is a no-op logout rather
        // than an error — worth saying, since it looks like a failure to
        // anyone reading a support ticket.
        tracing::debug!("logout with no session cookie present; clearing the cookie anyway");
    }

    let mut cookie = create_axum_cookie(&config, "".to_string());
    cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::ZERO));
    cookies.remove(cookie);

    Ok(Redirect::to(redirect_to))
}
pub async fn axum_login_handler<AppState, S, T>(
    Path(provider): Path<String>,
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(params): Query<OAuthLoginParams>,
    cookies: Cookies,
) -> Result<impl IntoResponse, AxumError>
where
    AppState: Clone + Send + Sync + 'static,
    Engine<S, T>: axum::extract::FromRef<AppState>,
    SessionConfig: axum::extract::FromRef<AppState>,
{
    use axum::extract::FromRef;
    let authkestra = Engine::<S, T>::from_ref(&state);
    let session_config = SessionConfig::from_ref(&state);

    let flow: &Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return Err(AxumError::NotFound(format!(
                "Provider {} not found",
                provider_for_display(&provider)
            )));
        }
    };

    let scopes_str = params.scope.unwrap_or_default();
    let scopes: Vec<&str> = scopes_str
        .split(|c: char| [' ', ','].contains(&c))
        .filter(|s| !s.is_empty())
        .collect();

    let redirect = initiate_oauth_login(
        flow.as_ref(),
        &cookies,
        &scopes,
        &session_config,
        params.success_url,
    );

    Ok(redirect)
}

#[cfg(feature = "session")]
pub async fn axum_callback_handler<AppState, S, T>(
    Path(provider): Path<String>,
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(params): Query<OAuthCallbackParams>,
    cookies: Cookies,
) -> Result<impl IntoResponse, AxumError>
where
    AppState: Clone + Send + Sync + 'static,
    Engine<S, T>: axum::extract::FromRef<AppState>,
    SessionConfig: axum::extract::FromRef<AppState>,
    Result<Arc<dyn SessionStore>, AxumError>: axum::extract::FromRef<AppState>,
{
    use axum::extract::FromRef;
    let authkestra = Engine::<S, T>::from_ref(&state);
    let session_config = SessionConfig::from_ref(&state);
    let session_store = <Result<Arc<dyn SessionStore>, AxumError>>::from_ref(&state)?;

    let flow: &Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return Err(AxumError::NotFound(format!(
                "Provider {} not found",
                provider_for_display(&provider)
            )));
        }
    };

    handle_oauth_callback_erased(
        flow.as_ref(),
        cookies,
        params,
        session_store,
        session_config,
        "",
    )
    .await
    .map_err(|(status, msg)| {
        if status == StatusCode::UNAUTHORIZED {
            AxumError::Unauthorized(msg)
        } else {
            AxumError::Internal(msg)
        }
    })
}

#[cfg(feature = "token")]
pub async fn axum_callback_handler_stateless<AppState, S, T>(
    Path(provider): Path<String>,
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(params): Query<OAuthCallbackParams>,
    cookies: Cookies,
) -> Result<impl IntoResponse, AxumError>
where
    AppState: Clone + Send + Sync + 'static,
    Engine<S, T>: axum::extract::FromRef<AppState>,
    SessionConfig: axum::extract::FromRef<AppState>,
    Result<Arc<TokenManager>, AxumError>: axum::extract::FromRef<AppState>,
{
    use axum::extract::FromRef;
    let authkestra = Engine::<S, T>::from_ref(&state);
    let session_config = SessionConfig::from_ref(&state);
    let token_manager = <Result<Arc<TokenManager>, AxumError>>::from_ref(&state)?;

    let flow: &Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return Err(AxumError::NotFound(format!(
                "Provider {} not found",
                provider_for_display(&provider)
            )));
        }
    };

    handle_oauth_callback_jwt_erased(
        flow.as_ref(),
        cookies,
        params,
        token_manager,
        3600, // Default 1 hour expiration
        session_config,
    )
    .await
    .map_err(|(status, msg)| {
        if status == StatusCode::UNAUTHORIZED {
            AxumError::Unauthorized(msg)
        } else {
            AxumError::Internal(msg)
        }
    })
}

#[cfg(feature = "session")]
pub async fn axum_logout_handler<AppState, S, T>(
    axum::extract::State(state): axum::extract::State<AppState>,
    cookies: Cookies,
) -> Result<impl IntoResponse, AxumError>
where
    AppState: Clone + Send + Sync + 'static,
    SessionConfig: axum::extract::FromRef<AppState>,
    Result<Arc<dyn SessionStore>, AxumError>: axum::extract::FromRef<AppState>,
{
    use axum::extract::FromRef;
    let session_config = SessionConfig::from_ref(&state);
    let session_store = <Result<Arc<dyn SessionStore>, AxumError>>::from_ref(&state)?;

    logout(cookies, session_store, session_config, "/")
        .await
        .map_err(|(status, msg)| {
            if status == StatusCode::UNAUTHORIZED {
                AxumError::Unauthorized(msg)
            } else {
                AxumError::Internal(msg)
            }
        })
}

/// The provider name, bounded, for use in a response body.
///
/// The name is an unvalidated, URL-decoded path segment, and the 404 body
/// echoes it back so the caller can see what was not found. Echoing it
/// unbounded means an arbitrarily long attacker-controlled string is reflected
/// into a response; bounding it keeps the message useful and the reflection
/// finite. `authkestra-actix` bounds it identically — the two adapters return
/// the same body by design, and a fix to one that skipped the other would
/// quietly break that.
///
/// The budget is in **bytes**, not characters. What matters for a reflection is
/// how much attacker-controlled data comes back, and 64 characters is up to 256
/// bytes of UTF-8 — so a character bound does not actually bound the response.
/// The cut moves down to a `char` boundary so the result stays valid UTF-8.
fn provider_for_display(provider: &str) -> String {
    const MAX_BYTES: usize = 64;
    if provider.len() <= MAX_BYTES {
        return provider.to_string();
    }
    let mut end = MAX_BYTES;
    while !provider.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &provider[..end])
}

/// How the axum adapter reports a failure.
///
/// `#[non_exhaustive]`, so a future variant is an additive change rather than a
/// major version. That is not free — downstream code cannot match on this
/// exhaustively and needs a wildcard arm — but the alternative is worse. #320
/// was exactly this: the enum had no not-found variant, every unregistered
/// provider fell through to `Internal`, and the fix could not ship as a patch
/// because adding one is breaking under
/// [Cargo's SemVer reference](https://doc.rust-lang.org/cargo/reference/semver.html#enum-variant-new).
/// The next status this adapter needs to distinguish should not have to wait
/// for a major release too.
///
/// Applied in 0.9.0 because that release is already breaking; after it, adding
/// the attribute would itself cost a major.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AxumError {
    Unauthorized(String),
    /// The caller asked for something that does not exist — an unregistered
    /// OAuth provider, say. A client error, not a server fault.
    NotFound(String),
    Internal(String),
    /// A required component (e.g., SessionManager, TokenManager) is missing
    ComponentMissing(String),
}

impl std::fmt::Display for AxumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AxumError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AxumError::NotFound(msg) => write!(f, "Not Found: {}", msg),
            AxumError::Internal(msg) => write!(f, "Internal Error: {}", msg),
            AxumError::ComponentMissing(msg) => write!(f, "Component Missing: {}", msg),
        }
    }
}

impl IntoResponse for AxumError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AxumError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AxumError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AxumError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AxumError::ComponentMissing(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        // `(StatusCode, String)` already sets `text/plain; charset=utf-8`, which
        // is what keeps the echoed provider name in a 404 from being sniffed as
        // HTML. `nosniff` states that explicitly rather than relying on the
        // tuple impl keeping that behaviour, and matches what `authkestra-actix`
        // sends — where the content type has to be set by hand because
        // `HttpResponseBuilder::body` sets none at all.
        (
            status,
            [(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff")],
            message,
        )
            .into_response()
    }
}

#[cfg(feature = "session")]
#[tracing::instrument(skip(store, cookies))]
pub async fn get_session(
    store: &Arc<dyn SessionStore>,
    config: &SessionConfig,
    cookies: &Cookies,
) -> Result<Session, AxumError> {
    tracing::debug!("getting session from cookies");
    let session_id = cookies
        .get(&config.cookie_name)
        .map(|c| c.value().to_string())
        .ok_or_else(|| {
            tracing::warn!("missing session cookie in request");
            AxumError::Unauthorized("Missing session cookie".to_string())
        })?;

    let session = store
        .load_session(&session_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to load session from store");
            AxumError::Internal(e.to_string())
        })?
        .ok_or_else(|| {
            tracing::warn!("session not found or invalid");
            AxumError::Unauthorized("Invalid session".to_string())
        })?;

    tracing::info!(session_id = %session.id, user_id = %session.identity.external_id, "successfully retrieved session");
    Ok(session)
}

#[cfg(feature = "token")]
#[tracing::instrument(skip_all)]
pub async fn get_token(
    parts: &axum::http::request::Parts,
    token_manager: &TokenManager,
) -> Result<authkestra_engine::Claims, AxumError> {
    tracing::debug!("getting token from request parts");
    let auth_header = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("missing Authorization header in request");
            AxumError::Unauthorized("Missing Authorization header".to_string())
        })?;

    if !auth_header.starts_with("Bearer ") {
        tracing::warn!("invalid Authorization header format in request");
        return Err(AxumError::Unauthorized(
            "Invalid Authorization header".to_string(),
        ));
    }

    let token = &auth_header[7..];
    let claims = token_manager.validate_token(token, None).map_err(|e| {
        tracing::error!(error = %e, "failed to validate token");
        AxumError::Unauthorized(format!("Invalid token: {e}"))
    })?;

    tracing::info!("successfully retrieved and validated token");
    Ok(claims)
}
