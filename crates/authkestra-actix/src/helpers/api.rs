#![allow(unused_imports)]
use actix_web::{cookie::Cookie, http::header, web, HttpRequest, HttpResponse};
pub use authkestra_engine::auth::{
    is_safe_relative_url, resolve_redirect_target, Session, SessionConfig, SessionStore,
};
use authkestra_engine::auth::{Identity, OAuthToken};
use authkestra_engine::pkce::Pkce;
use authkestra_engine::{state::OAuth2State, Engine, ErasedOAuthFlow, OAuth2Flow};
#[allow(unused_imports)]
use std::sync::Arc;

#[cfg(feature = "session")]
use super::cookie::create_actix_cookie;

/// The cookie carrying the encrypted OAuth state between the authorization
/// redirect and the callback. Named once: it was written as a literal at each
/// of the three places that touch it.
const STATE_COOKIE: &str = "ak_state";

/// The provider name, bounded, for use in a response body.
///
/// The name is an unvalidated, URL-decoded path segment, and the 404 body
/// echoes it back so the caller can see what was not found. Echoing it
/// unbounded means an arbitrarily long attacker-controlled string is reflected
/// into a response; bounding it keeps the message useful and the reflection
/// finite. `authkestra-axum` bounds it identically — the two adapters return
/// the same body by design, and a fix to one that skipped the other would
/// quietly break that.
///
/// The budget is in **bytes**, not characters. What matters for a reflection is
/// how much attacker-controlled data comes back, and 64 characters is up to 256
/// bytes of UTF-8 — so a character bound does not actually bound the response.
/// The cut is moved down to a `char` boundary so the result is still valid UTF-8.
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

/// The 404 for an unregistered provider.
///
/// Built in one place because the `Content-Type` is load-bearing and easy to
/// forget: `HttpResponseBuilder::body` sets no content type at all, and a
/// response with none *and* an echoed path segment is sniffed as HTML by
/// browsers — which turns this message into a reflected-XSS sink reachable from
/// a plain link. `authkestra-axum` gets `text/plain` for free from
/// `(StatusCode, String)`; actix does not, so it is set explicitly here, with
/// `nosniff` as the belt to that braces.
fn provider_not_found(provider: &str) -> HttpResponse {
    HttpResponse::NotFound()
        .content_type(actix_web::http::header::ContentType::plaintext())
        .insert_header(("x-content-type-options", "nosniff"))
        .body(format!(
            "Provider {} not found",
            provider_for_display(provider)
        ))
}

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

/// Helper to initiate the OAuth2 login flow.
///
/// This generates the authorization URL and sets a CSRF state cookie.
pub fn initiate_oauth_login<P, M>(
    flow: &OAuth2Flow<P, M>,
    scopes: &[&str],
    config: &SessionConfig,
    success_url: Option<String>,
) -> HttpResponse
where
    P: authkestra_engine::OAuthProvider + 'static,
    M: authkestra_engine::UserMapper + 'static,
{
    initiate_oauth_login_erased(flow, scopes, config, success_url)
}

/// Type-erased helper to initiate the OAuth2 login flow and set a CSRF state cookie.
pub fn initiate_oauth_login_erased(
    flow: &dyn ErasedOAuthFlow,
    scopes: &[&str],
    config: &SessionConfig,
    success_url: Option<String>,
) -> HttpResponse {
    let pkce = Pkce::new();
    let (url, mut auth_state) = flow.initiate_login(scopes, Some(&pkce.code_challenge));

    auth_state.code_verifier = Some(pkce.code_verifier);
    let safe_success_url = match success_url {
        Some(ref u) if is_safe_relative_url(u) => success_url,
        Some(invalid) => {
            tracing::warn!(
                invalid = ?invalid.chars().take(128).collect::<String>(),
                "unsafe or invalid success_url provided in login request; ignoring"
            );
            None
        }
        None => None,
    };
    auth_state.success_url = safe_success_url;

    let encrypted = auth_state
        .encrypt(&config.state_encryption_key)
        .expect("Failed to encrypt OAuth state");

    let cookie = Cookie::build(STATE_COOKIE, encrypted)
        .path("/")
        .http_only(true)
        .same_site(actix_web::cookie::SameSite::Lax)
        .secure(true)
        .max_age(actix_web::cookie::time::Duration::minutes(15))
        .finish();

    // 303, not 302: the target is fetched with GET regardless of how this
    // route was reached, which is exactly what a redirect-to-the-provider
    // means. `authkestra-axum` sends 303 here too — `Redirect::to` is 303 —
    // and the two adapters must not disagree on the status code for the same
    // request. See issue #320 for the class of bug that causes.
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
    HttpResponse::SeeOther()
        .insert_header((header::LOCATION, url))
        .cookie(cookie)
        .finish()
}

/// Helper to handle the OAuth2 callback and create a server-side session.
#[cfg(feature = "session")]
pub async fn handle_oauth_callback<P, M>(
    req: HttpRequest,
    flow: &OAuth2Flow<P, M>,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<HttpResponse, actix_web::Error>
where
    P: authkestra_engine::OAuthProvider + Send + Sync + 'static,
    M: authkestra_engine::UserMapper + Send + Sync + 'static,
{
    handle_oauth_callback_erased(req, flow, params, store, config, success_url).await
}

/// Validates the callback's state cookie and exchanges the code for an
/// identity, shared by both callbacks.
///
/// Extracted for #356. This crate previously inlined the sequence twice, once
/// per callback, while `authkestra-axum` routed both of its callbacks through
/// a single helper of the same name. The duplicated part is the CSRF defence,
/// and the part that legitimately differs — creating a session versus issuing
/// a token — sat immediately after it, which is the shape that invites drift.
///
/// It did drift: the debug line reporting the resolved identity was added to
/// one copy and missed from the other, in the change that introduced it
/// (#355, corrected in #357). Sharing the block removes the possibility
/// rather than the instance.
///
/// The three failure modes are reported distinctly here, so an operator can
/// tell a browser `SameSite` problem from a rotated `state_encryption_key`
/// from a provider refusal — all three of which are otherwise an identical
/// 401.
#[cfg(any(feature = "session", feature = "token"))]
async fn finalize_callback_erased(
    req: &HttpRequest,
    flow: &dyn ErasedOAuthFlow,
    params: &OAuthCallbackParams,
    config: &SessionConfig,
) -> Result<(Identity, OAuthToken, OAuth2State), actix_web::Error> {
    let encrypted_state = req
        .cookie(STATE_COOKIE)
        .map(|c: Cookie| c.value().to_string())
        .ok_or_else(|| {
            // No cookie at all, which is usually the browser rather than the
            // user: a `SameSite`/`Secure` mismatch, or a callback arriving
            // after the fifteen-minute lifetime.
            tracing::warn!("OAuth callback carries no state cookie; cannot validate CSRF");
            actix_web::error::ErrorUnauthorized("CSRF validation failed or session expired")
        })?;

    let expected_state = OAuth2State::decrypt(&encrypted_state, &config.state_encryption_key)
        .map_err(|e| {
            // The cookie arrived but would not decrypt. A rotated
            // `state_encryption_key` fails every in-flight login exactly
            // like this, and nothing else in the system would say so.
            tracing::warn!(
                error = %e,
                "OAuth state cookie could not be decrypted; if the state encryption key \
                 was rotated, logins started before the rotation will all fail this way"
            );
            actix_web::error::ErrorUnauthorized(format!("Invalid state cookie: {e}"))
        })?;

    let (identity, token) = flow
        .finalize_login(&params.code, &params.state, &expected_state)
        .await
        .map_err(|e| {
            // The state checked out; the provider exchange is what failed.
            tracing::warn!(error = %e, "OAuth code exchange failed after state validation");
            actix_web::error::ErrorUnauthorized(format!("Authentication failed: {e}"))
        })?;

    tracing::debug!(
        external_id = %identity.external_id,
        "OAuth callback validated and exchanged for an identity"
    );

    Ok((identity, token, expected_state))
}

/// Type-erased helper to handle the OAuth2 callback and create a server-side session.
#[cfg(feature = "session")]
pub async fn handle_oauth_callback_erased(
    req: HttpRequest,
    flow: &dyn ErasedOAuthFlow,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<HttpResponse, actix_web::Error> {
    let (mut identity, token, expected_state) =
        finalize_callback_erased(&req, flow, &params, &config).await?;

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

    let user_id = session.identity.external_id.clone();
    store.save_session(&session).await.map_err(|e| {
        tracing::error!(error = %e, "failed to persist the session after a successful login");
        actix_web::error::ErrorInternalServerError(format!("Failed to save session: {e}"))
    })?;
    tracing::info!(%user_id, "OAuth login completed; session created");

    let cookie = create_actix_cookie(&config, session.id);

    // Remove the flow cookie
    let remove_cookie = Cookie::build(STATE_COOKIE, "")
        .path("/")
        .secure(true)
        .max_age(actix_web::cookie::time::Duration::ZERO)
        .finish();

    if let Some(ref invalid) = expected_state.success_url {
        if !is_safe_relative_url(invalid) {
            tracing::warn!(
                invalid = ?invalid.chars().take(128).collect::<String>(),
                "unsafe success_url found in OAuth state during callback redirect; falling back to default"
            );
        }
    }
    let final_success_url =
        resolve_redirect_target(expected_state.success_url.as_deref(), success_url);

    Ok(HttpResponse::SeeOther()
        .insert_header((header::LOCATION, final_success_url))
        .cookie(cookie)
        .cookie(remove_cookie)
        .finish())
}
pub async fn actix_login_handler<S, T>(
    path: web::Path<String>,
    authkestra: web::Data<Engine<S, T>>,
    params: web::Query<OAuthLoginParams>,
) -> impl actix_web::Responder {
    let provider = path.into_inner();
    let flow: &std::sync::Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return provider_not_found(&provider);
        }
    };

    let scopes_str = params.scope.clone().unwrap_or_default();
    let scopes: Vec<&str> = scopes_str
        .split(|c: char| [' ', ','].contains(&c))
        .filter(|s: &&str| !s.is_empty())
        .collect();

    initiate_oauth_login_erased(
        flow.as_ref(),
        &scopes,
        &authkestra.session_config,
        params.success_url.clone(),
    )
}

#[cfg(feature = "session")]
pub async fn actix_callback_handler<S, T>(
    req: HttpRequest,
    path: web::Path<String>,
    authkestra: web::Data<Engine<S, T>>,
    params: web::Query<OAuthCallbackParams>,
) -> actix_web::Result<impl actix_web::Responder>
where
    S: authkestra_engine::SessionStoreState,
{
    let provider = path.into_inner();
    let flow: &std::sync::Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return Ok(provider_not_found(&provider));
        }
    };

    let callback_params = params.into_inner();

    let response = handle_oauth_callback_erased(
        req,
        flow.as_ref(),
        callback_params,
        authkestra.session_store.get_store(),
        authkestra.session_config.clone(),
        "",
    )
    .await?;

    Ok(response)
}

#[cfg(feature = "session")]
pub async fn actix_logout_handler<S, T>(
    req: HttpRequest,
    authkestra: web::Data<Engine<S, T>>,
) -> actix_web::Result<impl actix_web::Responder>
where
    S: authkestra_engine::SessionStoreState,
{
    logout(
        req,
        authkestra.session_store.get_store(),
        authkestra.session_config.clone(),
        "/",
    )
    .await
}

/// Helper to handle logout by deleting the session from the store and clearing the cookie.
#[cfg(feature = "session")]
pub async fn logout(
    req: HttpRequest,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    redirect_to: &str,
) -> Result<HttpResponse, actix_web::Error> {
    if req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("cross-site"))
        .unwrap_or(false)
    {
        tracing::warn!("cross-site logout rejected via Sec-Fetch-Site");
        return Err(actix_web::error::ErrorUnauthorized(
            "Cross-site request rejected",
        ));
    }

    let session_id = req
        .cookie(&config.cookie_name)
        .map(|c: Cookie| c.value().to_string());

    if let Some(id) = session_id {
        store.delete_session(&id).await.map_err(|e| {
            tracing::error!(error = %e, "failed to delete the session during logout");
            actix_web::error::ErrorInternalServerError(e.to_string())
        })?;
        tracing::info!("session deleted on logout");
    } else {
        // Still clears the cookie below, so this is a no-op logout rather
        // than an error.
        tracing::debug!("logout with no session cookie present; clearing the cookie anyway");
    }

    let remove_cookie = create_actix_cookie(&config, "".to_string());

    let target = if is_safe_relative_url(redirect_to) {
        redirect_to
    } else {
        tracing::warn!(%redirect_to, "unsafe redirect_to in logout; falling back to '/'");
        "/"
    };

    Ok(HttpResponse::SeeOther()
        .insert_header((header::LOCATION, target))
        .cookie(remove_cookie)
        .finish())
}

/// Helper to handle the OAuth2 callback and return a JWT for stateless auth.
#[cfg(feature = "token")]
pub async fn handle_oauth_callback_jwt_erased(
    flow: &dyn ErasedOAuthFlow,
    req: &HttpRequest,
    params: OAuthCallbackParams,
    token_manager: Arc<authkestra_engine::TokenManager>,
    expires_in_secs: u64,
    config: SessionConfig,
) -> Result<HttpResponse, actix_web::Error> {
    let (identity, _token, _expected_state) =
        finalize_callback_erased(req, flow, &params, &config).await?;

    let user_id = identity.external_id.clone();
    let jwt = token_manager
        .issue_user_token(identity, expires_in_secs, None, None)
        // Not covered by a test, deliberately: signing with a fixed secret
        // has no reachable failure mode, so exercising this would mean
        // contriving one. Logged rather than dropped because if it ever does
        // fire, the login has failed for a reason nothing else would explain.
        .map_err(|e| {
            tracing::error!(error = %e, "failed to issue a token after a successful login");
            actix_web::error::ErrorInternalServerError(format!("Token error: {e}"))
        })?;
    // The token itself is a credential and is not logged.
    tracing::info!(%user_id, expires_in_secs, "OAuth login completed; token issued");

    let mut res = HttpResponse::Ok();

    // Remove the flow cookie
    let remove_cookie = Cookie::build(STATE_COOKIE, "")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::ZERO)
        .secure(true)
        .finish();

    res.cookie(remove_cookie);

    Ok(res.json(serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": expires_in_secs
    })))
}

/// Helper to handle the OAuth2 callback and return a JWT for stateless auth.
#[cfg(feature = "token")]
pub async fn handle_oauth_callback_jwt<P, M>(
    flow: &OAuth2Flow<P, M>,
    req: &HttpRequest,
    params: OAuthCallbackParams,
    token_manager: Arc<authkestra_engine::TokenManager>,
    expires_in_secs: u64,
    config: SessionConfig,
) -> Result<HttpResponse, actix_web::Error>
where
    P: authkestra_engine::OAuthProvider + Send + Sync + 'static,
    M: authkestra_engine::UserMapper + Send + Sync + 'static,
{
    handle_oauth_callback_jwt_erased(flow, req, params, token_manager, expires_in_secs, config)
        .await
}

#[cfg(feature = "token")]
pub async fn actix_callback_handler_stateless<S, T>(
    req: HttpRequest,
    path: web::Path<String>,
    authkestra: web::Data<Engine<S, T>>,
    params: web::Query<OAuthCallbackParams>,
) -> actix_web::Result<impl actix_web::Responder>
where
    T: authkestra_engine::TokenManagerState,
{
    let provider = path.into_inner();
    let flow: &std::sync::Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return Ok(provider_not_found(&provider));
        }
    };

    let callback_params = params.into_inner();

    let response = handle_oauth_callback_jwt_erased(
        flow.as_ref(),
        &req,
        callback_params,
        authkestra.token_manager.get_manager(),
        3600, // Default 1 hour expiration
        authkestra.session_config.clone(),
    )
    .await?;

    Ok(response)
}
