use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use authkestra_engine::token::cert_binding::ClientCertificateDer;
use authkestra_engine::TokenManager;
use authkestra_op::{
    attestation::{
        AttestationConfig, AttestationStatusProvider, EnrolmentChallengeStore, SecondFactorVerifier,
    },
    config::OpConfig,
    handlers::{
        authorize::{handle_authorize, AuthorizeOutcome, AuthorizeRequest},
        device_authorization::{handle_device_authorization, DeviceAuthorizationRequest},
        discovery::OidcDiscovery,
        enrolment::{
            handle_complete_challenge, handle_enrol_start, handle_reissue_start,
            CompleteChallengeRequest, EnrolStartRequest, ReissueStartRequest,
        },
        jwks::JwksResponse,
        token::{handle_token_with_client_cert, TokenErrorResponse, TokenRequest},
        userinfo::{handle_userinfo, UserInfoErrorResponse, UserInfoRequest},
    },
    OpError,
};
use std::sync::Arc;

pub async fn actix_jwks_handler(token_manager: web::Data<Arc<TokenManager>>) -> impl Responder {
    tracing::debug!("Handling JWKS request (actix)");
    let resp = JwksResponse::new(token_manager.public_jwk());
    HttpResponse::Ok().json(resp)
}

pub async fn actix_discovery_handler(config: web::Data<OpConfig>) -> impl Responder {
    tracing::debug!("Handling OIDC discovery request (actix)");
    let resp = OidcDiscovery::from_config(config.get_ref());
    HttpResponse::Ok().json(resp)
}

pub async fn actix_authorize_handler(
    op_store: web::Data<Arc<dyn authkestra_op::CloneableOpStore>>,
    config: web::Data<OpConfig>,
    auth_session: Option<crate::AuthSession>,
    req: web::Query<AuthorizeRequest>,
) -> actix_web::HttpResponse {
    tracing::debug!(client_id = %req.client_id, "Handling OP authorize request (actix)");
    let identity = match auth_session {
        Some(session) => session.0.identity,
        None => {
            tracing::info!("Unauthenticated user on /authorize, redirecting to /login");
            let login_url = String::from("/login");
            // NOTE: We omit return_to encoding to avoid adding urlencoding dependency for now.
            // login_url.push_str(&format!("?return_to=/authorize?..."));
            return actix_web::HttpResponse::SeeOther()
                .insert_header(("Location", login_url))
                .finish();
        }
    };

    // A fresh, owned clone for this request rather than a shared instance
    // behind a lock — see `authkestra_op::CloneableOpStore`'s doc comment
    // for why that matters for a pool-backed store.
    let mut store = op_store.get_ref().clone_op_store();
    match handle_authorize(req.into_inner(), identity, config.get_ref(), &mut *store).await {
        AuthorizeOutcome::Redirect(url) => HttpResponse::SeeOther()
            .insert_header(("Location", url))
            .finish(),
        AuthorizeOutcome::DirectError(err) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": err.to_string()
        })),
        // `max_age`/`prompt=login` requires a fresher authentication than
        // the current session carries (issue #381). `authkestra-op` cannot
        // perform that re-authentication itself, so — same as the
        // no-session branch above — this sends the browser to the host
        // application's own `/login`. As with that branch, the original
        // request is not carried along yet (see the NOTE above): a
        // deployment that wants `/login` to return here afterward has to
        // thread `reauth.request` through itself for now, which is exactly
        // the gap `return_to` encoding above already leaves open.
        AuthorizeOutcome::ReauthenticationRequired(_reauth) => {
            tracing::info!("authorize request needs fresher authentication, redirecting to /login");
            HttpResponse::SeeOther()
                .insert_header(("Location", "/login"))
                .finish()
        }
        _ => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "server_error",
            "error_description": "unhandled authorize outcome"
        })),
    }
}

pub async fn actix_device_authorization_handler(
    http_req: HttpRequest,
    req: web::Form<DeviceAuthorizationRequest>,
    op_store: web::Data<Arc<dyn authkestra_op::CloneableOpStore>>,
    config: web::Data<OpConfig>,
) -> impl Responder {
    tracing::debug!("Handling OP device authorization request (actix)");

    let auth_header = http_req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let mut store = op_store.get_ref().clone_op_store();
    match handle_device_authorization(req.into_inner(), auth_header, config.get_ref(), &mut *store)
        .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_client" | "unauthorized_client" => {
                    actix_web::http::StatusCode::UNAUTHORIZED
                }
                _ => actix_web::http::StatusCode::BAD_REQUEST,
            };
            HttpResponse::build(status).json(err)
        }
    }
}

/// Reads the request's `DPoP` header (RFC 9449 §4.1: exactly one is
/// expected). Returns `Ok(None)` if it's absent, `Ok(Some(value))` if
/// exactly one occurrence is present and valid ASCII, or `Err` in two
/// cases that are refused outright rather than tolerated:
///
/// - **More than one occurrence.** Which one would be authoritative is
///   ambiguous, and a duplicate is exactly the kind of situation a
///   proxy bug or request-smuggling attempt could produce — a
///   sender-constraining mechanism shouldn't guess which header to
///   trust.
/// - **A value that isn't valid ASCII.** Treating this as "no header"
///   would silently issue a plain Bearer token while the client
///   believes (because it sent one) that it's getting a
///   sender-constrained one — a mangled header should fail loudly, not
///   downgrade silently.
fn extract_dpop_header(
    headers: &actix_web::http::header::HeaderMap,
) -> Result<Option<&str>, TokenErrorResponse> {
    let mut dpop_headers = headers.get_all("DPoP");
    match (dpop_headers.next(), dpop_headers.next()) {
        (None, _) => Ok(None),
        (Some(_), Some(_)) => Err(TokenErrorResponse::new(
            "invalid_dpop_proof".to_string(),
            "Multiple DPoP headers were presented".to_string(),
        )),
        (Some(v), None) => v.to_str().map(Some).map_err(|_| {
            TokenErrorResponse::new(
                "invalid_dpop_proof".to_string(),
                "DPoP header value is not valid ASCII".to_string(),
            )
        }),
    }
}

/// Handler for the token endpoint.
///
/// Certificate binding (RFC 8705, issue #224): this crate does not
/// terminate mTLS itself. `client_cert_der` below is only ever `Some` if a
/// host application's own middleware/acceptor inserted a
/// `ClientCertificateDer` into the actix request's extension map ahead of
/// this handler — see `ClientCertificateDer`'s doc comment.
#[allow(clippy::too_many_arguments)]
pub async fn actix_token_handler(
    http_req: HttpRequest,
    req: web::Form<TokenRequest>,
    op_store: web::Data<Arc<dyn authkestra_op::CloneableOpStore>>,
    tokens: web::Data<Arc<TokenManager>>,
    config: web::Data<OpConfig>,
) -> impl Responder {
    tracing::debug!(grant_type = %req.grant_type, "Handling OP token request (actix)");

    let auth_header = http_req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let client_cert_der = http_req
        .extensions()
        .get::<ClientCertificateDer>()
        .map(|c| c.0.clone());

    // RFC 9449 — an ordinary header, unlike the mTLS certificate above:
    // `http_req` already gives access to the whole header map, no
    // extension-based plumbing needed. See `extract_dpop_header` for why
    // more than one occurrence, or one that isn't valid ASCII, is refused
    // outright rather than tolerated.
    let dpop_header = match extract_dpop_header(http_req.headers()) {
        Ok(h) => h,
        Err(err) => return HttpResponse::BadRequest().json(err),
    };

    let mut store = op_store.get_ref().clone_op_store();
    match handle_token_with_client_cert(
        req.into_inner(),
        auth_header,
        config.get_ref(),
        &mut *store,
        tokens.get_ref().as_ref(),
        client_cert_der.as_deref(),
        dpop_header,
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_client" => actix_web::http::StatusCode::UNAUTHORIZED,
                _ => actix_web::http::StatusCode::BAD_REQUEST,
            };
            HttpResponse::build(status).json(err)
        }
    }
}

pub async fn actix_userinfo_handler(
    http_req: HttpRequest,
    config: web::Data<OpConfig>,
    tokens: web::Data<Arc<TokenManager>>,
    // `/userinfo` is a protected resource, so a DPoP-bound token presented
    // here needs the same replay guard `/token` uses (RFC 9449 §11.1).
    op_store: web::Data<Arc<dyn authkestra_op::CloneableOpStore>>,
) -> impl Responder {
    tracing::debug!("Handling OP userinfo request (actix)");

    let unauthorized = |scheme: &str, desc: &str| {
        HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", scheme.to_string()))
            .json(UserInfoErrorResponse::new(
                "invalid_request".to_string(),
                desc.to_string(),
            ))
    };

    // RFC 9110 §11.1 makes the auth-scheme token case-insensitive, and
    // RFC 9449 §7.1 requires a DPoP-bound token to arrive under the `DPoP`
    // scheme rather than `Bearer`. Which scheme was used is passed through
    // to the handler, which refuses the two mismatches.
    let auth_header = match http_req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        Some(h) => h,
        None => return unauthorized("Bearer", "Missing or invalid Authorization header"),
    };
    let (token, presented_as_dpop) = match auth_header.split_once(' ') {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer") => (rest.trim(), false),
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("dpop") => (rest.trim(), true),
        _ => return unauthorized("Bearer", "Missing or invalid Authorization header"),
    };
    if token.is_empty() {
        return unauthorized("Bearer", "Missing or invalid Authorization header");
    }

    let req = if presented_as_dpop {
        let proof = match extract_dpop_header(http_req.headers()) {
            Ok(p) => p.map(|p| p.to_string()),
            Err(e) => {
                return HttpResponse::Unauthorized()
                    .insert_header(("WWW-Authenticate", "DPoP"))
                    .json(UserInfoErrorResponse::new(e.error, e.error_description));
            }
        };
        // `htu` is left `None`: behind a reverse proxy this handler cannot
        // reconstruct the absolute URL the client signed. See
        // `UserInfoRequest::htu`.
        UserInfoRequest::new_dpop(
            token.to_string(),
            proof,
            Some(http_req.method().as_str().to_string()),
            None,
        )
    } else {
        UserInfoRequest::new(token.to_string())
    };

    let mut store = op_store.get_ref().clone_op_store();
    let response = match handle_userinfo(
        req,
        config.get_ref(),
        tokens.get_ref().as_ref(),
        &mut *store,
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_token" => actix_web::http::StatusCode::UNAUTHORIZED,
                "insufficient_scope" => actix_web::http::StatusCode::FORBIDDEN,
                _ => actix_web::http::StatusCode::BAD_REQUEST,
            };
            HttpResponse::build(status).json(err)
        }
    };
    response
}

pub async fn actix_device_verify_handler(
    http_req: HttpRequest,
    req: web::Form<authkestra_op::handlers::device_verify::DeviceVerifyRequest>,
    op_store: web::Data<Arc<dyn authkestra_op::CloneableOpStore>>,
    op_config: Option<web::Data<OpConfig>>,
    session_config: Option<web::Data<authkestra_engine::SessionConfig>>,
    auth_session: Option<crate::AuthSession>,
) -> actix_web::HttpResponse {
    tracing::debug!("Handling OP device verify request (actix)");

    if http_req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("cross-site"))
        .unwrap_or(false)
    {
        tracing::warn!("cross-site request rejected on /device/verify via Sec-Fetch-Site");
        return actix_web::HttpResponse::Forbidden().json(serde_json::json!({
            "error": "access_denied",
            "error_description": "Cross-site request rejected"
        }));
    }

    if let (Some(origin_val), Some(cfg)) = (
        http_req.headers().get(actix_web::http::header::ORIGIN),
        op_config.as_ref(),
    ) {
        if let Ok(origin_str) = origin_val.to_str() {
            if let Ok(issuer_url) = url::Url::parse(&cfg.issuer) {
                let expected_origin = issuer_url.origin().ascii_serialization();
                if !origin_str.eq_ignore_ascii_case(&expected_origin) {
                    tracing::warn!(origin = %origin_str, expected = %expected_origin, "origin mismatch on /device/verify");
                    return actix_web::HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "access_denied",
                        "error_description": "Origin mismatch"
                    }));
                }
            }
        }
    }

    let session = match auth_session {
        Some(session) => session.0,
        None => {
            tracing::info!("Unauthenticated user on /device/verify, redirecting to /login");
            let login_url = String::from("/login");
            return actix_web::HttpResponse::SeeOther()
                .insert_header(("Location", login_url))
                .finish();
        }
    };

    if let (Some(ref csrf_token), Some(ref sess_cfg)) = (&req.csrf_token, &session_config) {
        if !authkestra_op::handlers::device_verify::verify_csrf_token(
            &sess_cfg.state_encryption_key,
            &session.id,
            csrf_token,
        ) {
            tracing::warn!("invalid CSRF token on /device/verify");
            return actix_web::HttpResponse::Forbidden().json(serde_json::json!({
                "error": "access_denied",
                "error_description": "Invalid CSRF token"
            }));
        }
    }

    let mut store = op_store.get_ref().clone_op_store();
    match authkestra_op::handlers::device_verify::handle_device_verify(
        req.into_inner(),
        session.identity,
        &mut *store,
    )
    .await
    {
        Ok(resp) => actix_web::HttpResponse::Ok().json(resp),
        Err(err) => actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": err.to_string()
        })),
    }
}

/// Maps an `OpError` from the attestation ceremony to an HTTP status and an
/// OAuth2-shaped `{error, error_description}` body, matching the style the
/// other OP handlers in this file already use for their own error enums.
fn attestation_error_response(err: OpError) -> HttpResponse {
    let status = match &err {
        OpError::BadJwk(_) | OpError::BadAlg(_) => actix_web::http::StatusCode::BAD_REQUEST,
        OpError::InvalidChallenge
        | OpError::ChallengeSignatureInvalid
        | OpError::AttestationInvalid
        | OpError::KeyNotBound
        | OpError::SecondFactorFailed => actix_web::http::StatusCode::UNAUTHORIZED,
        OpError::PrincipalRevoked => actix_web::http::StatusCode::FORBIDDEN,
        _ => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
    };
    let code = match &err {
        OpError::PrincipalRevoked => "access_denied",
        OpError::BadJwk(_) | OpError::BadAlg(_) => "invalid_request",
        _ if status == actix_web::http::StatusCode::INTERNAL_SERVER_ERROR => "server_error",
        _ => "invalid_grant",
    };
    HttpResponse::build(status).json(serde_json::json!({
        "error": code,
        "error_description": err.to_string(),
    }))
}

/// Handler for beginning device/service enrolment (spec §5.6 steps 1-3).
pub async fn actix_enrol_start_handler(
    req: web::Json<EnrolStartRequest>,
    second_factor: web::Data<Arc<dyn SecondFactorVerifier>>,
    challenges: web::Data<Arc<dyn EnrolmentChallengeStore>>,
    config: web::Data<AttestationConfig>,
) -> impl Responder {
    tracing::debug!(principal_type = ?req.principal_type, "Handling OP enrol start request (actix)");
    match handle_enrol_start(
        req.into_inner(),
        second_factor.get_ref().as_ref(),
        challenges.get_ref().as_ref(),
        config.get_ref(),
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => attestation_error_response(err),
    }
}

/// Handler for beginning re-issuance of a near-expiry attestation (ADR 0014
/// decision point 6). `AttestationStatusProvider` is optional: an app that
/// has not registered one simply gets `None` here (same `Option<T>`
/// extractor pattern already used for `crate::AuthSession` above), and
/// re-issuance falls back to copying the previous `att` claim forward — see
/// `handle_reissue_start`'s docs.
pub async fn actix_reissue_start_handler(
    req: web::Json<ReissueStartRequest>,
    tokens: web::Data<Arc<TokenManager>>,
    status_provider: Option<web::Data<Arc<dyn AttestationStatusProvider>>>,
    challenges: web::Data<Arc<dyn EnrolmentChallengeStore>>,
    config: web::Data<AttestationConfig>,
) -> impl Responder {
    tracing::debug!("Handling OP re-issuance start request (actix)");
    let status_provider = status_provider.as_ref().map(|d| d.get_ref().as_ref());

    match handle_reissue_start(
        req.into_inner(),
        tokens.get_ref().as_ref(),
        status_provider,
        challenges.get_ref().as_ref(),
        config.get_ref(),
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => attestation_error_response(err),
    }
}

/// Handler completing either an enrolment or a re-issuance ceremony — the
/// same operation either way (see `handle_complete_challenge`'s docs).
pub async fn actix_complete_challenge_handler(
    req: web::Json<CompleteChallengeRequest>,
    challenges: web::Data<Arc<dyn EnrolmentChallengeStore>>,
    tokens: web::Data<Arc<TokenManager>>,
    config: web::Data<AttestationConfig>,
) -> impl Responder {
    tracing::debug!("Handling OP enrolment/re-issuance completion request (actix)");
    match handle_complete_challenge(
        req.into_inner(),
        challenges.get_ref().as_ref(),
        tokens.get_ref().as_ref(),
        config.get_ref(),
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => attestation_error_response(err),
    }
}

pub trait OpExt {
    fn op_actix_scope(&self) -> actix_web::Scope;
}

impl<T> OpExt for T {
    fn op_actix_scope(&self) -> actix_web::Scope {
        web::scope("")
            .route("/jwks.json", web::get().to(actix_jwks_handler))
            .route(
                "/.well-known/openid-configuration",
                web::get().to(actix_discovery_handler),
            )
            .route("/authorize", web::get().to(actix_authorize_handler))
            .route(
                "/device_authorization",
                web::post().to(actix_device_authorization_handler),
            )
            .route("/token", web::post().to(actix_token_handler))
            .route("/userinfo", web::get().to(actix_userinfo_handler))
            .route("/userinfo", web::post().to(actix_userinfo_handler))
            .route(
                "/device/verify",
                web::post().to(actix_device_verify_handler),
            )
            .route("/enrol", web::post().to(actix_enrol_start_handler))
            .route(
                "/enrol/complete",
                web::post().to(actix_complete_challenge_handler),
            )
            .route("/reissue", web::post().to(actix_reissue_start_handler))
    }
}

use authkestra_engine::{Configured, Engine};
type CompleteOp = authkestra_op::Op<
    Engine<Configured<Arc<dyn crate::SessionStore>>, Configured<Arc<TokenManager>>>,
    Arc<dyn authkestra_op::CloneableOpStore>,
>;

pub trait OpActixExt {
    fn configure_op(self, op: CompleteOp) -> Self;
}

impl OpActixExt for &mut web::ServiceConfig {
    fn configure_op(self, op: CompleteOp) -> Self {
        self.app_data(web::Data::new(op.store.clone()))
            .app_data(web::Data::new(op.engine.token_manager.0.clone()))
            .app_data(web::Data::new(op.engine.session_store.0.clone()))
            .app_data(web::Data::new(op.engine.session_config.clone()))
            .app_data(web::Data::new(op.config.clone()));

        if let Some(cfg) = op.attestation_config {
            self.app_data(web::Data::new(cfg));
        }
        if let Some(store) = op.challenge_store {
            self.app_data(web::Data::new(store));
        }
        if let Some(verifier) = op.second_factor_verifier {
            self.app_data(web::Data::new(verifier));
        }
        if let Some(provider) = op.status_provider {
            self.app_data(web::Data::new(provider));
        }
        self
    }
}

#[cfg(test)]
mod dpop_header_tests {
    use super::extract_dpop_header;
    use actix_web::http::header::{HeaderMap, HeaderValue};

    #[test]
    fn no_header_is_none() {
        let headers = HeaderMap::new();
        assert_eq!(extract_dpop_header(&headers).unwrap(), None);
    }

    #[test]
    fn exactly_one_header_is_returned() {
        let mut headers = HeaderMap::new();
        headers.insert(
            actix_web::http::header::HeaderName::from_static("dpop"),
            HeaderValue::from_static("proof-value"),
        );
        assert_eq!(extract_dpop_header(&headers).unwrap(), Some("proof-value"));
    }

    /// RFC 9449 §4.1 expects exactly one `DPoP` header; a duplicate is
    /// refused outright rather than silently resolved by picking one.
    #[test]
    fn two_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        let name = actix_web::http::header::HeaderName::from_static("dpop");
        headers.append(name.clone(), HeaderValue::from_static("first"));
        headers.append(name, HeaderValue::from_static("second"));
        let err = extract_dpop_header(&headers).expect_err("a duplicate header must be refused");
        assert_eq!(err.error, "invalid_dpop_proof");
    }

    /// A header value that isn't valid ASCII must be refused, not silently
    /// treated as "no header present" (which would issue a plain Bearer
    /// token while the client believes it asked for — and thinks it got —
    /// a sender-constrained one).
    #[test]
    fn non_ascii_header_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            actix_web::http::header::HeaderName::from_static("dpop"),
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        let err = extract_dpop_header(&headers).expect_err("a non-ASCII header must be refused");
        assert_eq!(err.error, "invalid_dpop_proof");
    }
}
