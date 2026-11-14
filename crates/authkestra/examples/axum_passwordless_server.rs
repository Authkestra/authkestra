//! # Axum Passwordless Authentication Server Example
//!
//! Runnable standalone in-memory server implementing the complete Authkestra Passwordless HTTP API
//! specification defined in `docs/passwordless-http-shapes.md`:
//! 1. Passkeys / WebAuthn (`/auth/passkey/*`)
//! 2. Magic Links (`/auth/magic-link/*`)
//! 3. One-Time Passcodes (Email/SMS) (`/auth/otp/*`)
//! 4. Recovery Codes (`/auth/recovery/*`)
//!
//! ## Execution Modes:
//! - Default / no args: executes automated end-to-end self-test verifying all flows, HTTP shapes,
//!   single-use guarantees, and wire error codes (400, 401, 403, 429).
//! - `--serve` or `PORT=<port>`: binds as a standing daemon and logs `READY: listening on http://...`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use authkestra_engine::auth::magic_link::{MagicLinkAuthMethod, MagicLinkBinding, MagicLinkRecord};
use authkestra_engine::auth::otp::{OtpAuthMethod, OtpChallenge, OtpChannel};
use authkestra_engine::auth::recovery::RecoveryCodeAuthMethod;
use authkestra_engine::auth::session::Session;
use authkestra_engine::auth::state::{
    IDENTITY_ATTR_AMR, IDENTITY_ATTR_AUTH_TIME, IDENTITY_ATTR_OTP_CHANNEL,
    IDENTITY_ATTR_STEP_UP_SATISFIED, METHOD_NAME_MAGIC_LINK, METHOD_NAME_RECOVERY_CODE,
    METHOD_NAME_WEBAUTHN,
};
use authkestra_engine::auth::webauthn::{derive_user_handle, PasskeyEnrolment, WebAuthnAuthMethod};
use authkestra_engine::auth::{
    AuthError, AuthInput, AuthMethod, AuthResult, CredentialStore, Identity, ReproofRequirement,
};
use authkestra_engine::store::memory::{MemoryCredentialStore, MemoryStore};
use authkestra_engine::store::KvStore;
use authkestra_engine::{AkEngine, Engine, SessionConfig, TokenManager};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use tokio::sync::RwLock;
use url::Url;
use webauthn_rs::prelude::*;

const SESSION_COOKIE_NAME: &str = "ak_session";
const ML_BINDING_COOKIE_NAME: &str = "ml_binding";

#[derive(Clone)]
pub struct AppState {
    pub engine: AkEngine,
    pub session_store: Arc<MemoryStore<Session>>,
    pub session_config: SessionConfig,
    pub credential_store: MemoryCredentialStore,
    pub webauthn: Arc<Webauthn>,
    pub webauthn_method: Arc<WebAuthnAuthMethod<MemoryCredentialStore>>,
    pub magic_link_method: Arc<MagicLinkAuthMethod<MemoryStore<MagicLinkRecord>>>,
    pub otp_method: Arc<OtpAuthMethod<MemoryStore<OtpChallenge>>>,
    pub recovery_method: Arc<RecoveryCodeAuthMethod<MemoryCredentialStore>>,
    // Ceremony session state for registration & assertion
    pub passkey_enrolments: Arc<RwLock<HashMap<String, PasskeyEnrolment>>>,
    pub passkey_authentications: Arc<RwLock<HashMap<String, PasskeyAuthentication>>>,
    // Test inspection helper to retrieve out-of-band codes without real mailer/SMS
    pub test_secrets: Arc<RwLock<HashMap<String, String>>>,
}

// ---------------------------------------------------------------------------
// Helpers: Cookie & Response Builders
// ---------------------------------------------------------------------------

fn extract_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)
        .and_then(|val| val.to_str().ok())
        .and_then(|cookies| {
            for cookie in cookies.split(';') {
                let mut parts = cookie.splitn(2, '=');
                if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                    if k.trim() == name {
                        return Some(v.trim());
                    }
                }
            }
            None
        })
}

fn json_response<T: serde::Serialize>(status: StatusCode, body: T) -> Response {
    let mut resp = (status, Json(body)).into_response();
    apply_security_headers(&mut resp);
    resp
}

fn error_response(status: StatusCode, error: &str, description: &str) -> Response {
    let mut resp = (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description
        })),
    )
        .into_response();
    apply_security_headers(&mut resp);
    resp
}

fn apply_security_headers(resp: &mut Response) {
    let headers = resp.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
}

fn set_cookie_header(resp: &mut Response, name: &str, value: &str, max_age_secs: Option<u64>) {
    let cookie = match max_age_secs {
        Some(max_age) => {
            format!("{name}={value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={max_age}")
        }
        None => format!("{name}={value}; HttpOnly; Secure; SameSite=Lax; Path=/"),
    };
    if let Ok(val) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, val);
    }
}

fn clear_cookie_header(resp: &mut Response, name: &str) {
    let cookie = format!("{name}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
    if let Ok(val) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, val);
    }
}

async fn get_authenticated_session(
    headers: &HeaderMap,
    session_store: &MemoryStore<Session>,
) -> Option<Session> {
    let session_id = extract_cookie(headers, SESSION_COOKIE_NAME).or_else(|| {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
    })?;

    session_store.get(session_id).await.ok().flatten()
}

async fn establish_session(state: &AppState, identity: &Identity) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    let session = Session::new(
        session_id.clone(),
        identity.clone(),
        chrono::Utc::now() + chrono::Duration::seconds(86400),
    );
    let _ = state
        .session_store
        .set(&session_id, session, Duration::from_secs(86400))
        .await;
    session_id
}

fn extract_webauthn_challenge(client_data_json_b64: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(client_data_json_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(client_data_json_b64))
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("challenge")?.as_str().map(String::from)
}

// ---------------------------------------------------------------------------
// 1. Passkey Handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PasskeyRegisterStartRequest {
    username: Option<String>,
    display_name: Option<String>,
}

async fn passkey_register_start_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyRegisterStartRequest>,
) -> Response {
    let username = match payload.username.filter(|u| !u.trim().is_empty()) {
        Some(u) => u,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Field 'username' is required.",
            )
        }
    };

    let session = match get_authenticated_session(&headers, &state.session_store).await {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::FORBIDDEN,
                "reproof_required",
                "Recent authentication required: no active session found.",
            );
        }
    };

    let gate = ReproofRequirement::new(300);
    let identity = session.identity.clone();

    if let Err(e) = gate.check(&identity) {
        return error_response(StatusCode::FORBIDDEN, "reproof_required", &e.to_string());
    }

    let display_name = payload.display_name.unwrap_or_else(|| username.clone());
    let handle = derive_user_handle(&identity.external_id);

    match state.webauthn_method.start_register_with_handle(
        &identity,
        &gate,
        handle,
        &username,
        &display_name,
    ) {
        Ok((challenge, enrolment)) => {
            state
                .passkey_enrolments
                .write()
                .await
                .insert(session.id.clone(), enrolment);

            json_response(StatusCode::OK, challenge)
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string()),
    }
}

async fn passkey_register_finish_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(raw_payload): Json<serde_json::Value>,
) -> Response {
    let session = match get_authenticated_session(&headers, &state.session_store).await {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "No active session for passkey registration.",
            );
        }
    };

    let payload: RegisterPublicKeyCredential = match serde_json::from_value(raw_payload) {
        Ok(p) => p,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("Malformed registration credential: {e}"),
            );
        }
    };

    let enrolment = match state.passkey_enrolments.write().await.remove(&session.id) {
        Some(e) => e,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "No passkey registration ceremony found for this session.",
            );
        }
    };

    match state
        .webauthn_method
        .finish_register(enrolment, payload)
        .await
    {
        Ok(passkey) => {
            let cred_id =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "success",
                    "credential_id": cred_id,
                }),
            )
        }
        Err(e) => error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            &e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
struct PasskeyLoginStartRequest {
    username: Option<String>,
}

async fn passkey_login_start_handler(
    State(state): State<AppState>,
    Json(payload): Json<PasskeyLoginStartRequest>,
) -> Response {
    let passkeys = if let Some(username) = payload.username {
        match state
            .credential_store
            .get_credentials(&username, METHOD_NAME_WEBAUTHN)
            .await
        {
            Ok(creds) => creds
                .into_iter()
                .filter_map(|c| serde_json::from_value::<Passkey>(c).ok())
                .collect(),
            Err(_) => vec![],
        }
    } else {
        vec![]
    };

    match state.webauthn.start_passkey_authentication(&passkeys) {
        Ok((challenge, auth_state)) => {
            let challenge_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(challenge.public_key.challenge.as_ref());
            state
                .passkey_authentications
                .write()
                .await
                .insert(challenge_id, auth_state);

            json_response(StatusCode::OK, challenge)
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &format!("Failed to start passkey assertion: {e}"),
        ),
    }
}

#[derive(Deserialize)]
struct PasskeyLoginFinishFlat {
    user_id: Option<String>,
    credential_id: Option<String>,
    client_data_json: Option<String>,
    authenticator_data: Option<String>,
    signature: Option<String>,
    user_handle: Option<String>,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

async fn passkey_login_finish_handler(
    State(state): State<AppState>,
    Json(payload): Json<PasskeyLoginFinishFlat>,
) -> Response {
    let (user_id, credential_id, client_data_json, authenticator_data, signature, user_handle) =
        if let Some(data) = payload.data {
            (
                data["user_id"].as_str().map(String::from),
                data["credential_id"].as_str().map(String::from),
                data["client_data_json"].as_str().map(String::from),
                data["authenticator_data"].as_str().map(String::from),
                data["signature"].as_str().map(String::from),
                data["user_handle"].as_str().map(String::from),
            )
        } else {
            (
                payload.user_id,
                payload.credential_id,
                payload.client_data_json,
                payload.authenticator_data,
                payload.signature,
                payload.user_handle,
            )
        };

    let user_id = match user_id {
        Some(u) => u,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing 'user_id' field.",
            )
        }
    };

    let client_data_json = client_data_json.unwrap_or_default();
    let auth_state_opt = match extract_webauthn_challenge(&client_data_json) {
        Some(challenge_id) => state
            .passkey_authentications
            .write()
            .await
            .remove(&challenge_id),
        None => None,
    };

    let auth_state = match auth_state_opt {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "No matching active passkey authentication ceremony found.",
            );
        }
    };

    let auth_state_json = match serde_json::to_string(&auth_state) {
        Ok(j) => j,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to serialize state.",
            )
        }
    };

    let auth_input = AuthInput::WebAuthnAuthentication {
        user_id: user_id.clone(),
        credential_id: credential_id.unwrap_or_default(),
        client_data_json,
        authenticator_data: authenticator_data.unwrap_or_default(),
        signature: signature.unwrap_or_default(),
        user_handle,
        auth_state_json: Some(auth_state_json),
    };

    match state.engine.authenticate(auth_input).await {
        Ok(AuthResult::Success(mut identity)) => {
            identity.attributes.insert(
                IDENTITY_ATTR_AMR.to_string(),
                METHOD_NAME_WEBAUTHN.to_string(),
            );
            identity.attributes.insert(
                IDENTITY_ATTR_STEP_UP_SATISFIED.to_string(),
                "true".to_string(),
            );
            identity.attributes.insert(
                IDENTITY_ATTR_AUTH_TIME.to_string(),
                chrono::Utc::now().timestamp().to_string(),
            );
            let session_id = establish_session(&state, &identity).await;

            let mut resp = json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "success",
                    "identity": identity,
                }),
            );
            set_cookie_header(&mut resp, SESSION_COOKIE_NAME, &session_id, Some(86400));
            resp
        }
        _ => error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "WebAuthn signature verification failed.",
        ),
    }
}

// ---------------------------------------------------------------------------
// 2. Magic Link Handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MagicLinkRequestPayload {
    subject: Option<String>,
    binding: Option<String>,
}

async fn magic_link_request_handler(
    State(state): State<AppState>,
    Json(payload): Json<MagicLinkRequestPayload>,
) -> Response {
    let subject = match payload.subject.filter(|s| !s.trim().is_empty()) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Field 'subject' is required and must not be empty.",
            );
        }
    };

    let binding_mode = payload.binding.as_deref().unwrap_or("same_context");

    let (binding, cookie_nonce) = match binding_mode {
        "any_context" => (MagicLinkBinding::AnyContext, None),
        _ => {
            let mut nonce_bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
            let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
            (MagicLinkBinding::SameContext(nonce.clone()), Some(nonce))
        }
    };

    let ttl = Duration::from_secs(900);
    match state.magic_link_method.mint(&subject, ttl, binding).await {
        Ok(token) => {
            state
                .test_secrets
                .write()
                .await
                .insert(format!("magic-link:{subject}"), token.secret);

            let mut resp = json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "pending",
                    "message": "If an account exists, a sign-in link has been sent to your email.",
                    "expires_at": token.expires_at,
                }),
            );

            if let Some(nonce) = cookie_nonce {
                set_cookie_header(&mut resp, ML_BINDING_COOKIE_NAME, &nonce, Some(900));
            }
            resp
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
struct MagicLinkConsumePayload {
    token: Option<String>,
    binding: Option<String>,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

async fn magic_link_consume_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<MagicLinkConsumePayload>,
) -> Response {
    let token = payload.token.or_else(|| {
        payload
            .data
            .as_ref()
            .and_then(|d| d["token"].as_str().map(String::from))
    });

    let token = match token.filter(|t| !t.trim().is_empty()) {
        Some(t) => t,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing 'token' field.",
            )
        }
    };

    let explicit_binding = payload.binding.or_else(|| {
        payload
            .data
            .as_ref()
            .and_then(|d| d["binding"].as_str().map(String::from))
    });

    let cookie_binding = extract_cookie(&headers, ML_BINDING_COOKIE_NAME).map(String::from);
    let binding = explicit_binding.or(cookie_binding);

    let auth_input = AuthInput::MagicLink { token, binding };

    match state.magic_link_method.authenticate(auth_input).await {
        Ok(mut identity) => {
            identity.attributes.insert(
                IDENTITY_ATTR_AMR.to_string(),
                METHOD_NAME_MAGIC_LINK.to_string(),
            );
            identity.attributes.insert(
                IDENTITY_ATTR_AUTH_TIME.to_string(),
                chrono::Utc::now().timestamp().to_string(),
            );
            let session_id = establish_session(&state, &identity).await;

            let mut resp = json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "success",
                    "identity": identity,
                }),
            );
            clear_cookie_header(&mut resp, ML_BINDING_COOKIE_NAME);
            set_cookie_header(&mut resp, SESSION_COOKIE_NAME, &session_id, Some(86400));
            resp
        }
        _ => error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Invalid or expired magic link.",
        ),
    }
}

// ---------------------------------------------------------------------------
// 3. OTP Handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OtpRequestPayload {
    subject: Option<String>,
    channel: Option<String>,
}

async fn otp_request_handler(
    State(state): State<AppState>,
    Json(payload): Json<OtpRequestPayload>,
) -> Response {
    let subject = match payload.subject.filter(|s| !s.trim().is_empty()) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Fields 'subject' and 'channel' are required.",
            )
        }
    };

    let channel_str = match payload.channel.filter(|c| !c.trim().is_empty()) {
        Some(c) => c,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Fields 'subject' and 'channel' are required.",
            )
        }
    };

    let channel = match channel_str.to_lowercase().as_str() {
        "sms" => OtpChannel::Sms,
        "email" => OtpChannel::Email,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Channel must be 'email' or 'sms'.",
            )
        }
    };

    let ttl = Duration::from_secs(300);
    match state.otp_method.mint(&subject, ttl, channel, 5).await {
        Ok(otp) => {
            state
                .test_secrets
                .write()
                .await
                .insert(format!("otp:{subject}"), otp.code);

            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "pending",
                    "channel": channel_str,
                    "expires_at": otp.expires_at,
                }),
            )
        }
        Err(AuthError::Throttled) => {
            let mut resp = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Resend cooldown active. Please wait before requesting another code.",
            );
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            resp
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
struct OtpVerifyPayload {
    subject: Option<String>,
    code: Option<String>,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

async fn otp_verify_handler(
    State(state): State<AppState>,
    Json(payload): Json<OtpVerifyPayload>,
) -> Response {
    let subject = payload.subject.or_else(|| {
        payload
            .data
            .as_ref()
            .and_then(|d| d["subject"].as_str().map(String::from))
    });

    let code = payload.code.or_else(|| {
        payload
            .data
            .as_ref()
            .and_then(|d| d["code"].as_str().map(String::from))
    });

    let (subject, code) = match (subject, code) {
        (Some(s), Some(c)) if !s.trim().is_empty() && !c.trim().is_empty() => (s, c),
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Fields 'subject' and 'code' are required.",
            )
        }
    };

    let auth_input = AuthInput::Otp { subject, code };

    match state.otp_method.authenticate(auth_input).await {
        Ok(mut identity) => {
            let channel_name = identity
                .attributes
                .get(IDENTITY_ATTR_OTP_CHANNEL)
                .cloned()
                .unwrap_or_else(|| "sms".to_string());
            identity
                .attributes
                .insert(IDENTITY_ATTR_AMR.to_string(), format!("otp {channel_name}"));
            identity.attributes.insert(
                IDENTITY_ATTR_AUTH_TIME.to_string(),
                chrono::Utc::now().timestamp().to_string(),
            );
            let session_id = establish_session(&state, &identity).await;

            let mut resp = json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "success",
                    "identity": identity,
                }),
            );
            set_cookie_header(&mut resp, SESSION_COOKIE_NAME, &session_id, Some(86400));
            resp
        }
        _ => error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Invalid or expired one-time code.",
        ),
    }
}

// ---------------------------------------------------------------------------
// 4. Recovery Codes Handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RecoveryGeneratePayload {
    count: Option<u8>,
}

async fn recovery_generate_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RecoveryGeneratePayload>,
) -> Response {
    let session = match get_authenticated_session(&headers, &state.session_store).await {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::FORBIDDEN,
                "reproof_required",
                "Recent authentication required: no active session found.",
            );
        }
    };

    let count = payload.count.unwrap_or(10);
    if count == 0 || count > 20 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Count must be between 1 and 20.",
        );
    }

    let gate = ReproofRequirement::new(300);
    let identity = session.identity;

    if let Err(e) = gate.check(&identity) {
        return error_response(StatusCode::FORBIDDEN, "reproof_required", &e.to_string());
    }

    match state
        .recovery_method
        .generate(&identity, &gate, count)
        .await
    {
        Ok(codes) => json_response(
            StatusCode::OK,
            serde_json::json!({
                "codes": codes,
                "warning": "Save these recovery codes in a secure location. They will not be displayed again."
            }),
        ),
        Err(AuthError::InvalidInput) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid count requested.",
        ),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
struct RecoveryRedeemPayload {
    user_id: Option<String>,
    code: Option<String>,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

async fn recovery_redeem_handler(
    State(state): State<AppState>,
    Json(payload): Json<RecoveryRedeemPayload>,
) -> Response {
    let user_id = payload.user_id.or_else(|| {
        payload
            .data
            .as_ref()
            .and_then(|d| d["user_id"].as_str().map(String::from))
    });

    let code = payload.code.or_else(|| {
        payload
            .data
            .as_ref()
            .and_then(|d| d["code"].as_str().map(String::from))
    });

    let (user_id, code) = match (user_id, code) {
        (Some(u), Some(c)) if !u.trim().is_empty() && !c.trim().is_empty() => (u, c),
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Fields 'user_id' and 'code' are required.",
            )
        }
    };

    let auth_input = AuthInput::RecoveryCode {
        user_id: user_id.clone(),
        code,
    };

    match state.recovery_method.authenticate(auth_input).await {
        Ok(mut identity) => {
            identity.attributes.insert(
                IDENTITY_ATTR_AMR.to_string(),
                METHOD_NAME_RECOVERY_CODE.to_string(),
            );
            identity.attributes.insert(
                IDENTITY_ATTR_AUTH_TIME.to_string(),
                chrono::Utc::now().timestamp().to_string(),
            );
            let remaining = state
                .credential_store
                .get_credentials(&user_id, METHOD_NAME_RECOVERY_CODE)
                .await
                .map(|v| v.len())
                .unwrap_or(0);

            let session_id = establish_session(&state, &identity).await;

            let mut resp = json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "success",
                    "identity": identity,
                    "remaining_codes": remaining,
                }),
            );
            set_cookie_header(&mut resp, SESSION_COOKIE_NAME, &session_id, Some(86400));
            resp
        }
        _ => error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Invalid or previously redeemed recovery code.",
        ),
    }
}

// ---------------------------------------------------------------------------
// Test-Only Delivery Sink (Never expose out-of-band secrets in prod responses)
// ---------------------------------------------------------------------------

async fn test_outbox_handler(
    State(state): State<AppState>,
    Path((kind, subject)): Path<(String, String)>,
) -> Response {
    if kind != "magic-link" && kind != "otp" {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Unsupported outbox kind.",
        );
    }
    let key = format!("{kind}:{subject}");
    match state.test_secrets.read().await.get(&key).cloned() {
        Some(secret) => json_response(
            StatusCode::OK,
            serde_json::json!({
                "kind": kind,
                "subject": subject,
                "secret": secret,
            }),
        ),
        None => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "No captured secret for subject.",
        ),
    }
}

/// Resolves the engine token signing secret from `AUTHKESTRA_TOKEN_SECRET` / `JWT_SECRET`,
/// falling back to a freshly generated 32-byte random key at startup (CWE-321).
pub fn resolve_token_secret() -> Vec<u8> {
    for var_name in ["AUTHKESTRA_TOKEN_SECRET", "JWT_SECRET"] {
        if let Ok(val) = std::env::var(var_name) {
            let bytes = val.into_bytes();
            if bytes.len() >= 32 {
                return bytes;
            }
        }
    }
    let mut key = vec![0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

// ---------------------------------------------------------------------------
// App Builder
// ---------------------------------------------------------------------------

pub fn build_app(port: u16) -> (Router, AppState) {
    let session_store = Arc::new(MemoryStore::<Session>::new());
    let session_config = SessionConfig {
        cookie_name: SESSION_COOKIE_NAME.to_string(),
        ..Default::default()
    };

    let credential_store = MemoryCredentialStore::new();
    let magic_link_store = MemoryStore::<MagicLinkRecord>::new();
    let otp_store = MemoryStore::<OtpChallenge>::new();

    let origin = Url::parse(&format!("http://localhost:{port}")).expect("valid RP origin");
    let webauthn = Arc::new(
        WebauthnBuilder::new("localhost", &origin)
            .expect("valid WebAuthn builder")
            .rp_name("Authkestra Passwordless Demo")
            .build()
            .expect("valid WebAuthn instance"),
    );

    let webauthn_method = Arc::new(WebAuthnAuthMethod::new(
        webauthn.clone(),
        credential_store.clone(),
    ));
    let magic_link_method = Arc::new(MagicLinkAuthMethod::new(magic_link_store.clone()));
    let otp_method = Arc::new(
        OtpAuthMethod::new(otp_store.clone()).with_resend_cooldown(Duration::from_secs(60)),
    );
    let recovery_method = Arc::new(RecoveryCodeAuthMethod::new(credential_store.clone()));

    let token_secret = resolve_token_secret();
    let token_manager = Arc::new(TokenManager::new(&token_secret, None));

    let engine = Engine::builder()
        .session_store(session_store.clone())
        .session_config(session_config.clone())
        .token_manager(token_manager)
        .with_auth_method(WebAuthnAuthMethod::new(
            webauthn.clone(),
            credential_store.clone(),
        ))
        .with_auth_method(MagicLinkAuthMethod::new(magic_link_store))
        .with_auth_method(
            OtpAuthMethod::new(otp_store).with_resend_cooldown(Duration::from_secs(60)),
        )
        .with_auth_method(RecoveryCodeAuthMethod::new(credential_store.clone()))
        .build();

    let state = AppState {
        engine,
        session_store,
        session_config,
        credential_store,
        webauthn,
        webauthn_method,
        magic_link_method,
        otp_method,
        recovery_method,
        passkey_enrolments: Arc::new(RwLock::new(HashMap::new())),
        passkey_authentications: Arc::new(RwLock::new(HashMap::new())),
        test_secrets: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        // Passkey routes
        .route(
            "/auth/passkey/register/start",
            post(passkey_register_start_handler),
        )
        .route(
            "/auth/passkey/register/finish",
            post(passkey_register_finish_handler),
        )
        .route(
            "/auth/passkey/login/start",
            post(passkey_login_start_handler),
        )
        .route(
            "/auth/passkey/login/finish",
            post(passkey_login_finish_handler),
        )
        // Magic link routes
        .route("/auth/magic-link/request", post(magic_link_request_handler))
        .route("/auth/magic-link/consume", post(magic_link_consume_handler))
        // OTP routes
        .route("/auth/otp/request", post(otp_request_handler))
        .route("/auth/otp/verify", post(otp_verify_handler))
        // Recovery routes
        .route("/auth/recovery/generate", post(recovery_generate_handler))
        .route("/auth/recovery/redeem", post(recovery_redeem_handler))
        // Demo/CI outbox inspection sink (dev/test only; do not mount in production)
        .route("/_test/outbox/{kind}/{subject}", get(test_outbox_handler))
        .with_state(state.clone());

    (app, state)
}

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();

    let args: Vec<String> = std::env::args().collect();
    let serve_flag = args.iter().any(|a| a == "--serve");
    let port_var = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok());

    if serve_flag || port_var.is_some() {
        let port = port_var.unwrap_or(3001);
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .expect("bind listener");
        let local_addr = listener.local_addr().unwrap();
        let (app, _) = build_app(local_addr.port());
        println!("READY: listening on http://127.0.0.1:{}", local_addr.port());
        use std::io::Write;
        let _ = std::io::stdout().flush();
        tracing::info!(
            "Passwordless server listening on http://127.0.0.1:{}",
            local_addr.port()
        );
        axum::serve(listener, app).await.expect("serve app");
    } else {
        println!("Running in-memory automated passwordless self-test...");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("listener local_addr");
        let (app, state) = build_app(addr.port());

        println!("READY: listening on http://{addr}");
        use std::io::Write;
        let _ = std::io::stdout().flush();

        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        run_automated_self_test(addr, state).await;
        println!("All passwordless automated tests passed successfully!");
    }
}

// ---------------------------------------------------------------------------
// Automated End-to-End Self Test
// ---------------------------------------------------------------------------

fn extract_set_cookie(resp: &reqwest::Response, name: &str) -> Option<String> {
    for val in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        if let Ok(cookie_str) = val.to_str() {
            if let Some(cookie) = cookie_str.split(';').next() {
                let mut parts = cookie.splitn(2, '=');
                if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                    if k.trim() == name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

async fn run_automated_self_test(addr: SocketAddr, state: AppState) {
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    println!("\n=== Testing Magic Links ===");
    // 1. Missing subject -> 400 Bad Request
    let bad_req = client
        .post(format!("{base}/auth/magic-link/request"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("req");
    assert_eq!(bad_req.status(), StatusCode::BAD_REQUEST);
    let err_json: serde_json::Value = bad_req.json().await.unwrap();
    assert_eq!(err_json["error"], "invalid_request");

    // 2. Request valid magic link (response must NOT leak out-of-band secret)
    let ml_req = client
        .post(format!("{base}/auth/magic-link/request"))
        .json(&serde_json::json!({
            "subject": "alice@example.com",
            "binding": "same_context"
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(ml_req.status(), StatusCode::OK);
    let ml_binding =
        extract_set_cookie(&ml_req, ML_BINDING_COOKIE_NAME).expect("ml_binding cookie");
    let ml_json: serde_json::Value = ml_req.json().await.unwrap();
    assert_eq!(ml_json["status"], "pending");
    assert!(
        ml_json.get("test_token").is_none(),
        "production /auth/magic-link/request must not leak token secret"
    );

    let outbox_ml: serde_json::Value = client
        .get(format!(
            "{base}/_test/outbox/magic-link/alice%40example.com"
        ))
        .send()
        .await
        .expect("outbox ml")
        .json()
        .await
        .unwrap();
    let test_token = outbox_ml["secret"]
        .as_str()
        .expect("captured secret")
        .to_string();

    // 3. Consume with wrong token -> 401 Unauthorized
    let wrong_consume = client
        .post(format!("{base}/auth/magic-link/consume"))
        .header(
            header::COOKIE,
            format!("{ML_BINDING_COOKIE_NAME}={ml_binding}"),
        )
        .json(&serde_json::json!({ "token": "invalid_wrong_token" }))
        .send()
        .await
        .expect("req");
    assert_eq!(wrong_consume.status(), StatusCode::UNAUTHORIZED);
    let err_json: serde_json::Value = wrong_consume.json().await.unwrap();
    assert_eq!(err_json["error"], "invalid_credentials");

    // 4. Consume valid magic link
    let valid_consume = client
        .post(format!("{base}/auth/magic-link/consume"))
        .header(
            header::COOKIE,
            format!("{ML_BINDING_COOKIE_NAME}={ml_binding}"),
        )
        .json(&serde_json::json!({ "token": test_token }))
        .send()
        .await
        .expect("req");
    assert_eq!(valid_consume.status(), StatusCode::OK);
    let consume_json: serde_json::Value = valid_consume.json().await.unwrap();
    assert_eq!(consume_json["status"], "success");
    assert_eq!(
        consume_json["identity"]["provider_id"],
        METHOD_NAME_MAGIC_LINK
    );
    assert_eq!(consume_json["identity"]["external_id"], "alice@example.com");
    assert_eq!(
        consume_json["identity"]["attributes"]["amr"],
        METHOD_NAME_MAGIC_LINK
    );

    // 5. Consume same magic link again -> single-use failure (401)
    let replay_consume = client
        .post(format!("{base}/auth/magic-link/consume"))
        .header(
            header::COOKIE,
            format!("{ML_BINDING_COOKIE_NAME}={ml_binding}"),
        )
        .json(&serde_json::json!({ "token": test_token }))
        .send()
        .await
        .expect("req");
    assert_eq!(replay_consume.status(), StatusCode::UNAUTHORIZED);

    println!("\n=== Testing OTP ===");
    // 1. Missing fields -> 400 Bad Request
    let bad_otp = client
        .post(format!("{base}/auth/otp/request"))
        .json(&serde_json::json!({ "subject": "+15551234567" }))
        .send()
        .await
        .expect("req");
    assert_eq!(bad_otp.status(), StatusCode::BAD_REQUEST);

    // 2. Request OTP (response must NOT leak out-of-band code)
    let otp_req = client
        .post(format!("{base}/auth/otp/request"))
        .json(&serde_json::json!({
            "subject": "+15551234567",
            "channel": "sms"
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(otp_req.status(), StatusCode::OK);
    let otp_json: serde_json::Value = otp_req.json().await.unwrap();
    assert_eq!(otp_json["status"], "pending");
    assert_eq!(otp_json["channel"], "sms");
    assert!(
        otp_json.get("test_code").is_none(),
        "production /auth/otp/request must not leak OTP code"
    );

    let outbox_otp: serde_json::Value = client
        .get(format!("{base}/_test/outbox/otp/%2B15551234567"))
        .send()
        .await
        .expect("outbox otp")
        .json()
        .await
        .unwrap();
    let test_code = outbox_otp["secret"]
        .as_str()
        .expect("captured code")
        .to_string();

    // 3. Request OTP again immediately -> 429 Too Many Requests (cooldown)
    let rate_limited = client
        .post(format!("{base}/auth/otp/request"))
        .json(&serde_json::json!({
            "subject": "+15551234567",
            "channel": "sms"
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(rate_limited.headers().get(header::RETRY_AFTER).is_some());
    let rate_json: serde_json::Value = rate_limited.json().await.unwrap();
    assert_eq!(rate_json["error"], "rate_limited");

    // 4. Verify wrong OTP code -> 401 Unauthorized
    let wrong_otp_verify = client
        .post(format!("{base}/auth/otp/verify"))
        .json(&serde_json::json!({
            "subject": "+15551234567",
            "code": "000000"
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(wrong_otp_verify.status(), StatusCode::UNAUTHORIZED);

    // 5. Verify valid OTP code -> 200 OK
    let valid_otp_verify = client
        .post(format!("{base}/auth/otp/verify"))
        .json(&serde_json::json!({
            "subject": "+15551234567",
            "code": test_code
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(valid_otp_verify.status(), StatusCode::OK);
    let session_cookie =
        extract_set_cookie(&valid_otp_verify, SESSION_COOKIE_NAME).expect("session cookie");
    let verify_json: serde_json::Value = valid_otp_verify.json().await.unwrap();
    assert_eq!(verify_json["status"], "success");
    assert_eq!(verify_json["identity"]["external_id"], "+15551234567");
    assert_eq!(verify_json["identity"]["attributes"]["otp_channel"], "sms");
    assert_eq!(verify_json["identity"]["attributes"]["amr"], "otp sms");

    // 6. Verify same OTP code again -> 401 Unauthorized (single use)
    let replay_otp = client
        .post(format!("{base}/auth/otp/verify"))
        .json(&serde_json::json!({
            "subject": "+15551234567",
            "code": test_code
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(replay_otp.status(), StatusCode::UNAUTHORIZED);

    println!("\n=== Testing Recovery Codes ===");
    // 1. Generate without session -> 403 reproof_required
    let unauthed_client = reqwest::Client::new();
    let unauthed_gen = unauthed_client
        .post(format!("{base}/auth/recovery/generate"))
        .json(&serde_json::json!({ "count": 10 }))
        .send()
        .await
        .expect("req");
    assert_eq!(unauthed_gen.status(), StatusCode::FORBIDDEN);
    let unauth_json: serde_json::Value = unauthed_gen.json().await.unwrap();
    assert_eq!(unauth_json["error"], "reproof_required");

    // 2. Generate with authenticated session (from OTP verification) but count = 0 -> 400
    let zero_gen = client
        .post(format!("{base}/auth/recovery/generate"))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={session_cookie}"),
        )
        .json(&serde_json::json!({ "count": 0 }))
        .send()
        .await
        .expect("req");
    assert_eq!(zero_gen.status(), StatusCode::BAD_REQUEST);

    // 3. Generate 10 recovery codes
    let valid_gen = client
        .post(format!("{base}/auth/recovery/generate"))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={session_cookie}"),
        )
        .json(&serde_json::json!({ "count": 10 }))
        .send()
        .await
        .expect("req");
    assert_eq!(valid_gen.status(), StatusCode::OK);
    let gen_json: serde_json::Value = valid_gen.json().await.unwrap();
    let codes = gen_json["codes"].as_array().expect("codes array");
    assert_eq!(codes.len(), 10);
    let first_code = codes[0].as_str().unwrap().to_string();

    // 4. Redeem invalid recovery code -> 401
    let bad_redeem = client
        .post(format!("{base}/auth/recovery/redeem"))
        .json(&serde_json::json!({
            "user_id": "+15551234567",
            "code": "ZZZZ-YYYY-XXXX-WWWW"
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(bad_redeem.status(), StatusCode::UNAUTHORIZED);

    // 5. Redeem valid recovery code (testing normalization: lower case and no hyphens)
    let normalized_code = first_code.to_lowercase().replace('-', " ");
    let valid_redeem = client
        .post(format!("{base}/auth/recovery/redeem"))
        .json(&serde_json::json!({
            "user_id": "+15551234567",
            "code": normalized_code
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(valid_redeem.status(), StatusCode::OK);
    let recovery_session_cookie =
        extract_set_cookie(&valid_redeem, SESSION_COOKIE_NAME).expect("recovery session cookie");
    let redeem_json: serde_json::Value = valid_redeem.json().await.unwrap();
    assert_eq!(redeem_json["status"], "success");
    assert_eq!(
        redeem_json["identity"]["provider_id"],
        METHOD_NAME_RECOVERY_CODE
    );
    assert_eq!(
        redeem_json["identity"]["attributes"]["amr"],
        METHOD_NAME_RECOVERY_CODE
    );
    assert_eq!(redeem_json["remaining_codes"], 9);

    // 6. Redeem same code again -> 401 (single use)
    let replay_redeem = client
        .post(format!("{base}/auth/recovery/redeem"))
        .json(&serde_json::json!({
            "user_id": "+15551234567",
            "code": first_code
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(replay_redeem.status(), StatusCode::UNAUTHORIZED);

    println!("\n=== Testing Passkeys ===");
    // 1. Register start without session -> 403 reproof_required
    let unauthed_passkey = unauthed_client
        .post(format!("{base}/auth/passkey/register/start"))
        .json(&serde_json::json!({ "username": "bob@example.com" }))
        .send()
        .await
        .expect("req");
    assert_eq!(unauthed_passkey.status(), StatusCode::FORBIDDEN);

    // 2. Register start with authenticated session -> 200 OK
    let passkey_start = client
        .post(format!("{base}/auth/passkey/register/start"))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={recovery_session_cookie}"),
        )
        .json(&serde_json::json!({
            "username": "+15551234567",
            "display_name": "Bob Demo"
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(passkey_start.status(), StatusCode::OK);
    let pk_start_json: serde_json::Value = passkey_start.json().await.unwrap();
    assert!(pk_start_json["publicKey"]["challenge"].as_str().is_some());

    // 3. Register finish with invalid data -> 400 invalid_request
    let invalid_finish = client
        .post(format!("{base}/auth/passkey/register/finish"))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={recovery_session_cookie}"),
        )
        .json(&serde_json::json!({
            "id": "invalid_id",
            "rawId": "invalid_rawId",
            "type": "public-key",
            "response": {
                "clientDataJSON": "invalid",
                "attestationObject": "invalid"
            }
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(invalid_finish.status(), StatusCode::BAD_REQUEST);
    let inv_err: serde_json::Value = invalid_finish.json().await.unwrap();
    assert_eq!(inv_err["error"], "invalid_request");

    // 4. Passkey login start (two concurrent ceremonies) -> 200 OK
    let login_start_1 = client
        .post(format!("{base}/auth/passkey/login/start"))
        .json(&serde_json::json!({ "username": "+15551234567" }))
        .send()
        .await
        .expect("req");
    assert_eq!(login_start_1.status(), StatusCode::OK);
    let login_start_1_json: serde_json::Value = login_start_1.json().await.unwrap();
    let challenge_1 = login_start_1_json["publicKey"]["challenge"]
        .as_str()
        .expect("challenge 1")
        .to_string();

    let login_start_2 = client
        .post(format!("{base}/auth/passkey/login/start"))
        .json(&serde_json::json!({ "username": "+15551234567" }))
        .send()
        .await
        .expect("req");
    assert_eq!(login_start_2.status(), StatusCode::OK);
    let login_start_2_json: serde_json::Value = login_start_2.json().await.unwrap();
    let challenge_2 = login_start_2_json["publicKey"]["challenge"]
        .as_str()
        .expect("challenge 2")
        .to_string();
    assert_ne!(challenge_1, challenge_2);

    // 5. Passkey login finish targeting challenge_2 must consume challenge_2 only,
    // leaving concurrent challenge_1 intact, and reject invalid signatures with 401.
    let client_data_2 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_2,
            "origin": base,
        })
        .to_string(),
    );
    let login_finish = client
        .post(format!("{base}/auth/passkey/login/finish"))
        .json(&serde_json::json!({
            "user_id": "+15551234567",
            "credential_id": "test_cred_id",
            "client_data_json": client_data_2,
            "authenticator_data": "dGVzdF9hdXRoX2RhdGE",
            "signature": "dGVzdF9zaWduYXR1cmU"
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(login_finish.status(), StatusCode::UNAUTHORIZED);
    {
        let pending = state.passkey_authentications.read().await;
        assert!(
            pending.contains_key(&challenge_1),
            "concurrent passkey ceremony 1 must remain intact when ceremony 2 finishes"
        );
        assert!(
            !pending.contains_key(&challenge_2),
            "targeted passkey ceremony 2 must be consumed"
        );
    }

    // 6. Passkey login finish missing challenge in client_data_json -> 401 invalid_credentials
    let login_finish_missing_chal = client
        .post(format!("{base}/auth/passkey/login/finish"))
        .json(&serde_json::json!({
            "user_id": "+15551234567",
            "credential_id": "test_cred_id",
            "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
            "authenticator_data": "dGVzdF9hdXRoX2RhdGE",
            "signature": "dGVzdF9zaWduYXR1cmU"
        }))
        .send()
        .await
        .expect("req");
    assert_eq!(login_finish_missing_chal.status(), StatusCode::UNAUTHORIZED);
}
