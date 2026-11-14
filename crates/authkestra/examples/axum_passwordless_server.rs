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
//!   single-use guarantees, wire error codes (400, 401, 403, 429, 503), and server-mode file delivery.
//! - `--serve` or `PORT=<port>`: binds as a standing daemon and logs `READY: listening on http://...`.
//!   Server mode never mounts `/_test/outbox/*`; pass `--delivery-file <path>` (or
//!   `AUTHKESTRA_DELIVERY_FILE=<path>`) for owner-only local file delivery, `--local-delivery` (or
//!   `AUTHKESTRA_LOCAL_DELIVERY=1`) for interactive stderr delivery, or wire a custom
//!   [`PasswordlessDelivery`] via [`build_app_with_delivery`].

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use authkestra::core::auth::magic_link::{MagicLinkAuthMethod, MagicLinkBinding, MagicLinkRecord};
use authkestra::core::auth::otp::{OtpAuthMethod, OtpChallenge, OtpChannel};
use authkestra::core::auth::recovery::RecoveryCodeAuthMethod;
use authkestra::core::auth::session::Session;
use authkestra::core::auth::state::{
    IDENTITY_ATTR_AMR, IDENTITY_ATTR_AUTH_TIME, IDENTITY_ATTR_OTP_CHANNEL,
    IDENTITY_ATTR_STEP_UP_SATISFIED, METHOD_NAME_MAGIC_LINK, METHOD_NAME_RECOVERY_CODE,
    METHOD_NAME_WEBAUTHN,
};
use authkestra::core::auth::webauthn::{derive_user_handle, PasskeyEnrolment, WebAuthnAuthMethod};
use authkestra::core::auth::{
    AuthError, AuthInput, AuthMethod, AuthResult, CredentialStore, Identity, ReproofRequirement,
};
use authkestra::core::store::memory::{MemoryCredentialStore, MemoryStore};
use authkestra::core::store::KvStore;
use authkestra::core::{AkEngine, Engine, SessionConfig, TokenManager};
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use url::Url;
use webauthn_rs::prelude::*;

type ExampleResult<T> = Result<T, Box<dyn std::error::Error>>;

const SESSION_COOKIE_NAME: &str = "ak_session";
const ML_BINDING_COOKIE_NAME: &str = "ml_binding";
const PENDING_CEREMONY_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING_CEREMONIES: usize = 1024;

struct ExpiringEntry<V> {
    value: V,
    expires_at: Instant,
}

/// Bounded in-memory ceremony store that evicts expired entries on access and
/// enforces a maximum active entry count.
pub struct ExpiringMap<V> {
    entries: HashMap<String, ExpiringEntry<V>>,
    ttl: Duration,
    max_capacity: usize,
}

impl<V> Default for ExpiringMap<V> {
    fn default() -> Self {
        Self::new(PENDING_CEREMONY_TTL, MAX_PENDING_CEREMONIES)
    }
}

impl<V> ExpiringMap<V> {
    /// Creates a bounded map where each inserted item expires after `ttl`.
    pub fn new(ttl: Duration, max_capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            max_capacity,
        }
    }

    /// Removes all entries whose deadline has elapsed and returns the number removed.
    pub fn purge_expired(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.expires_at > now);
        before.saturating_sub(self.entries.len())
    }

    /// Inserts `value` under `key` after purging expired entries, rejecting new keys
    /// once `max_capacity` is reached.
    pub fn insert(&mut self, key: String, value: V) -> Result<(), &'static str> {
        let now = Instant::now();
        self.purge_expired(now);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_capacity {
            return Err("pending ceremony capacity exceeded");
        }
        self.entries.insert(
            key,
            ExpiringEntry {
                value,
                expires_at: now + self.ttl,
            },
        );
        Ok(())
    }

    /// Removes expired entries, then removes and returns `key` if still active.
    pub fn remove(&mut self, key: &str) -> Option<V> {
        self.purge_expired(Instant::now());
        self.entries.remove(key).map(|entry| entry.value)
    }

    /// Returns `true` when an unexpired entry exists for `key`.
    pub fn contains_key(&self, key: &str) -> bool {
        let now = Instant::now();
        self.entries
            .get(key)
            .is_some_and(|entry| entry.expires_at > now)
    }
}

/// Shared JSON extractor mapping malformed payloads or missing `Content-Type` headers
/// to the standard `400 {"error": "invalid_request", ...}` JSON envelope.
struct ValidatedJson<T>(T);

impl<S, T> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let path = req.uri().path().to_string();
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                let reason = match &rejection {
                    JsonRejection::JsonDataError(_) => "json_data_error",
                    JsonRejection::JsonSyntaxError(_) => "json_syntax_error",
                    JsonRejection::MissingJsonContentType(_) => "missing_json_content_type",
                    JsonRejection::BytesRejection(_) => "bytes_rejection",
                    _ => "json_rejection",
                };
                tracing::warn!(
                    path = %path,
                    reason = reason,
                    "rejected malformed JSON request payload"
                );
                Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    &rejection.body_text(),
                ))
            }
        }
    }
}

/// Out-of-band delivery backend for freshly minted magic-link secrets and OTP codes.
///
/// Implement this trait to integrate a real email/SMS provider via [`build_app_with_delivery`].
/// Standalone local runs can also use [`LocalFileDelivery`] (`AUTHKESTRA_DELIVERY_FILE` /
/// `--delivery-file`) or [`LocalStderrDelivery`] (`AUTHKESTRA_LOCAL_DELIVERY=1` /
/// `--local-delivery`). Never write secrets to HTTP responses or `tracing` logs.
#[async_trait::async_trait]
pub trait PasswordlessDelivery: Send + Sync {
    /// Returns `true` when this backend can deliver challenges out of band.
    fn is_configured(&self) -> bool {
        true
    }

    /// Delivers a freshly minted magic-link token to `subject`.
    async fn deliver_magic_link(
        &self,
        subject: &str,
        token: &str,
        expires_at: i64,
    ) -> Result<(), String>;

    /// Delivers a freshly minted one-time passcode (`code`) to `subject` over `channel`.
    async fn deliver_otp(
        &self,
        subject: &str,
        channel: &str,
        code: &str,
        expires_at: i64,
    ) -> Result<(), String>;
}

/// Appends delivered challenges as newline-delimited JSON objects to an owner-only (`0600`) file.
///
/// Intended for isolated local testing or automation against `--serve` without exposing HTTP
/// outbox endpoints.
pub struct LocalFileDelivery {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl LocalFileDelivery {
    /// Creates a delivery sink that appends challenges as JSON lines to `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write_lock: Mutex::new(()),
        }
    }

    async fn append_record(&self, record: serde_json::Value) -> Result<(), String> {
        let mut line = serde_json::to_string(&record)
            .map_err(|e| format!("failed to serialize delivery record: {e}"))?;
        line.push('\n');

        let _guard = self.write_lock.lock().await;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = file.metadata()?.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "delivery file permissions {mode:#05o} expose group/other bits; require 0600 or stricter"
                        ),
                    ));
                }
            }
            file.write_all(line.as_bytes())?;
            file.flush()?;
            Ok(())
        })
        .await
        .map_err(|e| format!("delivery writer task failed: {e}"))?
        .map_err(|e| format!("failed to write delivery record: {e}"))
    }
}

#[async_trait::async_trait]
impl PasswordlessDelivery for LocalFileDelivery {
    async fn deliver_magic_link(
        &self,
        subject: &str,
        token: &str,
        expires_at: i64,
    ) -> Result<(), String> {
        self.append_record(serde_json::json!({
            "kind": "magic-link",
            "subject": subject,
            "secret": token,
            "expires_at": expires_at,
        }))
        .await
    }

    async fn deliver_otp(
        &self,
        subject: &str,
        channel: &str,
        code: &str,
        expires_at: i64,
    ) -> Result<(), String> {
        self.append_record(serde_json::json!({
            "kind": "otp",
            "subject": subject,
            "channel": channel,
            "secret": code,
            "expires_at": expires_at,
        }))
        .await
    }
}

/// Prints delivered challenges to standard error for explicitly enabled interactive local sessions.
///
/// Activated only via `--local-delivery` or `AUTHKESTRA_LOCAL_DELIVERY=1` so server mode never
/// emits secrets silently when running unattended.
#[derive(Default)]
pub struct LocalStderrDelivery;

#[async_trait::async_trait]
impl PasswordlessDelivery for LocalStderrDelivery {
    async fn deliver_magic_link(
        &self,
        subject: &str,
        token: &str,
        expires_at: i64,
    ) -> Result<(), String> {
        eprintln!(
            "[LOCAL DELIVERY] magic-link subject={subject} token={token} expires_at={expires_at}"
        );
        Ok(())
    }

    async fn deliver_otp(
        &self,
        subject: &str,
        channel: &str,
        code: &str,
        expires_at: i64,
    ) -> Result<(), String> {
        eprintln!(
            "[LOCAL DELIVERY] otp channel={channel} subject={subject} code={code} expires_at={expires_at}"
        );
        Ok(())
    }
}

struct UnconfiguredDelivery;

#[async_trait::async_trait]
impl PasswordlessDelivery for UnconfiguredDelivery {
    fn is_configured(&self) -> bool {
        false
    }

    async fn deliver_magic_link(
        &self,
        _subject: &str,
        _token: &str,
        _expires_at: i64,
    ) -> Result<(), String> {
        Err(
            "No out-of-band delivery backend is configured. Provide a PasswordlessDelivery via build_app_with_delivery, set AUTHKESTRA_DELIVERY_FILE / --delivery-file, or pass --local-delivery.".to_string(),
        )
    }

    async fn deliver_otp(
        &self,
        _subject: &str,
        _channel: &str,
        _code: &str,
        _expires_at: i64,
    ) -> Result<(), String> {
        Err(
            "No out-of-band delivery backend is configured. Provide a PasswordlessDelivery via build_app_with_delivery, set AUTHKESTRA_DELIVERY_FILE / --delivery-file, or pass --local-delivery.".to_string(),
        )
    }
}

#[derive(Clone, Default)]
struct SelfTestOutboxDelivery {
    secrets: Arc<RwLock<HashMap<String, String>>>,
}

#[async_trait::async_trait]
impl PasswordlessDelivery for SelfTestOutboxDelivery {
    async fn deliver_magic_link(
        &self,
        subject: &str,
        token: &str,
        _expires_at: i64,
    ) -> Result<(), String> {
        self.secrets
            .write()
            .await
            .insert(format!("magic-link:{subject}"), token.to_string());
        Ok(())
    }

    async fn deliver_otp(
        &self,
        subject: &str,
        _channel: &str,
        code: &str,
        _expires_at: i64,
    ) -> Result<(), String> {
        self.secrets
            .write()
            .await
            .insert(format!("otp:{subject}"), code.to_string());
        Ok(())
    }
}

/// Shared Axum state for the passwordless authentication reference server.
///
/// All stores (`session_store`, `credential_store`, magic-link/OTP challenge stores, and
/// [`ExpiringMap`] ceremony caches) are ephemeral in-memory implementations sized for a
/// single local instance; state is lost on process restart. WebAuthn relies on the `localhost`
/// Relying Party ID and `http://localhost:{port}` origin supplied to [`build_app`] or
/// [`build_app_with_delivery`].
///
/// Challenge delivery goes through `delivery` ([`PasswordlessDelivery`]). [`build_app`] checks
/// `AUTHKESTRA_DELIVERY_FILE` / `AUTHKESTRA_LOCAL_DELIVERY` and otherwise fails closed with HTTP
/// `503 delivery_unavailable` instead of silently discarding challenges; the `/_test/outbox/*`
/// inspection route is mounted only by the isolated in-process self-test runner.
#[derive(Clone)]
pub struct AppState {
    /// Core Authkestra engine configured with all four passwordless auth methods.
    pub engine: AkEngine,
    /// Ephemeral in-memory session store.
    pub session_store: Arc<MemoryStore<Session>>,
    /// Session cookie configuration.
    pub session_config: SessionConfig,
    /// Ephemeral in-memory credential store for WebAuthn passkeys and recovery codes.
    pub credential_store: MemoryCredentialStore,
    /// Configured WebAuthn Relying Party instance (`rp_id = "localhost"`).
    pub webauthn: Arc<Webauthn>,
    /// WebAuthn authentication method facade bound to `credential_store`.
    pub webauthn_method: Arc<WebAuthnAuthMethod<MemoryCredentialStore>>,
    /// Magic-link authentication method backed by an ephemeral `MemoryStore`.
    pub magic_link_method: Arc<MagicLinkAuthMethod<MemoryStore<MagicLinkRecord>>>,
    /// OTP authentication method backed by an ephemeral `MemoryStore`.
    pub otp_method: Arc<OtpAuthMethod<MemoryStore<OtpChallenge>>>,
    /// Recovery-code authentication method backed by `credential_store`.
    pub recovery_method: Arc<RecoveryCodeAuthMethod<MemoryCredentialStore>>,
    /// Bounded TTL-expiring passkey registration ceremonies keyed by session ID.
    pub passkey_enrolments: Arc<RwLock<ExpiringMap<PasskeyEnrolment>>>,
    /// Bounded TTL-expiring passkey authentication ceremonies keyed by WebAuthn challenge ID.
    pub passkey_authentications: Arc<RwLock<ExpiringMap<PasskeyAuthentication>>>,
    /// Out-of-band delivery backend for minted magic-link secrets and OTP codes.
    pub delivery: Arc<dyn PasswordlessDelivery>,
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

async fn purge_expired_passkey_ceremonies(state: &AppState) {
    let now = Instant::now();
    let expired_enrolments = state.passkey_enrolments.write().await.purge_expired(now);
    let expired_auths = state
        .passkey_authentications
        .write()
        .await
        .purge_expired(now);
    if expired_enrolments > 0 || expired_auths > 0 {
        tracing::debug!(
            expired_enrolments = expired_enrolments,
            expired_authentications = expired_auths,
            "purged expired pending passkey ceremonies"
        );
    }
}

async fn passkey_register_start_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(payload): ValidatedJson<PasskeyRegisterStartRequest>,
) -> Response {
    tracing::debug!("handling passkey registration start request");
    purge_expired_passkey_ceremonies(&state).await;

    let username = match payload.username.filter(|u| !u.trim().is_empty()) {
        Some(u) => u,
        None => {
            tracing::warn!("passkey registration start rejected: missing username");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Field 'username' is required.",
            );
        }
    };

    let session = match get_authenticated_session(&headers, &state.session_store).await {
        Some(s) => s,
        None => {
            tracing::warn!("passkey registration start rejected: no active session");
            return error_response(
                StatusCode::FORBIDDEN,
                "reproof_required",
                "Recent authentication required: no active session found.",
            );
        }
    };

    let gate = ReproofRequirement::new(300);
    let identity = session.identity.clone();

    if username != identity.external_id {
        tracing::warn!(
            subject = %identity.external_id,
            "passkey registration start rejected: username does not match session subject"
        );
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Field 'username' must match the authenticated session subject identifier.",
        );
    }

    if let Err(e) = gate.check(&identity) {
        tracing::warn!(
            subject = %identity.external_id,
            "passkey registration start rejected: reproof requirement failed"
        );
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
            if let Err(msg) = state
                .passkey_enrolments
                .write()
                .await
                .insert(session.id.clone(), enrolment)
            {
                tracing::warn!(
                    subject = %identity.external_id,
                    "passkey registration start rejected: pending enrolment capacity reached"
                );
                return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg);
            }

            tracing::info!(
                subject = %identity.external_id,
                "passkey registration challenge issued"
            );
            json_response(StatusCode::OK, challenge)
        }
        Err(e) => {
            tracing::warn!(
                subject = %identity.external_id,
                error = %e,
                "passkey registration start rejected by WebAuthn method"
            );
            error_response(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string())
        }
    }
}

async fn passkey_register_finish_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(raw_payload): ValidatedJson<serde_json::Value>,
) -> Response {
    tracing::debug!("handling passkey registration finish request");
    purge_expired_passkey_ceremonies(&state).await;

    let session = match get_authenticated_session(&headers, &state.session_store).await {
        Some(s) => s,
        None => {
            tracing::warn!("passkey registration finish rejected: no active session");
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
            tracing::warn!(
                subject = %session.identity.external_id,
                "passkey registration finish rejected: malformed registration credential"
            );
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
            tracing::warn!(
                subject = %session.identity.external_id,
                "passkey registration finish rejected: missing or expired enrolment ceremony"
            );
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
            tracing::info!(
                subject = %session.identity.external_id,
                "passkey registration completed"
            );
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "success",
                    "credential_id": cred_id,
                }),
            )
        }
        Err(e) => {
            tracing::warn!(
                subject = %session.identity.external_id,
                "passkey registration finish rejected: verification failed"
            );
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                &e.to_string(),
            )
        }
    }
}

#[derive(Deserialize)]
struct PasskeyLoginStartRequest {
    username: Option<String>,
}

async fn passkey_login_start_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<PasskeyLoginStartRequest>,
) -> Response {
    tracing::debug!(
        has_username = payload.username.is_some(),
        "handling passkey login start request"
    );
    purge_expired_passkey_ceremonies(&state).await;

    let username = match payload.username.filter(|u| !u.trim().is_empty()) {
        Some(u) => u,
        None => {
            tracing::warn!("passkey login start rejected: missing username");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Field 'username' is required.",
            );
        }
    };

    let passkeys: Vec<Passkey> = match state
        .credential_store
        .get_credentials(&username, METHOD_NAME_WEBAUTHN)
        .await
    {
        Ok(creds) => creds
            .into_iter()
            .filter_map(|c| serde_json::from_value::<Passkey>(c).ok())
            .collect(),
        Err(e) => {
            tracing::warn!(
                subject = %username,
                error = %e,
                "failed to query stored WebAuthn credentials for user"
            );
            vec![]
        }
    };

    match state.webauthn.start_passkey_authentication(&passkeys) {
        Ok((challenge, auth_state)) => {
            let challenge_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(challenge.public_key.challenge.as_ref());
            if let Err(msg) = state
                .passkey_authentications
                .write()
                .await
                .insert(challenge_id, auth_state)
            {
                tracing::warn!(
                    subject = %username,
                    "passkey login start rejected: pending authentication capacity reached"
                );
                return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg);
            }

            tracing::info!(
                subject = %username,
                credential_count = passkeys.len(),
                "passkey login challenge issued"
            );
            json_response(StatusCode::OK, challenge)
        }
        Err(e) => {
            tracing::error!(
                subject = %username,
                error = %e,
                "failed to start passkey authentication"
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &format!("Failed to start passkey assertion: {e}"),
            )
        }
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
    ValidatedJson(payload): ValidatedJson<PasskeyLoginFinishFlat>,
) -> Response {
    tracing::debug!("handling passkey login finish request");
    purge_expired_passkey_ceremonies(&state).await;

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
            tracing::warn!("passkey login finish rejected: missing user_id");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing 'user_id' field.",
            );
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
            tracing::warn!(
                subject = %user_id,
                "passkey login finish rejected: missing or expired authentication ceremony"
            );
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "No matching active passkey authentication ceremony found.",
            );
        }
    };

    let auth_state_json = match serde_json::to_string(&auth_state) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(
                subject = %user_id,
                error = %e,
                "failed to serialize passkey authentication state"
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to serialize state.",
            );
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

            tracing::info!(
                subject = %identity.external_id,
                "passkey authentication succeeded"
            );
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
        _ => {
            tracing::warn!(
                subject = %user_id,
                "passkey login finish rejected: assertion verification failed"
            );
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "WebAuthn signature verification failed.",
            )
        }
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
    ValidatedJson(payload): ValidatedJson<MagicLinkRequestPayload>,
) -> Response {
    tracing::debug!(
        has_subject = payload.subject.is_some(),
        "handling magic-link request"
    );

    let subject = match payload.subject.filter(|s| !s.trim().is_empty()) {
        Some(s) => s,
        None => {
            tracing::warn!("magic-link request rejected: missing subject");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Field 'subject' is required and must not be empty.",
            );
        }
    };

    if !state.delivery.is_configured() {
        tracing::warn!(subject = %subject, "magic-link request rejected: delivery backend unconfigured");
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "delivery_unavailable",
            "No out-of-band delivery backend is configured. Provide PasswordlessDelivery via build_app_with_delivery, set AUTHKESTRA_DELIVERY_FILE / --delivery-file, or pass --local-delivery.",
        );
    }

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
            if let Err(err) = state
                .delivery
                .deliver_magic_link(&subject, &token.secret, token.expires_at)
                .await
            {
                tracing::error!(
                    subject = %subject,
                    error = %err,
                    "magic-link delivery failed"
                );
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "delivery_unavailable",
                    &err,
                );
            }

            tracing::info!(
                subject = %subject,
                binding = binding_mode,
                "magic-link challenge minted and queued for delivery"
            );
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
        Err(e) => {
            tracing::error!(
                subject = %subject,
                error = %e,
                "magic-link minting failed"
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            )
        }
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
    ValidatedJson(payload): ValidatedJson<MagicLinkConsumePayload>,
) -> Response {
    tracing::debug!("handling magic-link consume request");

    let token = payload.token.or_else(|| {
        payload
            .data
            .as_ref()
            .and_then(|d| d["token"].as_str().map(String::from))
    });

    let token = match token.filter(|t| !t.trim().is_empty()) {
        Some(t) => t,
        None => {
            tracing::warn!("magic-link consume rejected: missing token");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing 'token' field.",
            );
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

            tracing::info!(
                subject = %identity.external_id,
                "magic-link authentication succeeded"
            );
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
        _ => {
            tracing::warn!("magic-link consume rejected: invalid or expired token");
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid or expired magic link.",
            )
        }
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
    ValidatedJson(payload): ValidatedJson<OtpRequestPayload>,
) -> Response {
    tracing::debug!(
        has_subject = payload.subject.is_some(),
        has_channel = payload.channel.is_some(),
        "handling OTP request"
    );

    let subject = match payload.subject.filter(|s| !s.trim().is_empty()) {
        Some(s) => s,
        None => {
            tracing::warn!("OTP request rejected: missing subject");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Fields 'subject' and 'channel' are required.",
            );
        }
    };

    let channel_str = match payload.channel.filter(|c| !c.trim().is_empty()) {
        Some(c) => c,
        None => {
            tracing::warn!(subject = %subject, "OTP request rejected: missing channel");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Fields 'subject' and 'channel' are required.",
            );
        }
    };

    let channel = match channel_str.to_lowercase().as_str() {
        "sms" => OtpChannel::Sms,
        "email" => OtpChannel::Email,
        _ => {
            tracing::warn!(
                subject = %subject,
                channel = %channel_str,
                "OTP request rejected: unsupported channel"
            );
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Channel must be 'email' or 'sms'.",
            );
        }
    };

    if !state.delivery.is_configured() {
        tracing::warn!(
            subject = %subject,
            channel = %channel_str,
            "OTP request rejected: delivery backend unconfigured"
        );
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "delivery_unavailable",
            "No out-of-band delivery backend is configured. Provide PasswordlessDelivery via build_app_with_delivery, set AUTHKESTRA_DELIVERY_FILE / --delivery-file, or pass --local-delivery.",
        );
    }

    let ttl = Duration::from_secs(300);
    match state.otp_method.mint(&subject, ttl, channel, 5).await {
        Ok(otp) => {
            if let Err(err) = state
                .delivery
                .deliver_otp(&subject, &channel_str, &otp.code, otp.expires_at)
                .await
            {
                tracing::error!(
                    subject = %subject,
                    channel = %channel_str,
                    error = %err,
                    "OTP delivery failed"
                );
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "delivery_unavailable",
                    &err,
                );
            }

            tracing::info!(
                subject = %subject,
                channel = %channel_str,
                "OTP challenge minted and queued for delivery"
            );
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
            tracing::warn!(
                subject = %subject,
                channel = %channel_str,
                "OTP request throttled during resend cooldown"
            );
            let mut resp = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Resend cooldown active. Please wait before requesting another code.",
            );
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            resp
        }
        Err(e) => {
            tracing::error!(
                subject = %subject,
                channel = %channel_str,
                error = %e,
                "OTP minting failed"
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            )
        }
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
    ValidatedJson(payload): ValidatedJson<OtpVerifyPayload>,
) -> Response {
    tracing::debug!("handling OTP verification request");

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
            tracing::warn!("OTP verify rejected: missing subject or code");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Fields 'subject' and 'code' are required.",
            );
        }
    };

    let subject_for_log = subject.clone();
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

            tracing::info!(
                subject = %identity.external_id,
                channel = %channel_name,
                "OTP authentication succeeded"
            );
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
        _ => {
            tracing::warn!(
                subject = %subject_for_log,
                "OTP verify rejected: invalid or expired code"
            );
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid or expired one-time code.",
            )
        }
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
    ValidatedJson(payload): ValidatedJson<RecoveryGeneratePayload>,
) -> Response {
    tracing::debug!("handling recovery code generation request");

    let session = match get_authenticated_session(&headers, &state.session_store).await {
        Some(s) => s,
        None => {
            tracing::warn!("recovery code generation rejected: no active session");
            return error_response(
                StatusCode::FORBIDDEN,
                "reproof_required",
                "Recent authentication required: no active session found.",
            );
        }
    };

    let count = payload.count.unwrap_or(10);
    if count == 0 || count > 20 {
        tracing::warn!(
            subject = %session.identity.external_id,
            count = count,
            "recovery code generation rejected: count out of bounds"
        );
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Count must be between 1 and 20.",
        );
    }

    let gate = ReproofRequirement::new(300);
    let identity = session.identity;

    if let Err(e) = gate.check(&identity) {
        tracing::warn!(
            subject = %identity.external_id,
            "recovery code generation rejected: reproof requirement failed"
        );
        return error_response(StatusCode::FORBIDDEN, "reproof_required", &e.to_string());
    }

    match state
        .recovery_method
        .generate(&identity, &gate, count)
        .await
    {
        Ok(codes) => {
            tracing::info!(
                subject = %identity.external_id,
                count = count,
                "recovery codes generated"
            );
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "codes": codes,
                    "warning": "Save these recovery codes in a secure location. They will not be displayed again."
                }),
            )
        }
        Err(AuthError::InvalidInput) => {
            tracing::warn!(
                subject = %identity.external_id,
                "recovery code generation rejected: invalid input"
            );
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid count requested.",
            )
        }
        Err(e) => {
            tracing::error!(
                subject = %identity.external_id,
                error = %e,
                "recovery code generation failed"
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            )
        }
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
    ValidatedJson(payload): ValidatedJson<RecoveryRedeemPayload>,
) -> Response {
    tracing::debug!("handling recovery code redeem request");

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
            tracing::warn!("recovery code redeem rejected: missing user_id or code");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Fields 'user_id' and 'code' are required.",
            );
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

            tracing::info!(
                subject = %identity.external_id,
                remaining_codes = remaining,
                "recovery code authentication succeeded"
            );
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
        _ => {
            tracing::warn!(
                subject = %user_id,
                "recovery code redeem rejected: invalid or previously redeemed code"
            );
            error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid or previously redeemed recovery code.",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Test-Only Delivery Sink (Mounted only in isolated self-test mode)
// ---------------------------------------------------------------------------

async fn test_outbox_handler(
    State(outbox): State<SelfTestOutboxDelivery>,
    Path((kind, subject)): Path<(String, String)>,
) -> Response {
    if kind != "magic-link" && kind != "otp" {
        tracing::warn!(kind = %kind, "test outbox rejected unsupported kind");
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Unsupported outbox kind.",
        );
    }
    let key = format!("{kind}:{subject}");
    match outbox.secrets.read().await.get(&key).cloned() {
        Some(secret) => {
            tracing::debug!(kind = %kind, subject = %subject, "serving test outbox entry");
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "kind": kind,
                    "subject": subject,
                    "secret": secret,
                }),
            )
        }
        None => {
            tracing::debug!(kind = %kind, subject = %subject, "no captured test outbox entry found");
            error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "No captured secret for subject.",
            )
        }
    }
}

/// Resolves the engine token signing secret from `AUTHKESTRA_TOKEN_SECRET` / `JWT_SECRET`,
/// falling back to a freshly generated 32-byte random key at startup (CWE-321).
pub fn resolve_token_secret() -> Vec<u8> {
    for var_name in ["AUTHKESTRA_TOKEN_SECRET", "JWT_SECRET"] {
        if let Ok(val) = std::env::var(var_name) {
            let bytes = val.into_bytes();
            if bytes.len() >= 32 {
                tracing::debug!(
                    source = var_name,
                    "resolved token signing secret from environment"
                );
                return bytes;
            }
            tracing::warn!(
                source = var_name,
                "ignoring token secret environment variable shorter than 32 bytes"
            );
        }
    }
    tracing::warn!(
        "AUTHKESTRA_TOKEN_SECRET and JWT_SECRET unset or invalid; generating ephemeral CSPRNG secret"
    );
    let mut key = vec![0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn resolve_delivery_from_env() -> Arc<dyn PasswordlessDelivery> {
    if let Ok(path) = std::env::var("AUTHKESTRA_DELIVERY_FILE") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Arc::new(LocalFileDelivery::new(trimmed));
        }
    }
    if std::env::var("AUTHKESTRA_LOCAL_DELIVERY")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    {
        return Arc::new(LocalStderrDelivery);
    }
    Arc::new(UnconfiguredDelivery)
}

fn parse_cli_delivery(args: &[String]) -> ExampleResult<Arc<dyn PasswordlessDelivery>> {
    let mut idx = 1;
    while idx < args.len() {
        let arg = &args[idx];
        if arg == "--delivery-file" {
            let path = args
                .get(idx + 1)
                .ok_or("--delivery-file requires a path argument")?;
            return Ok(Arc::new(LocalFileDelivery::new(path)));
        }
        if let Some(path) = arg.strip_prefix("--delivery-file=") {
            if path.trim().is_empty() {
                return Err("--delivery-file= requires a non-empty path".into());
            }
            return Ok(Arc::new(LocalFileDelivery::new(path)));
        }
        if arg == "--local-delivery" {
            return Ok(Arc::new(LocalStderrDelivery));
        }
        idx += 1;
    }
    Ok(resolve_delivery_from_env())
}

// ---------------------------------------------------------------------------
// App Builder
// ---------------------------------------------------------------------------

/// Builds the reference passwordless Axum [`Router`] and its owned [`AppState`] using
/// environment-configured challenge delivery.
///
/// Delivery backend precedence:
/// 1. `AUTHKESTRA_DELIVERY_FILE=<path>` -> [`LocalFileDelivery`] (`0600` NDJSON file).
/// 2. `AUTHKESTRA_LOCAL_DELIVERY=1` -> [`LocalStderrDelivery`] (interactive dev stderr).
/// 3. Otherwise -> fail-closed `503 delivery_unavailable` until [`build_app_with_delivery`] or
///    local delivery is configured.
///
/// Constraints and defaults:
/// - All backing stores are ephemeral in-memory stores that do not persist across restarts.
/// - WebAuthn binds to RP ID `"localhost"` with origin `http://localhost:{port}`.
/// - Callers own the returned [`AppState`] alongside the [`Router`] (for inspection/testing
///   only via public handles).
/// - `/_test/outbox/*` is never mounted by [`build_app`] or `--serve`.
pub fn build_app(port: u16) -> ExampleResult<(Router, AppState)> {
    build_app_with_delivery(port, resolve_delivery_from_env())
}

/// Builds the reference passwordless Axum [`Router`] and its owned [`AppState`] with a custom
/// [`PasswordlessDelivery`] backend.
///
/// `/_test/outbox/*` is never mounted here; callers handle out-of-band magic-link and OTP
/// challenge delivery exclusively through `delivery`.
pub fn build_app_with_delivery(
    port: u16,
    delivery: Arc<dyn PasswordlessDelivery>,
) -> ExampleResult<(Router, AppState)> {
    let session_store = Arc::new(MemoryStore::<Session>::new());
    let session_config = SessionConfig {
        cookie_name: SESSION_COOKIE_NAME.to_string(),
        ..Default::default()
    };

    let credential_store = MemoryCredentialStore::new();
    let magic_link_store = MemoryStore::<MagicLinkRecord>::new();
    let otp_store = MemoryStore::<OtpChallenge>::new();

    let origin = Url::parse(&format!("http://localhost:{port}"))?;
    let webauthn = Arc::new(
        WebauthnBuilder::new("localhost", &origin)?
            .rp_name("Authkestra Passwordless Demo")
            .build()?,
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
        passkey_enrolments: Arc::new(RwLock::new(ExpiringMap::default())),
        passkey_authentications: Arc::new(RwLock::new(ExpiringMap::default())),
        delivery,
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
        .route("/auth/recovery/redeem", post(recovery_redeem_handler));

    Ok((app.with_state(state.clone()), state))
}

fn build_app_with_outbox(port: u16) -> ExampleResult<(Router, AppState)> {
    let outbox = SelfTestOutboxDelivery::default();
    let (router, state) = build_app_with_delivery(port, Arc::new(outbox.clone()))?;
    // Self-test-only delivery inspection sink (never mounted in build_app / --serve).
    let router = router.merge(
        Router::new()
            .route("/_test/outbox/{kind}/{subject}", get(test_outbox_handler))
            .with_state(outbox),
    );
    Ok((router, state))
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let args: Vec<String> = std::env::args().collect();
    let serve_flag = args.iter().any(|a| a == "--serve");
    let port_var = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok());

    if serve_flag || port_var.is_some() {
        let port = port_var.unwrap_or(3001);
        let delivery = parse_cli_delivery(&args)?;
        if !delivery.is_configured() {
            tracing::warn!(
                "No passwordless delivery backend configured; magic-link and OTP requests will return 503 delivery_unavailable until --delivery-file <path>, AUTHKESTRA_DELIVERY_FILE, --local-delivery, or AUTHKESTRA_LOCAL_DELIVERY=1 is set."
            );
        }
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
        let local_addr = listener.local_addr()?;
        let (app, _) = build_app_with_delivery(local_addr.port(), delivery)?;
        println!("READY: listening on http://127.0.0.1:{}", local_addr.port());
        let _ = std::io::stdout().flush();
        tracing::info!(
            "Passwordless server listening on http://127.0.0.1:{}",
            local_addr.port()
        );
        axum::serve(listener, app).await?;
    } else {
        println!("Running in-memory automated passwordless self-test...");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let (app, state) = build_app_with_outbox(addr.port())?;

        println!("READY: listening on http://{addr}");
        let _ = std::io::stdout().flush();

        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                tracing::error!(error = %err, "in-process passwordless test server stopped with error");
            }
        });

        run_automated_self_test(addr, state).await?;
        println!("All passwordless automated tests passed successfully!");
    }

    Ok(())
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

async fn run_automated_self_test(addr: SocketAddr, state: AppState) -> ExampleResult<()> {
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    println!("\n=== Testing Magic Links ===");
    // 0. Malformed JSON -> 400 invalid_request envelope (ValidatedJson rejection)
    let malformed_res = client
        .post(format!("{base}/auth/magic-link/request"))
        .header(header::CONTENT_TYPE, "application/json")
        .body("{not-valid-json")
        .send()
        .await?;
    assert_eq!(malformed_res.status(), StatusCode::BAD_REQUEST);
    let malformed_json: serde_json::Value = malformed_res.json().await?;
    assert_eq!(malformed_json["error"], "invalid_request");

    // 1. Missing subject -> 400 Bad Request
    let bad_req = client
        .post(format!("{base}/auth/magic-link/request"))
        .json(&serde_json::json!({}))
        .send()
        .await?;
    assert_eq!(bad_req.status(), StatusCode::BAD_REQUEST);
    let err_json: serde_json::Value = bad_req.json().await?;
    assert_eq!(err_json["error"], "invalid_request");

    // 2. Request valid magic link (response must NOT leak out-of-band secret)
    let ml_req = client
        .post(format!("{base}/auth/magic-link/request"))
        .json(&serde_json::json!({
            "subject": "alice@example.com",
            "binding": "same_context"
        }))
        .send()
        .await?;
    assert_eq!(ml_req.status(), StatusCode::OK);
    let ml_binding =
        extract_set_cookie(&ml_req, ML_BINDING_COOKIE_NAME).ok_or("missing ml_binding cookie")?;
    let ml_json: serde_json::Value = ml_req.json().await?;
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
        .await?
        .json()
        .await?;
    let test_token = outbox_ml["secret"]
        .as_str()
        .ok_or("missing captured magic-link secret")?
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
        .await?;
    assert_eq!(wrong_consume.status(), StatusCode::UNAUTHORIZED);
    let err_json: serde_json::Value = wrong_consume.json().await?;
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
        .await?;
    assert_eq!(valid_consume.status(), StatusCode::OK);
    let consume_json: serde_json::Value = valid_consume.json().await?;
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
        .await?;
    assert_eq!(replay_consume.status(), StatusCode::UNAUTHORIZED);

    println!("\n=== Testing OTP ===");
    // 1. Missing fields -> 400 Bad Request
    let bad_otp = client
        .post(format!("{base}/auth/otp/request"))
        .json(&serde_json::json!({ "subject": "+15551234567" }))
        .send()
        .await?;
    assert_eq!(bad_otp.status(), StatusCode::BAD_REQUEST);

    // 2. Request OTP (response must NOT leak out-of-band code)
    let otp_req = client
        .post(format!("{base}/auth/otp/request"))
        .json(&serde_json::json!({
            "subject": "+15551234567",
            "channel": "sms"
        }))
        .send()
        .await?;
    assert_eq!(otp_req.status(), StatusCode::OK);
    let otp_json: serde_json::Value = otp_req.json().await?;
    assert_eq!(otp_json["status"], "pending");
    assert_eq!(otp_json["channel"], "sms");
    assert!(
        otp_json.get("test_code").is_none(),
        "production /auth/otp/request must not leak OTP code"
    );

    let outbox_otp: serde_json::Value = client
        .get(format!("{base}/_test/outbox/otp/%2B15551234567"))
        .send()
        .await?
        .json()
        .await?;
    let test_code = outbox_otp["secret"]
        .as_str()
        .ok_or("missing captured OTP code")?
        .to_string();

    // 3. Request OTP again immediately -> 429 Too Many Requests (cooldown)
    let rate_limited = client
        .post(format!("{base}/auth/otp/request"))
        .json(&serde_json::json!({
            "subject": "+15551234567",
            "channel": "sms"
        }))
        .send()
        .await?;
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(rate_limited.headers().get(header::RETRY_AFTER).is_some());
    let rate_json: serde_json::Value = rate_limited.json().await?;
    assert_eq!(rate_json["error"], "rate_limited");

    // 4. Verify wrong OTP code -> 401 Unauthorized
    let wrong_otp_verify = client
        .post(format!("{base}/auth/otp/verify"))
        .json(&serde_json::json!({
            "subject": "+15551234567",
            "code": "000000"
        }))
        .send()
        .await?;
    assert_eq!(wrong_otp_verify.status(), StatusCode::UNAUTHORIZED);

    // 5. Verify valid OTP code -> 200 OK
    let valid_otp_verify = client
        .post(format!("{base}/auth/otp/verify"))
        .json(&serde_json::json!({
            "subject": "+15551234567",
            "code": test_code
        }))
        .send()
        .await?;
    assert_eq!(valid_otp_verify.status(), StatusCode::OK);
    let session_cookie = extract_set_cookie(&valid_otp_verify, SESSION_COOKIE_NAME)
        .ok_or("missing session cookie")?;
    let verify_json: serde_json::Value = valid_otp_verify.json().await?;
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
        .await?;
    assert_eq!(replay_otp.status(), StatusCode::UNAUTHORIZED);

    println!("\n=== Testing Recovery Codes ===");
    // 1. Generate without session -> 403 reproof_required
    let unauthed_client = reqwest::Client::new();
    let unauthed_gen = unauthed_client
        .post(format!("{base}/auth/recovery/generate"))
        .json(&serde_json::json!({ "count": 10 }))
        .send()
        .await?;
    assert_eq!(unauthed_gen.status(), StatusCode::FORBIDDEN);
    let unauth_json: serde_json::Value = unauthed_gen.json().await?;
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
        .await?;
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
        .await?;
    assert_eq!(valid_gen.status(), StatusCode::OK);
    let gen_json: serde_json::Value = valid_gen.json().await?;
    let codes = gen_json["codes"].as_array().ok_or("missing codes array")?;
    assert_eq!(codes.len(), 10);
    let first_code = codes[0]
        .as_str()
        .ok_or("recovery code must be a string")?
        .to_string();

    // 4. Redeem invalid recovery code -> 401
    let bad_redeem = client
        .post(format!("{base}/auth/recovery/redeem"))
        .json(&serde_json::json!({
            "user_id": "+15551234567",
            "code": "ZZZZ-YYYY-XXXX-WWWW"
        }))
        .send()
        .await?;
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
        .await?;
    assert_eq!(valid_redeem.status(), StatusCode::OK);
    let recovery_session_cookie = extract_set_cookie(&valid_redeem, SESSION_COOKIE_NAME)
        .ok_or("missing recovery session cookie")?;
    let redeem_json: serde_json::Value = valid_redeem.json().await?;
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
        .await?;
    assert_eq!(replay_redeem.status(), StatusCode::UNAUTHORIZED);

    println!("\n=== Testing Passkeys ===");
    // 1. Register start without session -> 403 reproof_required
    let unauthed_passkey = unauthed_client
        .post(format!("{base}/auth/passkey/register/start"))
        .json(&serde_json::json!({ "username": "bob@example.com" }))
        .send()
        .await?;
    assert_eq!(unauthed_passkey.status(), StatusCode::FORBIDDEN);

    // 1b. Register start with username != session subject -> 400 invalid_request
    let mismatched_passkey = client
        .post(format!("{base}/auth/passkey/register/start"))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={recovery_session_cookie}"),
        )
        .json(&serde_json::json!({ "username": "different-subject@example.com" }))
        .send()
        .await?;
    assert_eq!(mismatched_passkey.status(), StatusCode::BAD_REQUEST);
    let mismatched_json: serde_json::Value = mismatched_passkey.json().await?;
    assert_eq!(mismatched_json["error"], "invalid_request");

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
        .await?;
    assert_eq!(passkey_start.status(), StatusCode::OK);
    let pk_start_json: serde_json::Value = passkey_start.json().await?;
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
        .await?;
    assert_eq!(invalid_finish.status(), StatusCode::BAD_REQUEST);
    let inv_err: serde_json::Value = invalid_finish.json().await?;
    assert_eq!(inv_err["error"], "invalid_request");

    // 3b. Passkey login start without username -> 400 invalid_request
    let missing_username_login = client
        .post(format!("{base}/auth/passkey/login/start"))
        .json(&serde_json::json!({}))
        .send()
        .await?;
    assert_eq!(missing_username_login.status(), StatusCode::BAD_REQUEST);
    let missing_user_json: serde_json::Value = missing_username_login.json().await?;
    assert_eq!(missing_user_json["error"], "invalid_request");

    // 4. Passkey login start (two concurrent ceremonies) -> 200 OK
    let login_start_1 = client
        .post(format!("{base}/auth/passkey/login/start"))
        .json(&serde_json::json!({ "username": "+15551234567" }))
        .send()
        .await?;
    assert_eq!(login_start_1.status(), StatusCode::OK);
    let login_start_1_json: serde_json::Value = login_start_1.json().await?;
    let challenge_1 = login_start_1_json["publicKey"]["challenge"]
        .as_str()
        .ok_or("missing challenge 1")?
        .to_string();

    let login_start_2 = client
        .post(format!("{base}/auth/passkey/login/start"))
        .json(&serde_json::json!({ "username": "+15551234567" }))
        .send()
        .await?;
    assert_eq!(login_start_2.status(), StatusCode::OK);
    let login_start_2_json: serde_json::Value = login_start_2.json().await?;
    let challenge_2 = login_start_2_json["publicKey"]["challenge"]
        .as_str()
        .ok_or("missing challenge 2")?
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
        .await?;
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
        .await?;
    assert_eq!(login_finish_missing_chal.status(), StatusCode::UNAUTHORIZED);

    // 7. ExpiringMap enforces both capacity limit and deterministic TTL expiry cleanup
    let mut bounded = ExpiringMap::new(Duration::from_secs(300), 2);
    assert!(bounded.insert("k1".to_string(), 1).is_ok());
    assert!(bounded.insert("k2".to_string(), 2).is_ok());
    assert!(bounded.insert("k3".to_string(), 3).is_err());
    let evicted = bounded.purge_expired(Instant::now() + Duration::from_secs(301));
    assert_eq!(evicted, 2);
    assert!(bounded.remove("k1").is_none());
    assert!(bounded.insert("k3".to_string(), 3).is_ok());

    // 8. Server-mode delivery isolation:
    //    - Unconfigured server fails closed with 503 delivery_unavailable and does not expose /_test/outbox
    //    - LocalFileDelivery writes OTP delivery records locally and completes auth end-to-end
    {
        let unconf_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let unconf_addr = unconf_listener.local_addr()?;
        let (unconf_app, _) =
            build_app_with_delivery(unconf_addr.port(), Arc::new(UnconfiguredDelivery))?;
        let unconf_handle = tokio::spawn(async move {
            let _ = axum::serve(unconf_listener, unconf_app).await;
        });
        let unconf_base = format!("http://{unconf_addr}");

        let outbox_probe = client
            .get(format!("{unconf_base}/_test/outbox/otp/user1"))
            .send()
            .await?;
        assert_eq!(outbox_probe.status(), StatusCode::NOT_FOUND);

        let unconf_otp = client
            .post(format!("{unconf_base}/auth/otp/request"))
            .json(&serde_json::json!({
                "subject": "unconfigured@example.com",
                "channel": "email"
            }))
            .send()
            .await?;
        assert_eq!(unconf_otp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let unconf_err: serde_json::Value = unconf_otp.json().await?;
        assert_eq!(unconf_err["error"], "delivery_unavailable");
        unconf_handle.abort();
    }

    {
        let delivery_path = std::env::temp_dir().join(format!(
            "authkestra-passwordless-delivery-{}.ndjson",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&delivery_path);

        let srv_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let srv_addr = srv_listener.local_addr()?;
        let (srv_app, _) = build_app_with_delivery(
            srv_addr.port(),
            Arc::new(LocalFileDelivery::new(&delivery_path)),
        )?;
        let srv_handle = tokio::spawn(async move {
            let _ = axum::serve(srv_listener, srv_app).await;
        });
        let srv_base = format!("http://{srv_addr}");

        let outbox_probe = client
            .get(format!("{srv_base}/_test/outbox/otp/user1"))
            .send()
            .await?;
        assert_eq!(outbox_probe.status(), StatusCode::NOT_FOUND);

        let otp_req = client
            .post(format!("{srv_base}/auth/otp/request"))
            .json(&serde_json::json!({
                "subject": "+15550001111",
                "channel": "sms"
            }))
            .send()
            .await?;
        assert_eq!(otp_req.status(), StatusCode::OK);

        let contents = std::fs::read_to_string(&delivery_path)?;
        let _ = std::fs::remove_file(&delivery_path);
        let record: serde_json::Value = serde_json::from_str(
            contents
                .lines()
                .last()
                .ok_or("expected delivered OTP record in delivery file")?,
        )?;
        assert_eq!(record["kind"], "otp");
        assert_eq!(record["subject"], "+15550001111");
        assert_eq!(record["channel"], "sms");
        let code = record["secret"]
            .as_str()
            .ok_or("missing delivered OTP secret")?;

        let otp_verify = client
            .post(format!("{srv_base}/auth/otp/verify"))
            .json(&serde_json::json!({
                "subject": "+15550001111",
                "code": code
            }))
            .send()
            .await?;
        assert_eq!(otp_verify.status(), StatusCode::OK);
        assert!(otp_verify.headers().get(header::SET_COOKIE).is_some());
        srv_handle.abort();
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissive_path = std::env::temp_dir().join(format!(
            "authkestra-passwordless-permissive-{}.ndjson",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&permissive_path);
        std::fs::File::create(&permissive_path)?;
        std::fs::set_permissions(&permissive_path, std::fs::Permissions::from_mode(0o644))?;

        let delivery = LocalFileDelivery::new(&permissive_path);
        let err = delivery
            .deliver_otp("permissive@example.com", "email", "654321", 1_900_000_000)
            .await
            .expect_err("0644 delivery file must be rejected before writing secret");
        assert!(
            err.contains("Permission denied") || err.contains("group/other"),
            "unexpected error: {err}"
        );
        let remaining = std::fs::read_to_string(&permissive_path)?;
        let _ = std::fs::remove_file(&permissive_path);
        assert!(
            remaining.is_empty(),
            "no secret must be written to a permissive delivery file"
        );
    }

    Ok(())
}
