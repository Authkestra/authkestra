//! Axum integration for `authkestra-devsig`: a `tower::Layer` that verifies device-signed
//! requests ahead of axum's own extraction, plus a thin extractor that reads the result back
//! out.
//!
//! ## Why a `tower::Layer` and not an `authkestra-engine` trait
//!
//! `authkestra-engine` has two extension points today, and — as of this writing — neither can
//! express what this verifier needs:
//!
//! - `AuthMethod` (`auth/mod.rs`) is roadmapped but used only in `tests.rs`; its `AuthInput` is
//!   `Password | OAuthCode | Token | Custom(json)` and carries no HTTP request context at all —
//!   not even a header map, let alone a body.
//! - `AuthenticationStrategy<I>` (`auth/strategy.rs`) is what `Guard<I>`/`JwtStrategy` actually
//!   chain, but its `authenticate(&self, parts: &http::request::Parts)` only ever sees `Parts` —
//!   no body. Every existing axum extractor in this crate implements `FromRequestParts`, not
//!   `FromRequest`, for the same reason: none of them read a body today.
//!
//! Device-signature verification needs the raw body bytes for the `bdh` check (spec: the
//! signature's `bdh` claim must match the SHA-256 of the actual request body). So this would be
//! the framework's first body-aware auth extractor, regardless of which trait it targets —
//! which is precisely the architecture question raised in
//! [authkestra#137](https://github.com/marcjazz/authkestra/issues/137) and deliberately left to
//! the maintainer rather than resolved here.
//!
//! This module does not implement `AuthenticationStrategy<I>`. A real implementation of that
//! trait for this verifier would have exactly one option today: silently skip the `bdh` check
//! whenever a body is present, because the trait cannot see it. Shipping that would mean a
//! caller configuring this "authentication method" gets a verifier that quietly stops enforcing
//! body-binding on write requests — the one case (a POST that moves money) where it matters
//! most. That is not a reasonable default to ship silently, so instead:
//!
//! - [`DeviceSignatureLayer`] is a plain `tower::Layer` that runs *before* axum's extraction,
//!   buffers the body (with an explicit, enforced size cap), calls `authkestra_devsig::verify`
//!   with the full request — including the body — and stashes the resulting
//!   `authkestra_devsig::DeviceIdentity` in request extensions on success, or short-circuits
//!   with a `401`/`413` response on failure — in device-signature profile v1's shape (a JSON
//!   body `{"error": "<code>"}` and, for a `401`, a `WWW-Authenticate: DeviceSignature`
//!   challenge; see [`refusal_response`]).
//! - [`AuthDeviceSignature`] implements `FromRequestParts` (this module, only compiled when the
//!   `devsig` feature is enabled), reading the value the layer already placed in extensions.
//!   This is intentionally *not* where any verification happens — by the time an extractor
//!   runs, the layer has already decided. It wraps `authkestra_devsig::DeviceIdentity` in a
//!   local newtype because `FromRequestParts` (axum) and `DeviceIdentity` (`authkestra-devsig`)
//!   are both foreign to this crate — Rust's orphan rules require the impl to live on a type
//!   this crate owns.
//!
//! Migrating to `AuthenticationStrategy<I>` (if it grows body access), `AuthMethod` (if it grows
//! request context), or a new body-aware trait is then a matter of writing a new, thin adapter
//! that builds an `authkestra_devsig::SignedRequest` from whatever the trait provides and calls
//! `authkestra_devsig::verify` — the algorithm does not know or care which caller invoked it, so
//! none of the code in this module needs to change for that migration to happen elsewhere.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use authkestra_devsig::{
    verify, DeviceIdentity, IssuerJwks, Refusal, ReplayStore, SignedRequest, VerifierConfig,
    VerifyError, REFUSAL_CONTENT_TYPE,
};
use axum::body::Body;
use axum::extract::{FromRequestParts, Request};
use axum::http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use tower_layer::Layer;
use tower_service::Service;

/// Default cap on the buffered request body. Buffering is a memory-amplification vector (the
/// layer must hold the whole body before it can compute `bdh`), so this is deliberately
/// conservative; override with [`DeviceSignatureLayer::max_body_size`] for endpoints that
/// legitimately need more.
pub const DEFAULT_MAX_BODY_SIZE: usize = 1024 * 1024; // 1 MiB

#[derive(Clone)]
struct Shared {
    config: VerifierConfig,
    jwks: Arc<IssuerJwks>,
    replay_store: Arc<dyn ReplayStore>,
    max_body_size: usize,
    signature_header: HeaderName,
    attestation_header: HeaderName,
}

/// A `tower::Layer` that verifies `X-Signature` + `X-Attestation` (header names configurable)
/// against a `VerifierConfig`, an `IssuerJwks` cache, and a `ReplayStore`, injecting a verified
/// `DeviceIdentity` into the request's extensions ahead of axum's own extraction.
///
/// On rejection, short-circuits with a `401 Unauthorized` (or `413 Payload Too Large` if the
/// body exceeds [`DeviceSignatureLayer::max_body_size`]) and never calls the inner service.
#[derive(Clone)]
#[non_exhaustive]
pub struct DeviceSignatureLayer {
    shared: Arc<Shared>,
}

impl DeviceSignatureLayer {
    /// Builds a layer with the default header names (`X-Signature`, `X-Attestation`) and default
    /// body size cap ([`DEFAULT_MAX_BODY_SIZE`]).
    #[tracing::instrument(skip_all)]
    pub fn new(
        config: VerifierConfig,
        jwks: Arc<IssuerJwks>,
        replay_store: Arc<dyn ReplayStore>,
    ) -> Self {
        tracing::debug!(target: "authkestra_devsig", "constructing axum DeviceSignatureLayer");
        Self {
            shared: Arc::new(Shared {
                config,
                jwks,
                replay_store,
                max_body_size: DEFAULT_MAX_BODY_SIZE,
                signature_header: HeaderName::from_static("x-signature"),
                attestation_header: HeaderName::from_static("x-attestation"),
            }),
        }
    }

    /// Overrides the maximum buffered body size. Requests whose body exceeds this are rejected
    /// with `413 Payload Too Large` before verification runs.
    pub fn max_body_size(mut self, bytes: usize) -> Self {
        Arc::make_mut(&mut self.shared).max_body_size = bytes;
        self
    }

    /// Overrides the header name carrying the request signature. Defaults to `X-Signature`.
    pub fn signature_header(mut self, name: HeaderName) -> Self {
        Arc::make_mut(&mut self.shared).signature_header = name;
        self
    }

    /// Overrides the header name carrying the attestation. Defaults to `X-Attestation`.
    pub fn attestation_header(mut self, name: HeaderName) -> Self {
        Arc::make_mut(&mut self.shared).attestation_header = name;
        self
    }
}

impl From<authkestra_devsig::DevSig<Arc<dyn ReplayStore>>> for DeviceSignatureLayer {
    fn from(devsig: authkestra_devsig::DevSig<Arc<dyn ReplayStore>>) -> Self {
        Self::new(devsig.config, devsig.jwks, devsig.replay_store)
    }
}

impl<S> Layer<S> for DeviceSignatureLayer {
    type Service = DeviceSignatureService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DeviceSignatureService {
            inner,
            shared: self.shared.clone(),
        }
    }
}

/// The `tower::Service` produced by [`DeviceSignatureLayer`]. Not constructed directly.
#[derive(Clone)]
#[non_exhaustive]
pub struct DeviceSignatureService<S> {
    inner: S,
    shared: Arc<Shared>,
}

impl<S> Service<Request<Body>> for DeviceSignatureService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Standard tower middleware pattern: hand the in-flight call the service that was
        // already polled ready, keep a freshly-cloned one for next time.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let shared = self.shared.clone();

        Box::pin(async move {
            match authenticate(&shared, req).await {
                Ok(authenticated_req) => inner.call(authenticated_req).await,
                Err(rejection) => Ok(*rejection),
            }
        })
    }
}

/// Authenticates an incoming Axum request against the DevSig profile v1 specification.
#[tracing::instrument(skip_all, fields(method = %req.method(), path = %req.uri().path()))]
async fn authenticate(shared: &Shared, req: Request<Body>) -> Result<Request<Body>, Box<Response>> {
    let (mut parts, body) = req.into_parts();

    // Buffer the body under an enforced cap -- `Limited` errors instead of allocating past the
    // limit, which is the point: an attacker sending an oversized body must not be able to force
    // unbounded memory use just by lacking a valid signature.
    let body_bytes: Bytes = match Limited::new(body, shared.max_body_size).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            tracing::warn!(target: "authkestra_devsig", max_body_size = shared.max_body_size, "rejecting request: body exceeds configured maximum");
            tracing::info!(
                target: "authkestra_devsig",
                limit = shared.max_body_size,
                "device-signature request body over the limit; answering 413"
            );
            return Err(reject(VerifyError::BodyTooLarge(shared.max_body_size)));
        }
    };

    let signature = header_str(&parts, &shared.signature_header);
    let attestation = header_str(&parts, &shared.attestation_header);
    let method = parts.method.as_str();
    let path = parts.uri.path();
    let query = parts.uri.query();
    let body_opt = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.as_ref())
    };

    let signed_request = SignedRequest {
        signature: signature.as_deref(),
        attestation: attestation.as_deref(),
        method,
        path,
        query,
        body: body_opt,
    };

    let result = verify(
        &signed_request,
        &shared.config,
        &shared.jwks,
        shared.replay_store.as_ref(),
    )
    .await;

    match result {
        Ok(identity) => {
            tracing::info!(target: "authkestra_devsig", subject = %identity.subject, device = %identity.device, "device signature verified (axum)");
            parts.extensions.insert(identity);
            Ok(Request::from_parts(parts, Body::from(body_bytes)))
        }
        Err(err) => {
            tracing::warn!(target: "authkestra_devsig", code = err.code(), "rejecting request at the device-signature layer");
            Err(reject(err))
        }
    }
}

/// Extracts an ASCII header string value from the request parts.
fn header_str(parts: &Parts, name: &HeaderName) -> Option<String> {
    parts
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Converts a [`VerifyError`] into a boxed HTTP [`Response`] refusal.
// Boxed: `Response` is large enough that returning it bare in an `Err` variant trips
// `clippy::result_large_err`, which inflates every `Ok` on this path to the error's size.
fn reject(err: VerifyError) -> Box<Response> {
    Box::new(refusal_response(err.refusal()))
}

/// Renders a device-signature refusal in profile v1's shape
/// (`docs/rfc-014-devsig-profile-v1.md`): the refusal's status, a JSON body
/// `{"error": "<code>"}` (`Content-Type: application/json`), and — for a `401` — a
/// `WWW-Authenticate: DeviceSignature error="<code>"` challenge.
///
/// [`DeviceSignatureLayer`] answers every rejection with it. It is public so a handler can
/// answer the two refusals the verifier never produces in the same shape a client already sorts
/// by: [`Refusal::device_revoked`] (the application knows the device is revoked) and
/// [`Refusal::insufficient_user_authentication`] (the handler needs the user-present key, see
/// `authkestra_devsig::DeviceIdentity::key_role`).
///
/// ```
/// use authkestra_axum::devsig::refusal_response;
/// use authkestra_devsig::Refusal;
///
/// let response = refusal_response(Refusal::insufficient_user_authentication());
/// assert_eq!(response.status(), 401);
/// assert_eq!(
///     response.headers()["www-authenticate"],
///     r#"DeviceSignature error="insufficient_user_authentication""#
/// );
/// ```
pub fn refusal_response(refusal: Refusal) -> Response {
    let status = StatusCode::from_u16(refusal.status).unwrap_or_else(|_| {
        tracing::warn!(
            target: "authkestra_devsig",
            status = refusal.status,
            code = refusal.error,
            "invalid refusal status; answering 401"
        );
        StatusCode::UNAUTHORIZED
    });
    let mut response = (
        status,
        [(CONTENT_TYPE, HeaderValue::from_static(REFUSAL_CONTENT_TYPE))],
        refusal.body(),
    )
        .into_response();
    if let Some(challenge) = refusal.www_authenticate() {
        match HeaderValue::from_str(&challenge) {
            Ok(value) => {
                response.headers_mut().insert(WWW_AUTHENTICATE, value);
            }
            Err(_) => tracing::warn!(
                target: "authkestra_devsig",
                code = refusal.error,
                "refusal challenge is not a valid header value; omitting WWW-Authenticate"
            ),
        }
    }
    response
}

/// The extractor for a request verified by [`DeviceSignatureLayer`].
///
/// Wraps `authkestra_devsig::DeviceIdentity` in a local newtype: Rust's orphan rules require
/// this crate to own either the trait (`FromRequestParts`, from axum) or the type
/// (`DeviceIdentity`, from `authkestra-devsig`) being implemented against, and this crate owns
/// neither of those directly -- it owns this wrapper instead.
#[derive(Debug, Clone)]
pub struct AuthDeviceSignature(pub DeviceIdentity);

/// Rejection returned by the [`AuthDeviceSignature`] extractor when the [`DeviceSignatureLayer`]
/// was never run (or rejected the request but the handler was reached anyway, which should not
/// normally happen).
#[derive(Debug)]
#[non_exhaustive]
pub struct MissingDeviceIdentity;

impl IntoResponse for MissingDeviceIdentity {
    fn into_response(self) -> Response {
        (
            StatusCode::UNAUTHORIZED,
            "device identity missing from request extensions -- is DeviceSignatureLayer installed?",
        )
            .into_response()
    }
}

impl<S> FromRequestParts<S> for AuthDeviceSignature
where
    S: Send + Sync,
{
    type Rejection = MissingDeviceIdentity;

    #[tracing::instrument(skip_all)]
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        tracing::debug!(target: "authkestra_devsig", "extracting AuthDeviceSignature from request extensions");
        parts
            .extensions
            .get::<DeviceIdentity>()
            .cloned()
            .map(AuthDeviceSignature)
            .ok_or(MissingDeviceIdentity)
    }
}
