//! Actix Web integration for `authkestra-devsig`: an `actix_web::dev::Transform` middleware
//! that verifies device-signed requests ahead of the handler, plus a thin extractor that reads
//! the result back out.
//!
//! This is the Actix mirror of `authkestra-axum`'s `devsig` module — same verification core
//! (`authkestra_devsig::verify`), same body-buffering rationale, different framework glue. See
//! that module's docs for the full architecture discussion of why this is a middleware and not
//! an `authkestra-engine` `AuthenticationStrategy<I>` impl (short version: neither
//! `AuthenticationStrategy<I>` nor `AuthMethod` can see the request body today, which this
//! scheme's `bdh` check requires — see
//! [authkestra#137](https://github.com/marcjazz/authkestra/issues/137)).
//!
//! [`DeviceSignatureAuth`] buffers the body (under an explicit, enforced size cap), calls
//! `authkestra_devsig::verify` with the full request, and stashes the resulting
//! `authkestra_devsig::DeviceIdentity` in the request's extensions on success -- or
//! short-circuits with a `401`/`413` response on failure, in device-signature profile v1's shape
//! (see [`refusal_response`]). [`AuthDeviceSignature`] is a
//! `FromRequest` extractor that reads the identity the middleware already verified back out of
//! extensions; it does not perform any verification itself.

use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::Arc;

use actix_web::dev::{forward_ready, Payload, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{self, HeaderName};
use actix_web::http::StatusCode;
use actix_web::web::{Bytes, BytesMut};
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse};
use authkestra_devsig::{
    verify, DeviceIdentity, IssuerJwks, Refusal, ReplayStore, SignedRequest, VerifierConfig,
    VerifyError, REFUSAL_CONTENT_TYPE,
};
use futures_util::future::LocalBoxFuture;
use futures_util::StreamExt;

/// Default cap on the buffered request body. Buffering is a memory-amplification vector (the
/// middleware must hold the whole body before it can compute `bdh`), so this is deliberately
/// conservative; override with [`DeviceSignatureAuth::max_body_size`] for endpoints that
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

/// An `actix_web::dev::Transform` factory that verifies `X-Signature` + `X-Attestation` (header
/// names configurable) against a `VerifierConfig`, an `IssuerJwks` cache, and a `ReplayStore`,
/// injecting a verified `DeviceIdentity` into the request's extensions ahead of the handler.
///
/// On rejection, short-circuits with a `401 Unauthorized` (or `413 Payload Too Large` if the
/// body exceeds [`DeviceSignatureAuth::max_body_size`]) and never calls the wrapped service.
///
/// Uses `Arc` (not `Rc`) for the shared configuration so the value stays `Send + Sync` and can
/// be constructed once, outside `HttpServer::new(move || ...)`, and cloned per worker -- the
/// standard shape for actix middleware factories that carry state.
#[derive(Clone)]
#[non_exhaustive]
pub struct DeviceSignatureAuth {
    shared: Arc<Shared>,
}

impl DeviceSignatureAuth {
    /// Builds a middleware factory with the default header names (`X-Signature`,
    /// `X-Attestation`) and default body size cap ([`DEFAULT_MAX_BODY_SIZE`]).
    #[tracing::instrument(skip_all)]
    pub fn new(
        config: VerifierConfig,
        jwks: Arc<IssuerJwks>,
        replay_store: Arc<dyn ReplayStore>,
    ) -> Self {
        tracing::debug!(target: "authkestra_devsig", "constructing actix DeviceSignatureAuth");
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

impl From<authkestra_devsig::DevSig<Arc<dyn ReplayStore>>> for DeviceSignatureAuth {
    fn from(devsig: authkestra_devsig::DevSig<Arc<dyn ReplayStore>>) -> Self {
        Self::new(devsig.config, devsig.jwks, devsig.replay_store)
    }
}

impl<S, B> Transform<S, ServiceRequest> for DeviceSignatureAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = DeviceSignatureAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DeviceSignatureAuthMiddleware {
            service: Rc::new(service),
            shared: self.shared.clone(),
        }))
    }
}

/// The `actix_web::dev::Service` produced by [`DeviceSignatureAuth`]. Not constructed directly.
#[non_exhaustive]
pub struct DeviceSignatureAuthMiddleware<S> {
    service: Rc<S>,
    shared: Arc<Shared>,
}

impl<S, B> Service<ServiceRequest> for DeviceSignatureAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let shared = Arc::clone(&self.shared);

        Box::pin(async move {
            let authenticated_req = authenticate(&shared, req).await?;
            service.call(authenticated_req).await
        })
    }
}

/// Authenticates an incoming Actix service request against the DevSig profile v1 specification.
#[tracing::instrument(skip_all, fields(method = %req.method(), path = %req.path()))]
async fn authenticate(shared: &Shared, req: ServiceRequest) -> Result<ServiceRequest, Error> {
    let (http_req, mut payload) = req.into_parts();

    // Buffer the body under an enforced cap -- an attacker sending an oversized body must not be
    // able to force unbounded memory use just by lacking a valid signature.
    let mut buf = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|e| {
            tracing::warn!(target: "authkestra_devsig", error = %e, "failed to read request body while verifying device signature");
            actix_web::error::ErrorBadRequest("failed to read request body")
        })?;
        if buf.len() + chunk.len() > shared.max_body_size {
            tracing::warn!(target: "authkestra_devsig", max_body_size = shared.max_body_size, "rejecting request: body exceeds configured maximum");
            tracing::info!(
                target: "authkestra_devsig",
                limit = shared.max_body_size,
                "device-signature request body over the limit; answering 413"
            );
            return Err(reject(VerifyError::BodyTooLarge(shared.max_body_size)));
        }
        buf.extend_from_slice(&chunk);
    }
    let body_bytes: Bytes = buf.freeze();

    let signature = header_str(&http_req, &shared.signature_header);
    let attestation = header_str(&http_req, &shared.attestation_header);
    let method = http_req.method().as_str();
    let path = http_req.uri().path();
    let query = http_req.uri().query();
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
            tracing::info!(target: "authkestra_devsig", subject = %identity.subject, device = %identity.device, "device signature verified (actix)");
            let new_req = ServiceRequest::from_parts(http_req, Payload::from(body_bytes));
            new_req.extensions_mut().insert(identity);
            Ok(new_req)
        }
        Err(err) => {
            tracing::warn!(target: "authkestra_devsig", code = err.code(), "rejecting request at the device-signature middleware");
            Err(reject(err))
        }
    }
}

/// Extracts an ASCII header string value from the HTTP request.
fn header_str(req: &HttpRequest, name: &HeaderName) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Converts a [`VerifyError`] into an Actix HTTP error refusal.
fn reject(err: VerifyError) -> Error {
    let response = refusal_response(err.refusal());
    actix_web::error::InternalError::from_response(err, response).into()
}

/// Renders a device-signature refusal in profile v1's shape
/// (`docs/rfc-014-devsig-profile-v1.md`): the refusal's status, a JSON body
/// `{"error": "<code>"}` (`Content-Type: application/json`), and — for a `401` — a
/// `WWW-Authenticate: DeviceSignature error="<code>"` challenge.
///
/// [`DeviceSignatureAuth`] answers every rejection with it. It is public so a handler can answer
/// the two refusals the verifier never produces in the same shape a client already sorts by:
/// [`Refusal::device_revoked`] (the application knows the device is revoked) and
/// [`Refusal::insufficient_user_authentication`] (the handler needs the user-present key, see
/// `authkestra_devsig::DeviceIdentity::key_role`).
///
/// ```
/// use authkestra_actix::devsig::refusal_response;
/// use authkestra_devsig::Refusal;
///
/// let response = refusal_response(Refusal::device_revoked());
/// assert_eq!(response.status(), 403);
/// ```
pub fn refusal_response(refusal: Refusal) -> HttpResponse {
    let status = StatusCode::from_u16(refusal.status).unwrap_or_else(|_| {
        tracing::warn!(
            target: "authkestra_devsig",
            status = refusal.status,
            code = refusal.error,
            "invalid refusal status; answering 401"
        );
        StatusCode::UNAUTHORIZED
    });
    let mut response = HttpResponse::build(status);
    response.content_type(REFUSAL_CONTENT_TYPE);
    if let Some(challenge) = refusal.www_authenticate() {
        response.insert_header((header::WWW_AUTHENTICATE, challenge));
    }
    response.body(refusal.body())
}

/// The extractor for a request verified by [`DeviceSignatureAuth`].
///
/// Wraps `authkestra_devsig::DeviceIdentity` in a local newtype: Rust's orphan rules require
/// this crate to own either the trait (`FromRequest`, from actix-web) or the type
/// (`DeviceIdentity`, from `authkestra-devsig`) being implemented against, and this crate owns
/// neither of those directly -- it owns this wrapper instead.
#[derive(Debug, Clone)]
pub struct AuthDeviceSignature(pub DeviceIdentity);

impl FromRequest for AuthDeviceSignature {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        tracing::debug!(target: "authkestra_devsig", "extracting AuthDeviceSignature from request extensions");
        let identity = req.extensions().get::<DeviceIdentity>().cloned();
        ready(identity.map(AuthDeviceSignature).ok_or_else(|| {
            tracing::warn!(target: "authkestra_devsig", "device identity missing from request extensions -- is DeviceSignatureAuth installed?");
            actix_web::error::ErrorUnauthorized(
                "device identity missing from request extensions -- is DeviceSignatureAuth installed?",
            )
        }))
    }
}
