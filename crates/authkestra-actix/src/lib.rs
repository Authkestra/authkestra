#[cfg(feature = "resource")]
use actix_web::HttpMessage;
#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use actix_web::{dev::Payload, web, Error, FromRequest, HttpRequest};
// Only the `token` (`AuthToken`) and `resource` (`Jwt`) extractors read the
// `Authorization` header directly; `session`'s `AuthSession` reads a cookie
// instead, so `header` alone needs the narrower gate.
#[cfg(any(feature = "token", feature = "resource"))]
use actix_web::http::header;
#[cfg(feature = "session")]
pub use authkestra_engine::auth::{Session, SessionStore};
#[cfg(feature = "resource")]
use authkestra_engine::token::cert_binding::ClientCertificateDer;
#[cfg(any(feature = "session", feature = "token"))]
pub use authkestra_engine::Missing;
#[cfg(feature = "session")]
pub use authkestra_engine::SessionStoreState;
#[cfg(feature = "token")]
pub use authkestra_engine::TokenManager;
#[cfg(feature = "token")]
pub use authkestra_engine::TokenManagerState;
pub use authkestra_engine::{Engine, SessionConfig};
#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use futures::future::LocalBoxFuture;
#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use std::sync::Arc;

#[cfg(feature = "resource")]
pub mod extensions;
pub mod helpers;

#[cfg(feature = "resource")]
pub use extensions::CarriedExtensions;

#[cfg(feature = "op")]
pub mod op;

#[cfg(feature = "devsig")]
pub mod devsig;

#[cfg(feature = "mcp")]
pub mod mcp;

#[cfg(feature = "ssf")]
pub mod ssf;

#[cfg(feature = "policy")]
pub mod policy;

#[cfg(feature = "macros")]
pub use authkestra_macros::ActixState;
pub use helpers::actix_login_handler;
#[cfg(feature = "session")]
pub use helpers::{actix_callback_handler, actix_logout_handler};

#[cfg(feature = "op")]
pub use op::OpExt;

#[cfg(feature = "devsig")]
pub use devsig::{AuthDeviceSignature, DeviceSignatureAuth};

#[cfg(feature = "mcp")]
pub use mcp::{mcp_actix_scope, McpExt};

#[cfg(feature = "ssf")]
pub use ssf::ssf_actix_scope;

#[cfg(feature = "policy")]
pub use policy::AuthPolicyGuard;

pub trait ActixExt<S, T> {
    fn actix_scope(&self) -> actix_web::Scope;
}
#[cfg(feature = "token")]
pub trait ActixStatelessExt<S, T> {
    fn actix_scope_stateless(&self) -> actix_web::Scope;
}
#[cfg(feature = "session")]
impl<S, T> ActixExt<S, T> for Engine<S, T>
where
    S: Clone + SessionStoreState + 'static,
    T: Clone + 'static,
{
    fn actix_scope(&self) -> actix_web::Scope {
        let mut scope = web::scope("/auth");

        scope = scope.route(
            "/login/{provider}",
            web::get().to(actix_login_handler::<S, T>),
        );
        scope = scope.route(
            "/callback/{provider}",
            web::get().to(actix_callback_handler::<S, T>),
        );
        scope = scope.route("/logout", web::get().to(actix_logout_handler::<S, T>));

        scope
    }
}

#[cfg(feature = "token")]
impl<S, T> ActixStatelessExt<S, T> for Engine<S, T>
where
    S: Clone + 'static,
    T: Clone + TokenManagerState + 'static,
{
    fn actix_scope_stateless(&self) -> actix_web::Scope {
        let mut scope = web::scope("/auth");

        scope = scope.route(
            "/login/{provider}",
            web::get().to(helpers::actix_login_handler::<S, T>),
        );
        scope = scope.route(
            "/callback/{provider}",
            web::get().to(helpers::actix_callback_handler_stateless::<S, T>),
        );

        scope
    }
}

/// The extractor for a validated session.
#[cfg(feature = "session")]
pub struct AuthSession(pub Session);

#[cfg(feature = "session")]
impl FromRequest for AuthSession {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let store = req.app_data::<web::Data<Arc<dyn SessionStore>>>().cloned();

        let config = req.app_data::<web::Data<SessionConfig>>().cloned();

        let session_id = req
            .cookie(
                config
                    .as_ref()
                    .map(|c| c.cookie_name.as_str())
                    .unwrap_or("authkestra_session"),
            )
            .map(|c| c.value().to_string());

        Box::pin(async move {
            tracing::debug!("extracting AuthSession from actix request");
            let store = store.ok_or_else(|| {
                tracing::error!("SessionStore not configured in actix app data");
                actix_web::error::ErrorInternalServerError("SessionStore not configured")
            })?;
            let _config = config.ok_or_else(|| {
                tracing::error!("SessionConfig not configured in actix app data");
                actix_web::error::ErrorInternalServerError("SessionConfig not configured")
            })?;

            let session_id = session_id.ok_or_else(|| {
                tracing::warn!("missing session cookie in request");
                actix_web::error::ErrorUnauthorized("Missing session cookie")
            })?;

            let session = store
                .get_ref()
                .load_session(&session_id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "failed to load session from store");
                    actix_web::error::ErrorInternalServerError(e.to_string())
                })?
                .ok_or_else(|| {
                    tracing::warn!("session not found or invalid");
                    actix_web::error::ErrorUnauthorized("Invalid session")
                })?;

            tracing::info!(session_id = %session.id, user_id = %session.identity.external_id, "successfully extracted actix AuthSession");
            Ok(AuthSession(session))
        })
    }
}

/// The extractor for a validated JWT.
///
/// Expects an `Authorization: Bearer <token>` header.
#[cfg(feature = "token")]
pub struct AuthToken(pub authkestra_engine::Claims);

#[cfg(feature = "token")]
impl FromRequest for AuthToken {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token_manager = req.app_data::<web::Data<Arc<TokenManager>>>().cloned();

        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        Box::pin(async move {
            tracing::debug!("extracting AuthToken from actix request");
            let token_manager = token_manager.ok_or_else(|| {
                tracing::error!("Token manager not configured in actix app data");
                actix_web::error::ErrorInternalServerError("Token manager not configured")
            })?;
            let auth_header = auth_header.ok_or_else(|| {
                tracing::warn!("missing Authorization header in actix request");
                actix_web::error::ErrorUnauthorized("Missing Authorization header")
            })?;

            if !auth_header.starts_with("Bearer ") {
                tracing::warn!("invalid Authorization header format in actix request");
                return Err(actix_web::error::ErrorUnauthorized(
                    "Invalid Authorization header",
                ));
            }

            let token = &auth_header[7..];
            let claims = token_manager
                .get_ref()
                .validate_token(token, None)
                .map_err(|e| {
                    tracing::error!(error = %e, "failed to validate token");
                    actix_web::error::ErrorUnauthorized(format!("Invalid token: {e}"))
                })?;

            tracing::info!("successfully extracted and validated actix AuthToken");
            Ok(AuthToken(claims))
        })
    }
}

/// A generic JWT extractor for resource server validation.
///
/// Validates a Bearer token against a configured `JwksCache` and `jsonwebtoken::Validation`.
#[cfg(feature = "resource")]
pub struct Jwt<T>(pub T);

#[cfg(feature = "resource")]
impl<T> FromRequest for Jwt<T>
where
    T: for<'de> serde::Deserialize<'de> + 'static,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let cache = req
            .app_data::<web::Data<Arc<authkestra_resource::jwt::JwksCache>>>()
            .cloned();
        let validation = req
            .app_data::<web::Data<jsonwebtoken::Validation>>()
            .cloned();

        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        Box::pin(async move {
            tracing::debug!("extracting Jwt from actix request");
            let cache = cache.ok_or_else(|| {
                tracing::error!("JwksCache not configured in actix app data");
                actix_web::error::ErrorInternalServerError("JwksCache not configured")
            })?;
            let validation = validation.ok_or_else(|| {
                tracing::error!("jsonwebtoken::Validation not configured in actix app data");
                actix_web::error::ErrorInternalServerError(
                    "jsonwebtoken::Validation not configured",
                )
            })?;
            let auth_header = auth_header.ok_or_else(|| {
                tracing::warn!("missing Authorization header in actix request");
                actix_web::error::ErrorUnauthorized("Missing Authorization header")
            })?;

            if !auth_header.starts_with("Bearer ") {
                tracing::warn!("invalid Authorization header format in actix request");
                return Err(actix_web::error::ErrorUnauthorized(
                    "Invalid Authorization header",
                ));
            }

            let token = &auth_header[7..];
            let claims =
                authkestra_resource::jwt::validate_jwt_generic::<T>(token, &cache, &validation)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "failed to validate generic jwt");
                        actix_web::error::ErrorUnauthorized(format!("Invalid token: {e}"))
                    })?;

            tracing::info!("successfully extracted and validated actix Jwt");
            Ok(Jwt(claims))
        })
    }
}

/// A unified extractor for authentication.
///
/// It uses the `Guard` from the application state to validate the request.
///
/// # Request extensions
///
/// Unlike axum, actix has no `http::request::Parts` of its own, so this
/// extractor synthesises one from the request's method, URI and headers. Actix
/// request extensions therefore do not come along automatically. Register the
/// types that must survive with [`CarriedExtensions`] in `app_data`; see that
/// type's docs (and `extensions`' module docs) for why carrying the whole map
/// generically is not possible on actix-http 3.x / `http` 1.x. Issue #246.
#[cfg(feature = "resource")]
pub struct Auth<I>(pub I);

#[cfg(feature = "resource")]
impl<I> FromRequest for Auth<I>
where
    I: Send + Sync + 'static,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let guard = req
            .app_data::<web::Data<Arc<authkestra_resource::Guard<I>>>>()
            .cloned();

        let req_clone = req.clone();

        Box::pin(async move {
            tracing::debug!("extracting generic Auth from actix request via Guard");
            let guard = guard.ok_or_else(|| {
                tracing::error!("Guard not configured in actix app data");
                actix_web::error::ErrorInternalServerError("Guard not configured")
            })?;

            // Convert actix HttpRequest to http::request::Parts (http 1.0)
            let mut builder = http::Request::builder()
                .method(req_clone.method().as_str())
                .uri(req_clone.uri().to_string());
            for (name, val) in req_clone.headers() {
                if let (Ok(name), Ok(val)) = (
                    http::HeaderName::from_bytes(name.as_str().as_bytes()),
                    http::HeaderValue::from_bytes(val.as_bytes()),
                ) {
                    builder = builder.header(name, val);
                }
            }
            let http_req = builder.body(()).map_err(|e| {
                tracing::error!("failed to build http request parts: {e}");
                actix_web::error::ErrorInternalServerError("Failed to build request parts")
            })?;
            let (mut parts, _) = http_req.into_parts();

            // The `Parts` above are synthesised from method/URI/headers only,
            // so actix's per-request extension map is not represented in them
            // at all. Copy across the types the host asked for (issue #246);
            // `extensions`' module docs record why an automatic
            // carry-everything is not expressible on actix-http 3.x + `http`
            // 1.x. This must happen before `authenticate`, and the borrow of
            // actix's `RefCell`-backed extensions is scoped so it is released
            // before the `.await` below.
            {
                let src = req_clone.extensions();

                // Always carried, no registration required: a host-app
                // middleware/acceptor stashes this from real mTLS termination
                // and RFC 8705 certificate-bound tokens
                // (`JwtStrategy::require_cert_binding`, issue #224) fail
                // closed without it. Keeping it implicit means the #224 fix
                // cannot be silently undone by a host forgetting to register
                // it.
                extensions::carry_one::<ClientCertificateDer>(&src, &mut parts.extensions);

                // Accept both `.app_data(web::Data::new(registry))` and the
                // bare `.app_data(registry)` form. Matching only one would
                // turn the other into a silent no-op, which is precisely the
                // failure mode issue #246 is about.
                let registry = req_clone
                    .app_data::<web::Data<extensions::CarriedExtensions>>()
                    .map(web::Data::get_ref)
                    .or_else(|| req_clone.app_data::<extensions::CarriedExtensions>());

                match registry {
                    Some(registry) => {
                        let carried = registry.apply(&src, &mut parts.extensions);
                        if !registry.is_empty() && carried == 0 {
                            // The host registered types but none were present
                            // on the request. Almost always a wiring mistake:
                            // wrong type registered, or the middleware that
                            // inserts it ordered after this extractor. Warn
                            // rather than debug — the symptom is otherwise a
                            // bare 401 with no operator-visible signal, which
                            // is the exact silence #246 exists to remove.
                            tracing::warn!(
                                registered = registry.len(),
                                "CarriedExtensions registered types but none were present on \
                                 the request; check the registered type and that the \
                                 middleware inserting it runs before the extractor"
                            );
                        } else {
                            tracing::debug!(
                                registered = registry.len(),
                                carried,
                                "carried registered actix request extensions into request parts"
                            );
                        }
                    }
                    None => {
                        // Deliberately `trace!`, not `debug!`: this arm fires on
                        // every request of every app that never opts in, where
                        // it carries no signal.
                        tracing::trace!(
                            "no CarriedExtensions registry in actix app data; only \
                             ClientCertificateDer is carried into request parts"
                        );
                    }
                }
            }

            match guard.authenticate(&parts).await {
                Ok(Some(identity)) => {
                    tracing::info!("successfully authenticated request via Guard");
                    Ok(Auth(identity))
                }
                Ok(None) => {
                    tracing::warn!("authentication failed: no identity returned");
                    Err(actix_web::error::ErrorUnauthorized("Authentication failed"))
                }
                Err(e) => {
                    tracing::error!(error = %e, "internal error during authentication");
                    Err(actix_web::error::ErrorInternalServerError(e.to_string()))
                }
            }
        })
    }
}

/// Re-exports the derive macros reach through. Not public API.
///
/// `#[derive(ActixState)]` expands to code naming `authkestra_engine` and
/// `actix_web`. Emitting those as bare paths made the expansion depend on what
/// the *caller* happens to have in scope, so the derive only compiled for
/// someone with both crates as direct dependencies under exactly those
/// names — anyone following the documented advice to depend on the
/// `authkestra` facade got an error naming a crate they never wrote down
/// (#332). Routing every emitted path through this module fixes that: the
/// anchor is this crate, which the caller demonstrably *can* name, since
/// that is where the derive itself came from.
///
/// A caller reaching this crate under another name — through the facade's
/// `authkestra::actix` re-export, say — says so with
/// `#[authkestra(crate = ...)]` on the struct.
#[doc(hidden)]
pub mod __private {
    pub use actix_web;
    pub use authkestra_engine;
}
