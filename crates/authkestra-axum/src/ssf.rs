//! Axum integration for OpenID Shared Signals Framework (SSF) and CAEP event delivery (RFC 8935).

use authkestra_ssf::PushReceiver;
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use std::sync::Arc;

/// Creates an Axum router mounting the SSF push delivery endpoints:
/// - `POST /.well-known/ssf/events`
/// - `POST /ssf/events`
pub fn ssf_axum_router<AppState>(receiver: Arc<PushReceiver>) -> Router<AppState>
where
    AppState: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/.well-known/ssf/events", post(handle_ssf_events))
        .route("/ssf/events", post(handle_ssf_events))
        .with_state(receiver)
}

async fn handle_ssf_events(
    State(receiver): State<Arc<PushReceiver>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok());

    let push_resp = receiver.receive(content_type, &body).await;

    let status =
        StatusCode::from_u16(push_resp.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = Response::builder().status(status);

    if let Some(ct) = push_resp.content_type() {
        response_builder = response_builder.header(header::CONTENT_TYPE, ct);
    }
    if let Some(cl) = push_resp.content_language() {
        response_builder = response_builder.header(header::CONTENT_LANGUAGE, cl);
    }

    response_builder
        .body(axum::body::Body::from(push_resp.body().to_vec()))
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build response",
            )
                .into_response()
        })
}
