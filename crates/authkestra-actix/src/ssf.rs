//! Actix-web integration for OpenID Shared Signals Framework (SSF) and CAEP event delivery (RFC 8935).

use actix_web::{web, HttpRequest, HttpResponse, Scope};
use authkestra_ssf::PushReceiver;
use std::sync::Arc;

/// Creates an Actix-web scope mounting the SSF push delivery endpoints:
/// - `POST /.well-known/ssf/events`
/// - `POST /ssf/events`
pub fn ssf_actix_scope(receiver: Arc<PushReceiver>) -> Scope {
    web::scope("")
        .app_data(web::Data::new(receiver))
        .route("/.well-known/ssf/events", web::post().to(handle_ssf_events))
        .route("/ssf/events", web::post().to(handle_ssf_events))
}

async fn handle_ssf_events(
    receiver: web::Data<Arc<PushReceiver>>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let content_type = req
        .headers()
        .get(actix_web::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok());

    let push_resp = receiver.receive(content_type, &body).await;

    let status = actix_web::http::StatusCode::from_u16(push_resp.status())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = HttpResponse::build(status);

    if let Some(ct) = push_resp.content_type() {
        builder.insert_header((actix_web::http::header::CONTENT_TYPE, ct));
    }
    if let Some(cl) = push_resp.content_language() {
        builder.insert_header((actix_web::http::header::CONTENT_LANGUAGE, cl));
    }

    builder.body(push_resp.body().to_vec())
}
