use actix_web::{
    http::header::{HeaderValue, CONTENT_TYPE, WWW_AUTHENTICATE},
    web, HttpMessage, HttpRequest, HttpResponse,
};
use authkestra_engine::auth::state::Identity;
use authkestra_mcp::{
    www_authenticate_insufficient_scope, www_authenticate_unauthorized, JsonRpcError,
    JsonRpcRequest, McpError, McpRouter, ProtectedResourceMetadata, APPROVAL_TOKEN_ARG_KEY,
    APPROVAL_TOKEN_HEADER, JSONRPC_VERSION, RPC_PARSE_ERROR, RPC_UNAUTHORIZED,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Query parameters for querying a pending approval challenge.
#[derive(Debug, Deserialize)]
pub struct QueryApproveParams {
    pub id: Option<String>,
    pub approval_id: Option<String>,
}

/// Request payload for submitting human step-up approval.
#[derive(Debug, Deserialize)]
pub struct ApprovalSubmissionPayload {
    pub approval_id: Option<String>,
    pub id: Option<String>,
}

/// Resolves the configured `McpRouter` from Actix application data.
fn get_router(req: &HttpRequest) -> Option<Arc<McpRouter>> {
    if let Some(d) = req.app_data::<web::Data<Arc<McpRouter>>>() {
        return Some(d.get_ref().clone());
    }
    if let Some(d) = req.app_data::<web::Data<McpRouter>>() {
        return Some(Arc::new(d.get_ref().clone()));
    }
    if let Some(d) = req.app_data::<Arc<McpRouter>>() {
        return Some(d.clone());
    }
    None
}

/// Extracts caller identity from request extensions, app data, or headers.
fn extract_identity(req: &HttpRequest) -> Option<Identity> {
    if let Some(id) = req.extensions().get::<Identity>() {
        tracing::debug!(
            provider_id = %id.provider_id,
            external_id = %id.external_id,
            "resolved caller identity from request extensions (Identity)"
        );
        return Some(id.clone());
    }

    if let Some(id) = req.extensions().get::<Arc<Identity>>() {
        tracing::debug!(
            provider_id = %id.provider_id,
            external_id = %id.external_id,
            "resolved caller identity from request extensions (Arc<Identity>)"
        );
        return Some((**id).clone());
    }

    if let Some(d) = req.app_data::<web::Data<Identity>>() {
        tracing::debug!(
            provider_id = %d.provider_id,
            external_id = %d.external_id,
            "resolved caller identity from app data (web::Data<Identity>)"
        );
        return Some(d.get_ref().clone());
    }

    if let Some(id) = req.app_data::<Identity>() {
        tracing::debug!(
            provider_id = %id.provider_id,
            external_id = %id.external_id,
            "resolved caller identity from app data (Identity)"
        );
        return Some(id.clone());
    }

    if let Some(id) = req.app_data::<Arc<Identity>>() {
        tracing::debug!(
            provider_id = %id.provider_id,
            external_id = %id.external_id,
            "resolved caller identity from app data (Arc<Identity>)"
        );
        return Some((**id).clone());
    }

    if let Some(raw_header) = req
        .headers()
        .get("x-authkestra-identity")
        .and_then(|h| h.to_str().ok())
    {
        match serde_json::from_str::<Identity>(raw_header) {
            Ok(id) => {
                tracing::debug!(
                    provider_id = %id.provider_id,
                    external_id = %id.external_id,
                    "resolved caller identity from x-authkestra-identity header"
                );
                return Some(id);
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse x-authkestra-identity header");
            }
        }
    }

    tracing::debug!("no caller identity found in Actix request");
    None
}

/// Handler for the MCP JSON-RPC 2.0 endpoint (`POST {path}`).
pub async fn actix_mcp_handler(req: HttpRequest, body_bytes: web::Bytes) -> HttpResponse {
    tracing::debug!("Handling MCP JSON-RPC request (actix)");
    let Some(router) = get_router(&req) else {
        tracing::error!("McpRouter not registered in Actix application data");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "server_error",
            "error_description": "McpRouter not found in Actix app_data"
        }));
    };

    let session_id = req
        .headers()
        .get("x-session-id")
        .or_else(|| req.headers().get("mcp-session-id"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let identity = extract_identity(&req);

    let mut rpc_req: JsonRpcRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse JSON-RPC request payload in Actix");
            return HttpResponse::Ok().json(serde_json::json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": null,
                "error": JsonRpcError {
                    code: RPC_PARSE_ERROR,
                    message: format!("Parse error: {e}"),
                    data: None,
                }
            }));
        }
    };

    // If client supplied execution token in HTTP header, inject into arguments if tools/call
    if let Some(token_val) = req
        .headers()
        .get(APPROVAL_TOKEN_HEADER)
        .and_then(|h| h.to_str().ok())
    {
        if rpc_req.method == "tools/call" {
            if let Some(serde_json::Value::Object(ref mut map)) = rpc_req.params {
                if !map.contains_key(APPROVAL_TOKEN_ARG_KEY) {
                    if let Some(serde_json::Value::Object(ref mut args)) = map.get_mut("arguments")
                    {
                        if !args.contains_key(APPROVAL_TOKEN_ARG_KEY) {
                            tracing::debug!(
                                "injecting approval token from HTTP header into tool arguments (actix)"
                            );
                            args.insert(
                                APPROVAL_TOKEN_ARG_KEY.to_string(),
                                serde_json::Value::String(token_val.to_string()),
                            );
                        }
                    }
                }
            }
        }
    }

    let rpc_res = router.handle_json_rpc(rpc_req, identity, session_id).await;

    let mut builder = HttpResponse::Ok();

    // Attach RFC 9728 WWW-Authenticate header if response contains authentication/scope error
    if let Some(ref err) = rpc_res.error {
        if err.code == RPC_UNAUTHORIZED {
            if err.message.to_lowercase().contains("insufficient scope") {
                tracing::debug!("attaching WWW-Authenticate insufficient_scope header in Actix");
                let www_auth = www_authenticate_insufficient_scope(router.metadata_url(), &[]);
                if let Ok(val) = HeaderValue::from_str(&www_auth) {
                    builder.insert_header((WWW_AUTHENTICATE, val));
                }
            } else {
                tracing::debug!("attaching WWW-Authenticate unauthorized header in Actix");
                let www_auth = www_authenticate_unauthorized(router.metadata_url());
                if let Ok(val) = HeaderValue::from_str(&www_auth) {
                    builder.insert_header((WWW_AUTHENTICATE, val));
                }
            }
        }
    }

    builder.json(rpc_res)
}

/// Handler for the RFC 9728 Protected Resource Metadata endpoint (`GET /.well-known/oauth-protected-resource`).
pub async fn actix_resource_metadata_handler(req: HttpRequest) -> HttpResponse {
    tracing::debug!("Handling RFC 9728 Protected Resource Metadata request (actix)");
    let Some(router) = get_router(&req) else {
        tracing::error!("McpRouter not registered in Actix application data");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "server_error",
            "error_description": "McpRouter not found in Actix app_data"
        }));
    };

    let meta = router
        .resource_metadata()
        .cloned()
        .unwrap_or_else(|| ProtectedResourceMetadata::new(router.metadata_url()));

    HttpResponse::Ok()
        .insert_header((CONTENT_TYPE, "application/json"))
        .json(meta)
}

/// Handler for querying a pending approval challenge (`GET /mcp/approve?id=...`).
pub async fn actix_approve_query_handler(
    req: HttpRequest,
    query: web::Query<QueryApproveParams>,
) -> HttpResponse {
    tracing::debug!(query = ?query, "Handling MCP step-up challenge query (actix)");
    let Some(router) = get_router(&req) else {
        tracing::error!("McpRouter not registered in Actix application data");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "server_error",
            "error_description": "McpRouter not found in Actix app_data"
        }));
    };

    let approval_id = match query.id.as_deref().or(query.approval_id.as_deref()) {
        Some(id) if !id.trim().is_empty() => id,
        _ => {
            tracing::warn!("missing approval id query parameter in Actix");
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Missing 'id' or 'approval_id' query parameter"
            }));
        }
    };

    match router.query_pending_approval(approval_id).await {
        Ok(Some(challenge)) => {
            tracing::info!(approval_id = %approval_id, "found pending approval challenge (actix)");
            HttpResponse::Ok().json(challenge)
        }
        Ok(None) => {
            tracing::warn!(approval_id = %approval_id, "pending approval challenge not found or expired (actix)");
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "not_found",
                "error_description": "Pending approval challenge not found or expired"
            }))
        }
        Err(e) => {
            tracing::error!(approval_id = %approval_id, error = %e, "internal error querying approval challenge in Actix");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "server_error",
                "error_description": e.to_string()
            }))
        }
    }
}

/// Handler for submitting a step-up approval proof (`POST /mcp/approve`).
pub async fn actix_approve_submit_handler(
    req: HttpRequest,
    payload: web::Json<ApprovalSubmissionPayload>,
) -> HttpResponse {
    tracing::debug!(payload = ?payload, "Handling MCP step-up challenge approval submission (actix)");
    let Some(router) = get_router(&req) else {
        tracing::error!("McpRouter not registered in Actix application data");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "server_error",
            "error_description": "McpRouter not found in Actix app_data"
        }));
    };

    let approval_id = match payload.approval_id.as_deref().or(payload.id.as_deref()) {
        Some(id) if !id.trim().is_empty() => id,
        _ => {
            tracing::warn!("missing approval id in submission payload (actix)");
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Missing 'approval_id' or 'id' in submission body"
            }));
        }
    };

    let identity = match extract_identity(&req) {
        Some(id) => id,
        None => {
            tracing::warn!(approval_id = %approval_id, "approver identity missing in step-up submission (actix)");
            let www_auth = www_authenticate_unauthorized(router.metadata_url());
            return HttpResponse::Unauthorized()
                .insert_header((WWW_AUTHENTICATE, www_auth))
                .json(serde_json::json!({
                    "error": "unauthorized",
                    "error_description": "Approver identity missing. Authentication required."
                }));
        }
    };

    match router.approve_challenge(approval_id, &identity).await {
        Ok(result) => {
            tracing::info!(
                approval_id = %approval_id,
                execution_token = %result.execution_token,
                "step-up challenge approved and execution token minted (actix)"
            );
            HttpResponse::Ok().json(result)
        }
        Err(McpError::Reproof(err)) => {
            tracing::warn!(approval_id = %approval_id, reproof_error = ?err, "reproof check failed during approval ceremony (actix)");
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "reproof_failed",
                "error_description": format!("Reproof verification failed: {err:?}")
            }))
        }
        Err(McpError::Unauthorized(msg)) => {
            tracing::warn!(approval_id = %approval_id, error = %msg, "pending challenge not found or unauthorized (actix)");
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "not_found",
                "error_description": msg
            }))
        }
        Err(e) => {
            tracing::error!(approval_id = %approval_id, error = %e, "internal error during step-up approval ceremony in Actix");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "server_error",
                "error_description": e.to_string()
            }))
        }
    }
}

/// Extension trait for creating an Actix scope with MCP endpoints.
pub trait McpExt {
    /// Creates an Actix scope registering MCP endpoints at `{path}`,
    /// RFC 9728 metadata at `/.well-known/oauth-protected-resource`,
    /// and step-up approval endpoints at `/mcp/approve`.
    fn mcp_actix_scope(&self, path: &str) -> actix_web::Scope;
}

impl<T> McpExt for T {
    fn mcp_actix_scope(&self, path: &str) -> actix_web::Scope {
        mcp_actix_scope(path)
    }
}

/// Free function to create an Actix scope registering:
/// - `POST {path}`: JSON-RPC MCP endpoint (`tools/list`, `tools/call`).
/// - `GET /.well-known/oauth-protected-resource`: RFC 9728 Protected Resource Metadata.
/// - `GET /mcp/approve` and `POST /mcp/approve`: Step-up challenge query and approval submission.
pub fn mcp_actix_scope(path: &str) -> actix_web::Scope {
    let clean_path = path.trim();
    if clean_path.is_empty() || clean_path == "/" {
        actix_web::web::scope("")
            .service(
                actix_web::web::resource("/mcp")
                    .route(actix_web::web::post().to(actix_mcp_handler)),
            )
            .service(
                actix_web::web::resource("/mcp/")
                    .route(actix_web::web::post().to(actix_mcp_handler)),
            )
            .service(
                actix_web::web::resource("/.well-known/oauth-protected-resource")
                    .route(actix_web::web::get().to(actix_resource_metadata_handler)),
            )
            .service(
                actix_web::web::resource("/mcp/approve")
                    .route(actix_web::web::get().to(actix_approve_query_handler))
                    .route(actix_web::web::post().to(actix_approve_submit_handler)),
            )
            .service(
                actix_web::web::resource("/approve")
                    .route(actix_web::web::get().to(actix_approve_query_handler))
                    .route(actix_web::web::post().to(actix_approve_submit_handler)),
            )
    } else {
        actix_web::web::scope(clean_path)
            .service(
                actix_web::web::resource("").route(actix_web::web::post().to(actix_mcp_handler)),
            )
            .service(
                actix_web::web::resource("/").route(actix_web::web::post().to(actix_mcp_handler)),
            )
            .service(
                actix_web::web::resource("/.well-known/oauth-protected-resource")
                    .route(actix_web::web::get().to(actix_resource_metadata_handler)),
            )
            .service(
                actix_web::web::resource("/approve")
                    .route(actix_web::web::get().to(actix_approve_query_handler))
                    .route(actix_web::web::post().to(actix_approve_submit_handler)),
            )
            .service(
                actix_web::web::resource("/mcp/approve")
                    .route(actix_web::web::get().to(actix_approve_query_handler))
                    .route(actix_web::web::post().to(actix_approve_submit_handler)),
            )
    }
}
