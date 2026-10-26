use authkestra_engine::auth::state::Identity;
use authkestra_mcp::{
    www_authenticate_insufficient_scope, www_authenticate_unauthorized, JsonRpcError,
    JsonRpcRequest, McpError, McpRouter, ProtectedResourceMetadata, APPROVAL_TOKEN_ARG_KEY,
    APPROVAL_TOKEN_HEADER, JSONRPC_VERSION, RPC_PARSE_ERROR, RPC_UNAUTHORIZED,
};
use axum::{
    body::Bytes,
    extract::{Extension, FromRef, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json,
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

/// Extracts caller identity from request extensions, custom headers, or returns None.
fn extract_identity(
    headers: &HeaderMap,
    opt_ext_id: Option<&Identity>,
    opt_ext_arc_id: Option<&Arc<Identity>>,
) -> Option<Identity> {
    if let Some(id) = opt_ext_id {
        tracing::debug!(
            provider_id = %id.provider_id,
            external_id = %id.external_id,
            "resolved caller identity from Extension<Identity>"
        );
        return Some(id.clone());
    }

    if let Some(id) = opt_ext_arc_id {
        tracing::debug!(
            provider_id = %id.provider_id,
            external_id = %id.external_id,
            "resolved caller identity from Extension<Arc<Identity>>"
        );
        return Some((**id).clone());
    }

    if let Some(raw_header) = headers
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

    tracing::debug!("no caller identity found in request extensions or headers");
    None
}

/// Handler for the MCP JSON-RPC 2.0 endpoint (`POST {path}`).
pub async fn axum_mcp_handler<AppState>(
    State(state): State<AppState>,
    headers: HeaderMap,
    opt_id: Option<Extension<Identity>>,
    opt_arc_id: Option<Extension<Arc<Identity>>>,
    body_bytes: Bytes,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Arc<McpRouter>: FromRef<AppState>,
{
    let router = Arc::<McpRouter>::from_ref(&state);
    tracing::debug!("Handling MCP JSON-RPC request (axum)");

    let session_id = headers
        .get("x-session-id")
        .or_else(|| headers.get("mcp-session-id"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let identity = extract_identity(
        &headers,
        opt_id.as_ref().map(|Extension(id)| id),
        opt_arc_id.as_ref().map(|Extension(id)| id),
    );

    let mut rpc_req: JsonRpcRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse JSON-RPC request payload");
            let error_response = serde_json::json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": null,
                "error": JsonRpcError {
                    code: RPC_PARSE_ERROR,
                    message: format!("Parse error: {e}"),
                    data: None,
                }
            });
            return (StatusCode::OK, Json(error_response)).into_response();
        }
    };

    // If client supplied execution token in HTTP header, inject into arguments if tools/call
    if let Some(token_val) = headers
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
                                "injecting approval token from HTTP header into tool arguments"
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

    // Attach RFC 9728 WWW-Authenticate header if response contains authentication/scope error
    let mut resp_headers = HeaderMap::new();
    if let Some(ref err) = rpc_res.error {
        if err.code == RPC_UNAUTHORIZED {
            if err.message.to_lowercase().contains("insufficient scope") {
                tracing::debug!("attaching WWW-Authenticate insufficient_scope header");
                let www_auth = www_authenticate_insufficient_scope(router.metadata_url(), &[]);
                if let Ok(val) = header::HeaderValue::from_str(&www_auth) {
                    resp_headers.insert(header::WWW_AUTHENTICATE, val);
                }
            } else {
                tracing::debug!("attaching WWW-Authenticate unauthorized header");
                let www_auth = www_authenticate_unauthorized(router.metadata_url());
                if let Ok(val) = header::HeaderValue::from_str(&www_auth) {
                    resp_headers.insert(header::WWW_AUTHENTICATE, val);
                }
            }
        }
    }

    (StatusCode::OK, resp_headers, Json(rpc_res)).into_response()
}

/// Handler for the RFC 9728 Protected Resource Metadata endpoint (`GET /.well-known/oauth-protected-resource`).
pub async fn axum_resource_metadata_handler<AppState>(State(state): State<AppState>) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Arc<McpRouter>: FromRef<AppState>,
{
    let router = Arc::<McpRouter>::from_ref(&state);
    tracing::debug!("Handling RFC 9728 Protected Resource Metadata request (axum)");

    let meta = router
        .resource_metadata()
        .cloned()
        .unwrap_or_else(|| ProtectedResourceMetadata::new(router.metadata_url()));

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(meta),
    )
        .into_response()
}

/// Handler for querying a pending approval challenge (`GET /mcp/approve?id=...`).
pub async fn axum_approve_query_handler<AppState>(
    State(state): State<AppState>,
    Query(params): Query<QueryApproveParams>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Arc<McpRouter>: FromRef<AppState>,
{
    let router = Arc::<McpRouter>::from_ref(&state);
    tracing::debug!(params = ?params, "Handling MCP step-up challenge query (axum)");

    let approval_id = match params.id.or(params.approval_id) {
        Some(id) if !id.trim().is_empty() => id,
        _ => {
            tracing::warn!("missing approval id query parameter");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Missing 'id' or 'approval_id' query parameter"
                })),
            )
                .into_response();
        }
    };

    match router.query_pending_approval(&approval_id).await {
        Ok(Some(challenge)) => {
            tracing::info!(approval_id = %approval_id, "found pending approval challenge");
            (StatusCode::OK, Json(challenge)).into_response()
        }
        Ok(None) => {
            tracing::warn!(approval_id = %approval_id, "pending approval challenge not found or expired");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "not_found",
                    "error_description": "Pending approval challenge not found or expired"
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(approval_id = %approval_id, error = %e, "internal error querying approval challenge");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Handler for submitting a step-up approval proof (`POST /mcp/approve`).
pub async fn axum_approve_submit_handler<AppState>(
    State(state): State<AppState>,
    headers: HeaderMap,
    opt_id: Option<Extension<Identity>>,
    opt_arc_id: Option<Extension<Arc<Identity>>>,
    Json(payload): Json<ApprovalSubmissionPayload>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Arc<McpRouter>: FromRef<AppState>,
{
    let router = Arc::<McpRouter>::from_ref(&state);
    tracing::debug!(payload = ?payload, "Handling MCP step-up challenge approval submission (axum)");

    let approval_id = match payload.approval_id.or(payload.id) {
        Some(id) if !id.trim().is_empty() => id,
        _ => {
            tracing::warn!("missing approval id in submission payload");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Missing 'approval_id' or 'id' in submission body"
                })),
            )
                .into_response();
        }
    };

    let identity = match extract_identity(
        &headers,
        opt_id.as_ref().map(|Extension(id)| id),
        opt_arc_id.as_ref().map(|Extension(id)| id),
    ) {
        Some(id) => id,
        None => {
            tracing::warn!(approval_id = %approval_id, "approver identity missing in step-up submission");
            let www_auth = www_authenticate_unauthorized(router.metadata_url());
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, www_auth)],
                Json(serde_json::json!({
                    "error": "unauthorized",
                    "error_description": "Approver identity missing. Authentication required."
                })),
            )
                .into_response();
        }
    };

    match router.approve_challenge(&approval_id, &identity).await {
        Ok(result) => {
            tracing::info!(
                approval_id = %approval_id,
                execution_token = %result.execution_token,
                "step-up challenge approved and execution token minted"
            );
            (StatusCode::OK, Json(result)).into_response()
        }
        Err(McpError::Reproof(err)) => {
            tracing::warn!(approval_id = %approval_id, reproof_error = ?err, "reproof check failed during approval ceremony");
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "reproof_failed",
                    "error_description": format!("Reproof verification failed: {err:?}")
                })),
            )
                .into_response()
        }
        Err(McpError::Unauthorized(msg)) => {
            tracing::warn!(approval_id = %approval_id, error = %msg, "pending challenge not found or unauthorized");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "not_found",
                    "error_description": msg
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(approval_id = %approval_id, error = %e, "internal error during step-up approval ceremony");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Extension trait for creating an Axum router with MCP endpoints.
pub trait McpExt {
    /// Creates an Axum router registering the MCP JSON-RPC endpoint at `{path}`,
    /// RFC 9728 metadata at `/.well-known/oauth-protected-resource`,
    /// and step-up approval endpoints at `/mcp/approve`.
    fn mcp_axum_router<AppState>(&self, path: &str) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Arc<McpRouter>: FromRef<AppState>;
}

impl<T> McpExt for T {
    fn mcp_axum_router<AppState>(&self, path: &str) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Arc<McpRouter>: FromRef<AppState>,
    {
        mcp_axum_router(path)
    }
}

/// Free function to create an Axum router registering:
/// - `POST {path}`: JSON-RPC MCP endpoint (`tools/list`, `tools/call`).
/// - `GET /.well-known/oauth-protected-resource`: RFC 9728 Protected Resource Metadata.
/// - `GET /mcp/approve` and `POST /mcp/approve`: Step-up challenge query and approval submission.
pub fn mcp_axum_router<AppState>(path: &str) -> axum::Router<AppState>
where
    AppState: Clone + Send + Sync + 'static,
    Arc<McpRouter>: FromRef<AppState>,
{
    let clean_path = if path.is_empty() { "/" } else { path };
    let approve_path = if clean_path == "/" || clean_path == "/mcp" {
        "/mcp/approve".to_string()
    } else {
        format!("{}/approve", clean_path.trim_end_matches('/'))
    };

    let mut router = axum::Router::new()
        .route(clean_path, post(axum_mcp_handler::<AppState>))
        .route(
            "/.well-known/oauth-protected-resource",
            get(axum_resource_metadata_handler::<AppState>),
        )
        .route(
            &approve_path,
            get(axum_approve_query_handler::<AppState>)
                .post(axum_approve_submit_handler::<AppState>),
        );

    if approve_path != "/mcp/approve" {
        router = router.route(
            "/mcp/approve",
            get(axum_approve_query_handler::<AppState>)
                .post(axum_approve_submit_handler::<AppState>),
        );
    }

    router
}
