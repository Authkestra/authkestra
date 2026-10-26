use authkestra_axum::{mcp_axum_router, McpExt};
use authkestra_engine::auth::state::Identity;
use authkestra_engine::auth::ReproofRequirement;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_mcp::{
    ApprovalResult, McpRouter, McpSecurityTier, PendingApprovalChallenge,
    ProtectedResourceMetadata, ToolCallResult, ToolContext, ToolDefinition, APPROVAL_TOKEN_ARG_KEY,
    APPROVAL_TOKEN_HEADER, JSONRPC_VERSION, RPC_INVALID_PARAMS, RPC_METHOD_NOT_FOUND,
    RPC_PARAMETER_MISMATCH, RPC_PARSE_ERROR, RPC_STEP_UP_REQUIRED, RPC_TOKEN_REPLAY_OR_EXPIRED,
    RPC_UNAUTHORIZED,
};
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

fn make_identity(scopes: &[&str], auth_time_ago_secs: i64, step_up: bool) -> Identity {
    let mut attrs = HashMap::new();
    attrs.insert("scope".to_string(), scopes.join(" "));
    let now = Utc::now().timestamp();
    attrs.insert(
        "auth_time".to_string(),
        (now - auth_time_ago_secs).to_string(),
    );
    if step_up {
        attrs.insert("step_up_satisfied".to_string(), "true".to_string());
    }

    Identity {
        provider_id: "test_idp".to_string(),
        external_id: "user_test_1".to_string(),
        email: Some("user@example.com".to_string()),
        username: Some("user".to_string()),
        attributes: attrs,
    }
}

fn setup_test_router() -> McpRouter {
    let pending_store = Arc::new(MemoryStore::new());
    let execution_store = Arc::new(MemoryStore::new());

    let echo_tool = ToolDefinition::new(
        "echo",
        json!({"type": "object"}),
        McpSecurityTier::Public,
        |args, _ctx: ToolContext| async move {
            let msg = args["msg"].as_str().unwrap_or("hello");
            Ok(ToolCallResult::text(format!("echo: {msg}")))
        },
    );

    let scoped_tool = ToolDefinition::new(
        "query_weather",
        json!({"type": "object"}),
        McpSecurityTier::Scoped {
            required_scopes: vec!["scope:read".to_string()],
        },
        |args, _ctx: ToolContext| async move {
            let city = args["city"].as_str().unwrap_or("Paris");
            Ok(ToolCallResult::text(format!("weather in {city}: sunny")))
        },
    );

    let human_tool = ToolDefinition::new(
        "execute_transfer",
        json!({"type": "object"}),
        McpSecurityTier::human_approved(
            vec!["scope:transfer"],
            ReproofRequirement::new(60).require_step_up(true),
            120,
        ),
        |args, ctx: ToolContext| async move {
            let recipient = args["recipient"].as_str().unwrap_or("unknown");
            let amount = args["amount"].as_i64().unwrap_or(0);
            let approver = ctx
                .approver_identity
                .map(|i| i.external_id)
                .unwrap_or_else(|| "none".to_string());
            Ok(ToolCallResult::text(format!(
                "transferred {amount} to {recipient} approved_by {approver}"
            )))
        },
    );

    let metadata = ProtectedResourceMetadata::new("https://api.example.com")
        .with_auth_server("https://auth.example.com")
        .with_scopes(vec!["scope:read", "scope:transfer"])
        .with_documentation("https://docs.example.com/mcp");

    McpRouter::builder(pending_store, execution_store)
        .tool(echo_tool)
        .tool(scoped_tool)
        .tool(human_tool)
        .resource_metadata(metadata)
        .build()
}

#[tokio::test]
async fn test_mcp_axum_router_tools_list() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    let req_body = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 1,
        "method": "tools/list",
        "params": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(body_json["jsonrpc"], "2.0");
    assert_eq!(body_json["id"], 1);
    let tools = body_json["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 3);
    assert_eq!(tools[0]["name"], "echo");
    assert_eq!(tools[1]["name"], "execute_transfer");
    assert_eq!(tools[2]["name"], "query_weather");
}

#[tokio::test]
async fn test_mcp_axum_rfc9728_resource_metadata() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(router.mcp_axum_router("/mcp"))
        .with_state(Arc::new(router));

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-protected-resource")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let meta: ProtectedResourceMetadata = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(meta.resource, "https://api.example.com");
    assert_eq!(meta.authorization_servers, vec!["https://auth.example.com"]);
    assert_eq!(meta.scopes_supported, vec!["scope:read", "scope:transfer"]);
}

#[tokio::test]
async fn test_mcp_axum_public_tool_execution() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    let req_body = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "msg": "Axum MCP Works!" }
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(
        body_json["result"]["content"][0]["text"],
        "echo: Axum MCP Works!"
    );
}

#[tokio::test]
async fn test_mcp_axum_scoped_tool_auth_and_forbidden() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "query_weather",
            "arguments": { "city": "London" }
        }
    });

    // 1. Without identity -> Unauthorized with WWW-Authenticate
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&tool_call).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().contains_key(header::WWW_AUTHENTICATE));

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_UNAUTHORIZED);

    // 2. With wrong scope -> Insufficient scope
    let invalid_identity = make_identity(&["scope:wrong"], 10, false);
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(invalid_identity)
        .body(Body::from(serde_json::to_vec(&tool_call).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_UNAUTHORIZED);
    assert!(body_json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Insufficient scope"));

    // 3. With valid scope -> Success
    let valid_identity = make_identity(&["scope:read"], 10, false);
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(valid_identity)
        .body(Body::from(serde_json::to_vec(&tool_call).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        body_json["result"]["content"][0]["text"],
        "weather in London: sunny"
    );
}

#[tokio::test]
async fn test_mcp_axum_human_approved_step_up_ceremony_full_flow() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let approver_identity = make_identity(&["scope:transfer"], 10, true);

    let initial_args = json!({
        "recipient": "alice@example.com",
        "amount": 100
    });

    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 99,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": initial_args
        }
    });

    // Step 1: Initial call -> StepUpRequired elicitation
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "session-xyz")
        .extension(caller_identity.clone())
        .body(Body::from(serde_json::to_vec(&tool_call).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(body_json["error"]["code"], RPC_STEP_UP_REQUIRED);
    let elicitation = &body_json["error"]["data"];
    let approval_id = elicitation["approval_id"].as_str().unwrap().to_string();
    let challenge_digest = elicitation["challenge_digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!approval_id.is_empty());
    assert!(!challenge_digest.is_empty());

    // Step 2: Query pending approval via GET /mcp/approve?id=...
    let req = Request::builder()
        .method("GET")
        .uri(format!("/mcp/approve?id={approval_id}"))
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let challenge: PendingApprovalChallenge = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(challenge.approval_id, approval_id);
    assert_eq!(challenge.tool_name, "execute_transfer");
    assert_eq!(challenge.challenge_digest, challenge_digest);

    // Step 3: Approve challenge via POST /mcp/approve with approver identity
    let approve_payload = json!({
        "approval_id": approval_id
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(approver_identity)
        .body(Body::from(serde_json::to_vec(&approve_payload).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let approval_result: ApprovalResult = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(approval_result.status, "approved");
    let execution_token = approval_result.execution_token;
    assert!(!execution_token.is_empty());

    // Step 4: Replay query on already approved challenge -> returns 404
    let req = Request::builder()
        .method("GET")
        .uri(format!("/mcp/approve?id={approval_id}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Step 5: Retry execution with parameter tampering -> Rejected with ParameterMismatch
    let tampered_args = json!({
        "recipient": "mallory@attacker.com",
        "amount": 100,
        APPROVAL_TOKEN_ARG_KEY: execution_token
    });
    let tampered_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": tampered_args
        }
    });

    // First clone execution token for genuine test
    // Note: because the token is consumed atomically, parameter mismatch will consume or reject:
    // Actually, in router.rs, atomic consume happens first!
    // Let's verify parameter mismatch behavior:
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "session-xyz")
        .extension(caller_identity.clone())
        .body(Body::from(serde_json::to_vec(&tampered_call).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // Step 6: Test replay of consumed token -> TokenReplayOrExpired
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "session-xyz")
        .extension(caller_identity.clone())
        .body(Body::from(serde_json::to_vec(&tampered_call).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_TOKEN_REPLAY_OR_EXPIRED);
}

#[tokio::test]
async fn test_mcp_axum_header_based_approval_token_execution() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let approver_identity = make_identity(&["scope:transfer"], 10, true);

    let initial_args = json!({
        "recipient": "bob@example.com",
        "amount": 250
    });

    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 200,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": initial_args
        }
    });

    // 1. Initial call
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "session-header-test")
        .extension(caller_identity.clone())
        .body(Body::from(serde_json::to_vec(&tool_call).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Approve via POST /mcp/approve
    let approve_payload = json!({ "approval_id": approval_id });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(approver_identity)
        .body(Body::from(serde_json::to_vec(&approve_payload).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let approval_result: ApprovalResult = serde_json::from_slice(&body_bytes).unwrap();
    let execution_token = approval_result.execution_token;

    // 3. Present execution token in x-authkestra-approval-token HTTP header!
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "session-header-test")
        .header(APPROVAL_TOKEN_HEADER, execution_token)
        .extension(caller_identity)
        .body(Body::from(serde_json::to_vec(&tool_call).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        body_json["result"]["content"][0]["text"],
        "transferred 250 to bob@example.com approved_by user_test_1"
    );
}

#[tokio::test]
async fn test_adversarial_axum_rfc9728_schema_and_headers() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    // 1. GET with Accept headers and query params
    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-protected-resource?extra=param&debug=true")
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let ctype = res
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ctype.starts_with("application/json"));

    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let meta: ProtectedResourceMetadata = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(meta.resource, "https://api.example.com");
    assert_eq!(meta.authorization_servers, vec!["https://auth.example.com"]);
    assert_eq!(meta.scopes_supported, vec!["scope:read", "scope:transfer"]);
    assert_eq!(meta.bearer_methods_supported, vec!["header"]);

    // 2. POST to discovery endpoint -> Method Not Allowed (405)
    let req = Request::builder()
        .method("POST")
        .uri("/.well-known/oauth-protected-resource")
        .body(Body::from(b"illegal post body" as &[u8]))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_adversarial_axum_malformed_and_boundary_jsonrpc() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    // 1. Corrupted / non-JSON payload -> returns ParseError (-32700)
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"{ corrupted json payload [" as &[u8]))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["jsonrpc"], "2.0");
    assert_eq!(body_json["error"]["code"], RPC_PARSE_ERROR);

    // 2. Unknown JSON-RPC method -> MethodNotFound (-32601)
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": "req-999",
        "method": "system/shutdown",
        "params": {}
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_METHOD_NOT_FOUND);

    // 3. tools/call with missing params object -> InvalidParams (-32602)
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": "req-998",
        "method": "tools/call"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_INVALID_PARAMS);

    // 4. tools/call referencing non-existent tool -> MethodNotFound (-32601)
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": "req-997",
        "method": "tools/call",
        "params": {
            "name": "ghost_tool_never_registered",
            "arguments": {}
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_METHOD_NOT_FOUND);

    // 5. tools/call with arguments as a non-object (e.g. array) -> InvalidParams (-32602)
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": "req-996",
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": ["invalid", "array", "arguments"]
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_INVALID_PARAMS);
}

#[tokio::test]
async fn test_adversarial_axum_parameter_tampering_variations() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let approver_identity = make_identity(&["scope:transfer"], 10, true);

    let helper_mint_token = |app: Router, args: serde_json::Value, session: &str| {
        let caller_id = caller_identity.clone();
        let approver_id = approver_identity.clone();
        let session_str = session.to_string();
        async move {
            let tool_call = json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "execute_transfer",
                    "arguments": args
                }
            });

            // 1. Elicitation
            let req = Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-session-id", &session_str)
                .extension(caller_id)
                .body(Body::from(serde_json::to_vec(&tool_call).unwrap()))
                .unwrap();

            let res = app.clone().oneshot(req).await.unwrap();
            let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
            assert_eq!(body_json["error"]["code"], RPC_STEP_UP_REQUIRED);
            let approval_id = body_json["error"]["data"]["approval_id"]
                .as_str()
                .unwrap()
                .to_string();

            // 2. Approve
            let approve_payload = json!({ "approval_id": approval_id });
            let req = Request::builder()
                .method("POST")
                .uri("/mcp/approve")
                .header(header::CONTENT_TYPE, "application/json")
                .extension(approver_id)
                .body(Body::from(serde_json::to_vec(&approve_payload).unwrap()))
                .unwrap();

            let res = app.oneshot(req).await.unwrap();
            let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap();
            let approval_result: ApprovalResult = serde_json::from_slice(&body_bytes).unwrap();
            approval_result.execution_token
        }
    };

    let original_args = json!({
        "recipient": "dave@example.com",
        "amount": 100
    });

    // --- Attack Vector 1: Numeric parameter alteration (amount: 100 -> 10000) ---
    let token1 = helper_mint_token(app.clone(), original_args.clone(), "sess-tamper-numeric").await;
    let tampered_num_args = json!({
        "recipient": "dave@example.com",
        "amount": 10000,
        APPROVAL_TOKEN_ARG_KEY: token1
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "sess-tamper-numeric")
        .extension(caller_identity.clone())
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": 10,
                "method": "tools/call",
                "params": { "name": "execute_transfer", "arguments": tampered_num_args }
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // --- Attack Vector 2: String parameter alteration (recipient: dave -> mallory) ---
    let token2 = helper_mint_token(app.clone(), original_args.clone(), "sess-tamper-string").await;
    let tampered_str_args = json!({
        "recipient": "mallory@attacker.com",
        "amount": 100,
        APPROVAL_TOKEN_ARG_KEY: token2
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "sess-tamper-string")
        .extension(caller_identity.clone())
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": 11,
                "method": "tools/call",
                "params": { "name": "execute_transfer", "arguments": tampered_str_args }
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // --- Attack Vector 3: Parameter injection (extra injected parameter) ---
    let token3 = helper_mint_token(app.clone(), original_args.clone(), "sess-tamper-inject").await;
    let injected_args = json!({
        "recipient": "dave@example.com",
        "amount": 100,
        "fee_override": 0,
        APPROVAL_TOKEN_ARG_KEY: token3
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "sess-tamper-inject")
        .extension(caller_identity.clone())
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": 12,
                "method": "tools/call",
                "params": { "name": "execute_transfer", "arguments": injected_args }
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // --- Legitimate JCS Canonicalization: Reordered JSON Keys MUST succeed! ---
    let token4 = helper_mint_token(app.clone(), original_args.clone(), "sess-jcs-reorder").await;
    // Reorder keys: "amount" first, then "recipient"
    let reordered_args = json!({
        "amount": 100,
        "recipient": "dave@example.com",
        APPROVAL_TOKEN_ARG_KEY: token4
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "sess-jcs-reorder")
        .extension(caller_identity)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": 13,
                "method": "tools/call",
                "params": { "name": "execute_transfer", "arguments": reordered_args }
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(
        body_json["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("transferred 100 to dave@example.com"),
        "JCS canonicalization should accept reordered keys without failure"
    );
}

#[tokio::test]
async fn test_adversarial_axum_replay_and_session_binding() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let approver_identity = make_identity(&["scope:transfer"], 10, true);

    let original_args = json!({
        "recipient": "eve@example.com",
        "amount": 300
    });

    // 1. Initial call under session "sess-session-bind"
    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 50,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": original_args
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "sess-session-bind")
        .extension(caller_identity.clone())
        .body(Body::from(serde_json::to_vec(&tool_call).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Approve challenge
    let approve_payload = json!({ "approval_id": approval_id });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(approver_identity)
        .body(Body::from(serde_json::to_vec(&approve_payload).unwrap()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let approval_result: ApprovalResult = serde_json::from_slice(&body_bytes).unwrap();
    let execution_token = approval_result.execution_token;

    // --- Attack Vector: Session Hijacking (presenting token in different session-id) ---
    // Token is bound to "sess-session-bind". Client presents it with "sess-hijacked-attacker"
    let mut session_attack_args = original_args.clone();
    session_attack_args[APPROVAL_TOKEN_ARG_KEY] =
        serde_json::Value::String(execution_token.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "sess-hijacked-attacker")
        .extension(caller_identity.clone())
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": 51,
                "method": "tools/call",
                "params": { "name": "execute_transfer", "arguments": session_attack_args }
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    // Session mismatch triggers ParameterMismatch (and atomically consumes the token)
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // --- Attack Vector: Replaying token after session hijack failure ---
    // The token must now be marked consumed!
    let mut retry_args = original_args.clone();
    retry_args[APPROVAL_TOKEN_ARG_KEY] = serde_json::Value::String(execution_token);
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "sess-session-bind")
        .extension(caller_identity.clone())
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": 52,
                "method": "tools/call",
                "params": { "name": "execute_transfer", "arguments": retry_args }
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_TOKEN_REPLAY_OR_EXPIRED);

    // --- Attack Vector: Forged / Arbitrary Token Injection ---
    let mut forged_args = original_args.clone();
    forged_args[APPROVAL_TOKEN_ARG_KEY] =
        serde_json::Value::String("forged-token-xyz-123".to_string());
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "sess-session-bind")
        .extension(caller_identity)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": 53,
                "method": "tools/call",
                "params": { "name": "execute_transfer", "arguments": forged_args }
            }))
            .unwrap(),
        ))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"]["code"], RPC_TOKEN_REPLAY_OR_EXPIRED);
}

#[tokio::test]
async fn test_adversarial_axum_approve_endpoint_adversarial_inputs() {
    let router = setup_test_router();
    let app = Router::new()
        .merge(mcp_axum_router::<Arc<McpRouter>>("/mcp"))
        .with_state(Arc::new(router));

    // 1. GET /mcp/approve with empty query -> 400 Bad Request
    let req = Request::builder()
        .method("GET")
        .uri("/mcp/approve")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 2. GET /mcp/approve with empty id parameter -> 400 Bad Request
    let req = Request::builder()
        .method("GET")
        .uri("/mcp/approve?id=")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 3. GET /mcp/approve with path traversal string -> 404 Not Found (safe handling)
    let req = Request::builder()
        .method("GET")
        .uri("/mcp/approve?id=../../../../etc/passwd")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // 4. POST /mcp/approve with missing approver identity -> 401 Unauthorized + WWW-Authenticate
    let req = Request::builder()
        .method("POST")
        .uri("/mcp/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "id": "test-id" })).unwrap(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(res.headers().contains_key(header::WWW_AUTHENTICATE));

    // 5. POST /mcp/approve with stale reproof identity (auth_time > 60s ago)
    // Setup a real challenge first
    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 70,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": { "recipient": "test@test.com", "amount": 50 }
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-session-id", "sess-reproof-test")
        .extension(caller_identity)
        .body(Body::from(serde_json::to_vec(&tool_call).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Approver with stale auth_time (120s ago, exceeds 60s max_age)
    let stale_approver = make_identity(&["scope:transfer"], 120, true);
    let req = Request::builder()
        .method("POST")
        .uri("/mcp/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(stale_approver)
        .body(Body::from(
            serde_json::to_vec(&json!({ "approval_id": approval_id })).unwrap(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "reproof_failed");

    // Approver without step_up_satisfied (step_up: false)
    let non_stepup_approver = make_identity(&["scope:transfer"], 10, false);
    let req = Request::builder()
        .method("POST")
        .uri("/mcp/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(non_stepup_approver)
        .body(Body::from(
            serde_json::to_vec(&json!({ "approval_id": approval_id })).unwrap(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "reproof_failed");

    // Approver with fresh step_up -> 200 OK
    let valid_approver = make_identity(&["scope:transfer"], 10, true);
    let req = Request::builder()
        .method("POST")
        .uri("/mcp/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(valid_approver.clone())
        .body(Body::from(
            serde_json::to_vec(&json!({ "approval_id": approval_id })).unwrap(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Double approval attempt -> 404 Not Found
    let req = Request::builder()
        .method("POST")
        .uri("/mcp/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(valid_approver)
        .body(Body::from(
            serde_json::to_vec(&json!({ "approval_id": approval_id })).unwrap(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
