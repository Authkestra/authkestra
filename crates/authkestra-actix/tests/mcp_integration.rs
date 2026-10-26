use actix_web::{
    http::{header, StatusCode},
    test, web, App,
};
use authkestra_actix::{mcp_actix_scope, McpExt};
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
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

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
        external_id: "actix_user_1".to_string(),
        email: Some("actix@example.com".to_string()),
        username: Some("actix_user".to_string()),
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
            let city = args["city"].as_str().unwrap_or("Berlin");
            Ok(ToolCallResult::text(format!("weather in {city}: cloudy")))
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

    let metadata = ProtectedResourceMetadata::new("https://actix.example.com")
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

#[actix_web::test]
async fn test_mcp_actix_scope_tools_list() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    let req_body = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 1,
        "method": "tools/list",
        "params": {}
    });

    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_json(&req_body)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);

    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["jsonrpc"], "2.0");
    assert_eq!(body_json["id"], 1);
    let tools = body_json["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 3);
}

#[actix_web::test]
async fn test_mcp_actix_rfc9728_resource_metadata() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router.clone())))
            .service(router.mcp_actix_scope(""))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/.well-known/oauth-protected-resource")
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );

    let meta: ProtectedResourceMetadata = test::read_body_json(res).await;
    assert_eq!(meta.resource, "https://actix.example.com");
    assert_eq!(meta.authorization_servers, vec!["https://auth.example.com"]);
    assert_eq!(meta.scopes_supported, vec!["scope:read", "scope:transfer"]);
}

#[actix_web::test]
async fn test_mcp_actix_public_tool_execution() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    let req_body = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 55,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "msg": "Actix MCP Works!" }
        }
    });

    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_json(&req_body)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);

    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(
        body_json["result"]["content"][0]["text"],
        "echo: Actix MCP Works!"
    );
}

#[actix_web::test]
async fn test_mcp_actix_scoped_tool_auth_and_forbidden() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 22,
        "method": "tools/call",
        "params": {
            "name": "query_weather",
            "arguments": { "city": "Berlin" }
        }
    });

    // 1. Without identity -> Unauthorized with WWW-Authenticate
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_json(&tool_call)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().contains_key(header::WWW_AUTHENTICATE));

    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_UNAUTHORIZED);

    // 2. With wrong scope -> Insufficient scope
    let invalid_identity = make_identity(&["scope:wrong"], 10, false);
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((
            "x-authkestra-identity",
            serde_json::to_string(&invalid_identity).unwrap(),
        ))
        .set_json(&tool_call)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_UNAUTHORIZED);
    assert!(body_json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Insufficient scope"));

    // 3. With valid scope -> Success
    let valid_identity = make_identity(&["scope:read"], 10, false);
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((
            "x-authkestra-identity",
            serde_json::to_string(&valid_identity).unwrap(),
        ))
        .set_json(&tool_call)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(
        body_json["result"]["content"][0]["text"],
        "weather in Berlin: cloudy"
    );
}

#[actix_web::test]
async fn test_mcp_actix_human_approved_step_up_ceremony_full_flow() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let approver_identity = make_identity(&["scope:transfer"], 10, true);

    let initial_args = json!({
        "recipient": "carol@example.com",
        "amount": 500
    });

    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 88,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": initial_args
        }
    });

    // Step 1: Initial call -> StepUpRequired elicitation
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-123"))
        .insert_header((
            "x-authkestra-identity",
            serde_json::to_string(&caller_identity).unwrap(),
        ))
        .set_json(&tool_call)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);

    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_STEP_UP_REQUIRED);
    let elicitation = &body_json["error"]["data"];
    let approval_id = elicitation["approval_id"].as_str().unwrap().to_string();
    let challenge_digest = elicitation["challenge_digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!approval_id.is_empty());

    // Step 2: Query pending approval via GET /mcp/approve?id=...
    let req = test::TestRequest::get()
        .uri(&format!("/mcp/approve?id={approval_id}"))
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);

    let challenge: PendingApprovalChallenge = test::read_body_json(res).await;
    assert_eq!(challenge.approval_id, approval_id);
    assert_eq!(challenge.tool_name, "execute_transfer");
    assert_eq!(challenge.challenge_digest, challenge_digest);

    // Step 3: Approve challenge via POST /mcp/approve with approver identity
    let approve_payload = json!({
        "approval_id": approval_id
    });

    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((
            "x-authkestra-identity",
            serde_json::to_string(&approver_identity).unwrap(),
        ))
        .set_json(&approve_payload)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);

    let approval_result: ApprovalResult = test::read_body_json(res).await;
    assert_eq!(approval_result.status, "approved");
    let execution_token = approval_result.execution_token;
    assert!(!execution_token.is_empty());

    // Step 4: Replay query on approved challenge -> returns 404
    let req = test::TestRequest::get()
        .uri(&format!("/mcp/approve?id={approval_id}"))
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Step 5: Retry execution with parameter tampering -> Rejected with ParameterMismatch
    let tampered_args = json!({
        "recipient": "mallory@attacker.com",
        "amount": 500,
        APPROVAL_TOKEN_ARG_KEY: execution_token
    });
    let tampered_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 105,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": tampered_args
        }
    });

    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-123"))
        .insert_header((
            "x-authkestra-identity",
            serde_json::to_string(&caller_identity).unwrap(),
        ))
        .set_json(&tampered_call)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // Step 6: Test replay of consumed token -> TokenReplayOrExpired
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-123"))
        .insert_header((
            "x-authkestra-identity",
            serde_json::to_string(&caller_identity).unwrap(),
        ))
        .set_json(&tampered_call)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_TOKEN_REPLAY_OR_EXPIRED);
}

#[actix_web::test]
async fn test_mcp_actix_header_based_approval_token_execution() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let approver_identity = make_identity(&["scope:transfer"], 10, true);

    let initial_args = json!({
        "recipient": "dave@example.com",
        "amount": 750
    });

    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 300,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": initial_args
        }
    });

    // 1. Initial call -> StepUpRequired
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-header"))
        .insert_header((
            "x-authkestra-identity",
            serde_json::to_string(&caller_identity).unwrap(),
        ))
        .set_json(&tool_call)
        .to_request();

    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Approve via POST /mcp/approve
    let approve_payload = json!({ "approval_id": approval_id });
    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((
            "x-authkestra-identity",
            serde_json::to_string(&approver_identity).unwrap(),
        ))
        .set_json(&approve_payload)
        .to_request();

    let res = test::call_service(&app, req).await;
    let approval_result: ApprovalResult = test::read_body_json(res).await;
    let execution_token = approval_result.execution_token;

    // 3. Present execution token in x-authkestra-approval-token HTTP header!
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-header"))
        .insert_header((APPROVAL_TOKEN_HEADER, execution_token))
        .insert_header((
            "x-authkestra-identity",
            serde_json::to_string(&caller_identity).unwrap(),
        ))
        .set_json(&tool_call)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);

    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(
        body_json["result"]["content"][0]["text"],
        "transferred 750 to dave@example.com approved_by actix_user_1"
    );
}

#[actix_web::test]
async fn test_adversarial_actix_rfc9728_schema_and_headers() {
    let router = setup_test_router();

    // 1. Root scope: App mounted with mcp_actix_scope("") serves RFC 9728 at standard root
    let root_app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router.clone())))
            .service(mcp_actix_scope("")),
    )
    .await;

    // GET with Accept headers and query params at standard root
    let req = test::TestRequest::get()
        .uri("/.well-known/oauth-protected-resource?extra=param&debug=true")
        .insert_header((header::ACCEPT, "application/json, text/plain, */*"))
        .to_request();

    let res = test::call_service(&root_app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let ctype = res
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ctype.starts_with("application/json"));

    let meta: ProtectedResourceMetadata = test::read_body_json(res).await;
    assert_eq!(meta.resource, "https://actix.example.com");
    assert_eq!(meta.authorization_servers, vec!["https://auth.example.com"]);
    assert_eq!(meta.scopes_supported, vec!["scope:read", "scope:transfer"]);
    assert_eq!(meta.bearer_methods_supported, vec!["header"]);

    // POST to discovery endpoint -> Method Not Allowed (405)
    let req = test::TestRequest::post()
        .uri("/.well-known/oauth-protected-resource")
        .set_payload(b"illegal post body" as &[u8])
        .to_request();

    let res = test::call_service(&root_app, req).await;
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);

    // 2. Prefixed scope: App mounted ONLY with mcp_actix_scope("/mcp")
    // Due to Actix Scope prefix isolation, discovery is prefixed under /mcp/.well-known/...
    let prefixed_app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    // Root /.well-known/... returns 404 because Scope("/mcp") only intercepts /mcp/*
    let req = test::TestRequest::get()
        .uri("/.well-known/oauth-protected-resource")
        .to_request();
    let res = test::call_service(&prefixed_app, req).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Prefixed path returns 200
    let req = test::TestRequest::get()
        .uri("/mcp/.well-known/oauth-protected-resource")
        .to_request();
    let res = test::call_service(&prefixed_app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_adversarial_actix_malformed_and_boundary_jsonrpc() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    // 1. Corrupted / non-JSON payload -> returns ParseError (-32700)
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(b"{ corrupted json payload [" as &[u8])
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["jsonrpc"], "2.0");
    assert_eq!(body_json["error"]["code"], RPC_PARSE_ERROR);

    // 2. Unknown JSON-RPC method -> MethodNotFound (-32601)
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": "actix-req-999",
        "method": "system/shutdown",
        "params": {}
    });
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_json(&req_body)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_METHOD_NOT_FOUND);

    // 3. tools/call with missing params object -> InvalidParams (-32602)
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": "actix-req-998",
        "method": "tools/call"
    });
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_json(&req_body)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_INVALID_PARAMS);

    // 4. tools/call referencing non-existent tool -> MethodNotFound (-32601)
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": "actix-req-997",
        "method": "tools/call",
        "params": {
            "name": "ghost_tool_never_registered",
            "arguments": {}
        }
    });
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_json(&req_body)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_METHOD_NOT_FOUND);

    // 5. tools/call with arguments as a non-object (e.g. array) -> InvalidParams (-32602)
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": "actix-req-996",
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": ["invalid", "array", "arguments"]
        }
    });
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_json(&req_body)
        .to_request();

    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_INVALID_PARAMS);
}

#[actix_web::test]
async fn test_adversarial_actix_parameter_tampering_variations() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let approver_identity = make_identity(&["scope:transfer"], 10, true);

    let original_args = json!({
        "recipient": "erin@example.com",
        "amount": 200
    });

    // Helper to generate a fresh approval token
    let helper_mint = |args: serde_json::Value, sess: &str| {
        let caller_str = serde_json::to_string(&caller_identity).unwrap();
        let approver_str = serde_json::to_string(&approver_identity).unwrap();
        let sess_str = sess.to_string();
        let tool_call = json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "execute_transfer",
                "arguments": args
            }
        });
        (tool_call, caller_str, approver_str, sess_str)
    };

    // 1. Numeric tampering
    let (call, caller_str, approver_str, sess_str) =
        helper_mint(original_args.clone(), "actix-tamper-num");
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", sess_str.as_str()))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&call)
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-authkestra-identity", approver_str.as_str()))
        .set_json(&json!({ "approval_id": approval_id }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let approval_res: ApprovalResult = test::read_body_json(res).await;
    let token1 = approval_res.execution_token;

    // Present tampered amount
    let tampered_num_args = json!({
        "recipient": "erin@example.com",
        "amount": 20000,
        APPROVAL_TOKEN_ARG_KEY: token1
    });
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", sess_str.as_str()))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 10,
            "method": "tools/call",
            "params": { "name": "execute_transfer", "arguments": tampered_num_args }
        }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // 2. String tampering
    let (call, caller_str, approver_str, sess_str) =
        helper_mint(original_args.clone(), "actix-tamper-str");
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", sess_str.as_str()))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&call)
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-authkestra-identity", approver_str.as_str()))
        .set_json(&json!({ "approval_id": approval_id }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let approval_res: ApprovalResult = test::read_body_json(res).await;
    let token2 = approval_res.execution_token;

    let tampered_str_args = json!({
        "recipient": "mallory@attacker.com",
        "amount": 200,
        APPROVAL_TOKEN_ARG_KEY: token2
    });
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", sess_str.as_str()))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 11,
            "method": "tools/call",
            "params": { "name": "execute_transfer", "arguments": tampered_str_args }
        }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // 3. Extra parameter injection
    let (call, caller_str, approver_str, sess_str) =
        helper_mint(original_args.clone(), "actix-tamper-inj");
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", sess_str.as_str()))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&call)
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-authkestra-identity", approver_str.as_str()))
        .set_json(&json!({ "approval_id": approval_id }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let approval_res: ApprovalResult = test::read_body_json(res).await;
    let token3 = approval_res.execution_token;

    let injected_args = json!({
        "recipient": "erin@example.com",
        "amount": 200,
        "unauthorized_fee": 0,
        APPROVAL_TOKEN_ARG_KEY: token3
    });
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", sess_str.as_str()))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 12,
            "method": "tools/call",
            "params": { "name": "execute_transfer", "arguments": injected_args }
        }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // 4. JCS Key Reordering Test
    let (call, caller_str, approver_str, sess_str) =
        helper_mint(original_args.clone(), "actix-jcs-reorder");
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", sess_str.as_str()))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&call)
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-authkestra-identity", approver_str.as_str()))
        .set_json(&json!({ "approval_id": approval_id }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let approval_res: ApprovalResult = test::read_body_json(res).await;
    let token4 = approval_res.execution_token;

    let reordered_args = json!({
        "amount": 200,
        "recipient": "erin@example.com",
        APPROVAL_TOKEN_ARG_KEY: token4
    });
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", sess_str.as_str()))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 13,
            "method": "tools/call",
            "params": { "name": "execute_transfer", "arguments": reordered_args }
        }))
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert!(
        body_json["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("transferred 200 to erin@example.com"),
        "JCS canonicalization in Actix should accept reordered keys without failure"
    );
}

#[actix_web::test]
async fn test_adversarial_actix_replay_and_session_binding() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let approver_identity = make_identity(&["scope:transfer"], 10, true);
    let caller_str = serde_json::to_string(&caller_identity).unwrap();
    let approver_str = serde_json::to_string(&approver_identity).unwrap();

    let original_args = json!({
        "recipient": "frank@example.com",
        "amount": 400
    });

    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 60,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": original_args
        }
    });

    // 1. Initial call under session "actix-sess-bind"
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-bind"))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&tool_call)
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Approve challenge
    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-authkestra-identity", approver_str.as_str()))
        .set_json(&json!({ "approval_id": approval_id }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let approval_res: ApprovalResult = test::read_body_json(res).await;
    let execution_token = approval_res.execution_token;

    // --- Attack: Session Hijacking (presenting token in different session-id) ---
    let mut session_attack_args = original_args.clone();
    session_attack_args[APPROVAL_TOKEN_ARG_KEY] =
        serde_json::Value::String(execution_token.clone());

    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-hijacked-attacker"))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 61,
            "method": "tools/call",
            "params": { "name": "execute_transfer", "arguments": session_attack_args }
        }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_PARAMETER_MISMATCH);

    // --- Attack: Replaying token after session hijack failure ---
    let mut retry_args = original_args.clone();
    retry_args[APPROVAL_TOKEN_ARG_KEY] = serde_json::Value::String(execution_token);
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-bind"))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 62,
            "method": "tools/call",
            "params": { "name": "execute_transfer", "arguments": retry_args }
        }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_TOKEN_REPLAY_OR_EXPIRED);

    // --- Attack: Forged / Arbitrary Token Injection ---
    let mut forged_args = original_args.clone();
    forged_args[APPROVAL_TOKEN_ARG_KEY] =
        serde_json::Value::String("forged-actix-token-xyz".to_string());
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-bind"))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 63,
            "method": "tools/call",
            "params": { "name": "execute_transfer", "arguments": forged_args }
        }))
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"]["code"], RPC_TOKEN_REPLAY_OR_EXPIRED);
}

#[actix_web::test]
async fn test_adversarial_actix_approve_endpoint_adversarial_inputs() {
    let router = setup_test_router();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(Arc::new(router)))
            .service(mcp_actix_scope("/mcp")),
    )
    .await;

    // 1. GET /mcp/approve with empty query -> 400 Bad Request
    let req = test::TestRequest::get().uri("/mcp/approve").to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 2. GET /mcp/approve with empty id parameter -> 400 Bad Request
    let req = test::TestRequest::get()
        .uri("/mcp/approve?id=")
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 3. GET /mcp/approve with path traversal string -> 404 Not Found (safe handling)
    let req = test::TestRequest::get()
        .uri("/mcp/approve?id=../../../../etc/passwd")
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // 4. POST /mcp/approve with missing approver identity -> 401 Unauthorized + WWW-Authenticate
    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_json(&json!({ "id": "test-id" }))
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(res.headers().contains_key(header::WWW_AUTHENTICATE));

    // 5. POST /mcp/approve with stale reproof identity (auth_time > 60s ago)
    let caller_identity = make_identity(&["scope:transfer"], 500, false);
    let caller_str = serde_json::to_string(&caller_identity).unwrap();
    let tool_call = json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 75,
        "method": "tools/call",
        "params": {
            "name": "execute_transfer",
            "arguments": { "recipient": "test@test.com", "amount": 60 }
        }
    });
    let req = test::TestRequest::post()
        .uri("/mcp")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-session-id", "actix-sess-reproof"))
        .insert_header(("x-authkestra-identity", caller_str.as_str()))
        .set_json(&tool_call)
        .to_request();
    let res = test::call_service(&app, req).await;
    let body_json: serde_json::Value = test::read_body_json(res).await;
    let approval_id = body_json["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Approver with stale auth_time (120s ago, exceeds 60s max_age)
    let stale_approver = make_identity(&["scope:transfer"], 120, true);
    let stale_str = serde_json::to_string(&stale_approver).unwrap();
    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-authkestra-identity", stale_str.as_str()))
        .set_json(&json!({ "approval_id": approval_id }))
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"], "reproof_failed");

    // Approver without step_up_satisfied (step_up: false)
    let non_stepup_approver = make_identity(&["scope:transfer"], 10, false);
    let non_stepup_str = serde_json::to_string(&non_stepup_approver).unwrap();
    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-authkestra-identity", non_stepup_str.as_str()))
        .set_json(&json!({ "approval_id": approval_id }))
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body_json: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(body_json["error"], "reproof_failed");

    // Approver with fresh step_up -> 200 OK
    let valid_approver = make_identity(&["scope:transfer"], 10, true);
    let valid_str = serde_json::to_string(&valid_approver).unwrap();
    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-authkestra-identity", valid_str.as_str()))
        .set_json(&json!({ "approval_id": approval_id }))
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::OK);

    // Double approval attempt -> 404 Not Found
    let req = test::TestRequest::post()
        .uri("/mcp/approve")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-authkestra-identity", valid_str.as_str()))
        .set_json(&json!({ "approval_id": approval_id }))
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
