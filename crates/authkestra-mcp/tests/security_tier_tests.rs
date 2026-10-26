use authkestra_engine::auth::state::Identity;
use authkestra_engine::auth::ReproofRequirement;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_mcp::{
    www_authenticate_insufficient_scope, www_authenticate_unauthorized, JsonRpcRequest, McpError,
    McpRouter, McpSecurityTier, ProtectedResourceMetadata, ToolCallParams, ToolCallResult,
    ToolContext, ToolDefinition, JSONRPC_VERSION, RPC_INVALID_PARAMS, RPC_INVALID_REQUEST,
    RPC_METHOD_NOT_FOUND,
};
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn make_identity_with_attrs(attrs: Vec<(&str, &str)>) -> Identity {
    let mut map = HashMap::new();
    for (k, v) in attrs {
        map.insert(k.to_string(), v.to_string());
    }

    Identity {
        provider_id: "test_idp".to_string(),
        external_id: "user_42".to_string(),
        email: Some("user42@example.com".to_string()),
        username: Some("user42".to_string()),
        attributes: map,
    }
}

fn setup_full_router() -> McpRouter {
    let pending_store = Arc::new(MemoryStore::new());
    let execution_store = Arc::new(MemoryStore::new());

    let public_tool = ToolDefinition::new(
        "public_echo",
        json!({"type": "object"}),
        McpSecurityTier::Public,
        |args, _ctx: ToolContext| async move {
            let msg = args["msg"].as_str().unwrap_or("hello");
            Ok(ToolCallResult::text(format!("echo: {msg}")))
        },
    );

    let scoped_tool = ToolDefinition::new(
        "read_profile",
        json!({"type": "object"}),
        McpSecurityTier::Scoped {
            required_scopes: vec!["profile:read".to_string()],
        },
        |_args, ctx: ToolContext| async move {
            let username = ctx
                .identity
                .map(|i| i.username.unwrap_or_default())
                .unwrap_or_default();
            Ok(ToolCallResult::text(format!("profile for {username}")))
        },
    );

    let human_tool = ToolDefinition::new(
        "delete_database",
        json!({"type": "object"}),
        McpSecurityTier::human_approved(
            vec!["admin:db"],
            ReproofRequirement::new(60).require_step_up(true),
            120,
        ),
        |_args, _ctx: ToolContext| async move { Ok(ToolCallResult::text("database deleted")) },
    );

    let metadata = ProtectedResourceMetadata::new("https://api.example.com")
        .with_auth_server("https://auth.example.com")
        .with_scopes(vec!["profile:read", "admin:db"])
        .with_documentation("https://docs.authkestra.com/mcp");

    McpRouter::builder(pending_store, execution_store)
        .tool(public_tool)
        .tool(scoped_tool)
        .tool(human_tool)
        .resource_metadata(metadata)
        .build()
}

#[tokio::test]
async fn test_public_tier_permissive_access() {
    let router = setup_full_router();
    let session = "sess_pub".to_string();

    // 1. Without identity
    let res = router
        .execute_tool(
            ToolCallParams {
                name: "public_echo".to_string(),
                arguments: Some(json!({"msg": "world"})),
            },
            None,
            session.clone(),
        )
        .await
        .expect("public tool succeeds without identity");

    assert_eq!(res.content[0].text, "echo: world");

    // 2. With identity
    let identity = make_identity_with_attrs(vec![]);
    let res = router
        .execute_tool(
            ToolCallParams {
                name: "public_echo".to_string(),
                arguments: Some(json!({"msg": "with identity"})),
            },
            Some(identity),
            session,
        )
        .await
        .expect("public tool succeeds with identity");

    assert_eq!(res.content[0].text, "echo: with identity");
}

#[tokio::test]
async fn test_scoped_tier_unauthorized_when_identity_missing() {
    let router = setup_full_router();
    let session = "sess_scoped_unauth".to_string();

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "read_profile".to_string(),
                arguments: None,
            },
            None,
            session,
        )
        .await
        .expect_err("scoped tool must reject unauthenticated call");

    assert!(matches!(err, McpError::Unauthorized(_)));
}

#[tokio::test]
async fn test_scoped_tier_forbidden_when_insufficient_scope() {
    let router = setup_full_router();
    let session = "sess_scoped_forbidden".to_string();

    // Identity has scope "other:scope", but tool requires "profile:read"
    let identity = make_identity_with_attrs(vec![("scope", "other:scope")]);

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "read_profile".to_string(),
                arguments: None,
            },
            Some(identity),
            session,
        )
        .await
        .expect_err("scoped tool must reject missing scopes");

    match err {
        McpError::Forbidden { required } => {
            assert_eq!(required, vec!["profile:read".to_string()]);
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

#[tokio::test]
async fn test_scoped_tier_success_when_scope_present() {
    let router = setup_full_router();
    let session = "sess_scoped_ok".to_string();

    let identity = make_identity_with_attrs(vec![("scope", "user profile:read email")]);

    let res = router
        .execute_tool(
            ToolCallParams {
                name: "read_profile".to_string(),
                arguments: None,
            },
            Some(identity),
            session,
        )
        .await
        .expect("scoped tool succeeds with valid scope");

    assert_eq!(res.content[0].text, "profile for user42");
}

#[tokio::test]
async fn test_reproof_verification_in_approval_ceremony() {
    let router = setup_full_router();
    let session = "sess_reproof".to_string();
    let caller = make_identity_with_attrs(vec![("scope", "admin:db")]);

    // Initial call produces challenge
    let err = router
        .execute_tool(
            ToolCallParams {
                name: "delete_database".to_string(),
                arguments: Some(json!({})),
            },
            Some(caller),
            session,
        )
        .await
        .unwrap_err();

    let approval_id = match err {
        McpError::StepUpRequired(e) => e.approval_id,
        other => panic!("expected StepUpRequired, got {other:?}"),
    };

    // Case 1: Human lacks auth_time -> fails Reproof
    let human_no_auth_time = make_identity_with_attrs(vec![("step_up_satisfied", "true")]);
    let err1 = router
        .approve_challenge(&approval_id, &human_no_auth_time)
        .await
        .expect_err("missing auth_time must fail reproof");
    assert!(matches!(err1, McpError::Reproof(_)));

    // Case 2: Human has stale auth_time (older than 60 seconds) -> fails Reproof
    let stale_time = (Utc::now().timestamp() - 120).to_string();
    let human_stale = make_identity_with_attrs(vec![
        ("auth_time", &stale_time),
        ("step_up_satisfied", "true"),
    ]);
    let err2 = router
        .approve_challenge(&approval_id, &human_stale)
        .await
        .expect_err("stale auth_time must fail reproof");
    assert!(matches!(err2, McpError::Reproof(_)));

    // Case 3: Human has fresh auth_time but step_up_satisfied is false/missing -> fails Reproof
    let fresh_time = Utc::now().timestamp().to_string();
    let human_no_step_up = make_identity_with_attrs(vec![("auth_time", &fresh_time)]);
    let err3 = router
        .approve_challenge(&approval_id, &human_no_step_up)
        .await
        .expect_err("missing step-up flag must fail reproof");
    assert!(matches!(err3, McpError::Reproof(_)));

    // Case 4: Human has fresh auth_time and step_up_satisfied is true -> SUCCEEDS!
    let human_fresh = make_identity_with_attrs(vec![
        ("auth_time", &fresh_time),
        ("step_up_satisfied", "true"),
    ]);
    let approval = router
        .approve_challenge(&approval_id, &human_fresh)
        .await
        .expect("fresh reproof with step-up succeeds");

    assert_eq!(approval.status, "approved");
    assert!(!approval.execution_token.is_empty());
}

#[tokio::test]
async fn test_tools_list_enumeration_sorted() {
    let router = setup_full_router();
    let req = JsonRpcRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: Some(json!(1)),
        method: "tools/list".to_string(),
        params: None,
    };

    let resp = router
        .handle_json_rpc(req, None, "sess_list".to_string())
        .await;
    assert!(resp.error.is_none());

    let result = resp.result.unwrap();
    let tools = result["tools"].as_array().unwrap();

    assert_eq!(tools.len(), 3);
    // Verified sorted order: delete_database < public_echo < read_profile
    assert_eq!(tools[0]["name"], "delete_database");
    assert_eq!(tools[1]["name"], "public_echo");
    assert_eq!(tools[2]["name"], "read_profile");
}

#[tokio::test]
async fn test_unknown_method_and_unknown_tool_errors() {
    let router = setup_full_router();

    // Unknown method
    let req_unknown_method = JsonRpcRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: Some(json!(2)),
        method: "resources/list".to_string(),
        params: None,
    };
    let resp = router
        .handle_json_rpc(req_unknown_method, None, "s".to_string())
        .await;
    assert_eq!(resp.error.unwrap().code, RPC_METHOD_NOT_FOUND);

    // Unknown tool
    let req_unknown_tool = JsonRpcRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: Some(json!(3)),
        method: "tools/call".to_string(),
        params: Some(json!({"name": "non_existent_tool"})),
    };
    let resp = router
        .handle_json_rpc(req_unknown_tool, None, "s".to_string())
        .await;
    assert_eq!(resp.error.unwrap().code, RPC_METHOD_NOT_FOUND);

    // Invalid params
    let req_invalid_params = JsonRpcRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: Some(json!(4)),
        method: "tools/call".to_string(),
        params: None,
    };
    let resp = router
        .handle_json_rpc(req_invalid_params, None, "s".to_string())
        .await;
    assert_eq!(resp.error.unwrap().code, RPC_INVALID_PARAMS);

    // Invalid JSON-RPC version
    let req_bad_version = JsonRpcRequest {
        jsonrpc: "1.0".to_string(),
        id: Some(json!(5)),
        method: "tools/list".to_string(),
        params: None,
    };
    let resp = router
        .handle_json_rpc(req_bad_version, None, "s".to_string())
        .await;
    assert_eq!(resp.error.unwrap().code, RPC_INVALID_REQUEST);
}

#[test]
fn test_rfc9728_resource_metadata_and_headers() {
    let metadata = ProtectedResourceMetadata::new("https://mcp.authkestra.com")
        .with_auth_server("https://auth.authkestra.com")
        .with_scopes(vec!["mcp:read", "mcp:write"])
        .with_documentation("https://docs.authkestra.com/mcp")
        .with_name("Authkestra MCP Server");

    let json_val = serde_json::to_value(&metadata).unwrap();
    assert_eq!(json_val["resource"], "https://mcp.authkestra.com");
    assert_eq!(
        json_val["authorization_servers"][0],
        "https://auth.authkestra.com"
    );
    assert_eq!(json_val["scopes_supported"][0], "mcp:read");
    assert_eq!(json_val["scopes_supported"][1], "mcp:write");
    assert_eq!(json_val["bearer_methods_supported"][0], "header");
    assert_eq!(json_val["resource_name"], "Authkestra MCP Server");

    // Test WWW-Authenticate header formatting
    let unauth_header = www_authenticate_unauthorized(
        "https://mcp.authkestra.com/.well-known/oauth-protected-resource",
    );
    assert_eq!(
        unauth_header,
        r#"Bearer resource_metadata="https://mcp.authkestra.com/.well-known/oauth-protected-resource""#
    );

    let ins_scope_header = www_authenticate_insufficient_scope(
        "https://mcp.authkestra.com/.well-known/oauth-protected-resource",
        &["mcp:write".to_string(), "admin".to_string()],
    );
    assert_eq!(
        ins_scope_header,
        r#"Bearer error="insufficient_scope", scope="mcp:write admin", resource_metadata="https://mcp.authkestra.com/.well-known/oauth-protected-resource""#
    );
}
