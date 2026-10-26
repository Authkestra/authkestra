#![cfg(feature = "policy")]

use authkestra_engine::auth::state::Identity;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_mcp::{
    JsonRpcRequest, McpError, McpRouter, McpSecurityTier, ToolCallParams, ToolCallResult,
    ToolDefinition, JSONRPC_VERSION, RPC_UNAUTHORIZED,
};
use authkestra_policy::{MemoryResourceLoader, PolicyEngine};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn test_challenger_execute_tool_strictly_unauthorized_on_deny() {
    let policies = r#"
        permit(
            principal == User::"github|alice",
            action == Action::"call",
            resource == Tool::"transfer_funds"
        );
        forbid(
            principal == User::"github|mallory",
            action,
            resource
        );
        forbid(
            principal == User::"anonymous",
            action,
            resource
        );
    "#;

    let loader = MemoryResourceLoader::new();
    let engine = PolicyEngine::builder()
        .policies(policies)
        .loader(loader)
        .build()
        .expect("policy engine build");

    let pending_store = Arc::new(MemoryStore::new());
    let execution_store = Arc::new(MemoryStore::new());

    let transfer_tool = ToolDefinition::new(
        "transfer_funds",
        json!({
            "type": "object",
            "properties": {
                "amount": { "type": "number" },
                "to": { "type": "string" }
            }
        }),
        McpSecurityTier::Public,
        |args, _ctx| async move { Ok(ToolCallResult::text(format!("transferred: {args:?}"))) },
    );

    let router = McpRouter::builder(pending_store, execution_store)
        .tool(transfer_tool)
        .with_policy_engine(Arc::new(engine))
        .build();

    let alice = Identity {
        provider_id: "github".to_string(),
        external_id: "alice".to_string(),
        email: None,
        username: None,
        attributes: Default::default(),
    };

    let mallory = Identity {
        provider_id: "github".to_string(),
        external_id: "mallory".to_string(),
        email: None,
        username: None,
        attributes: Default::default(),
    };

    // 1. Permitted policy on execute_tool executes without hindrance
    let params_alice = ToolCallParams {
        name: "transfer_funds".to_string(),
        arguments: Some(json!({ "amount": 100, "to": "bob" })),
    };
    let result_alice = router
        .execute_tool(params_alice, Some(alice), "sess-alice".to_string())
        .await;
    assert!(
        result_alice.is_ok(),
        "Permitted tool must execute without hindrance"
    );
    let content = result_alice.unwrap().content;
    assert!(!content.is_empty());

    // 2. Denied policy on execute_tool strictly returns McpError::Unauthorized
    let params_mallory = ToolCallParams {
        name: "transfer_funds".to_string(),
        arguments: Some(json!({ "amount": 9999, "to": "mallory" })),
    };
    let result_mallory = router
        .execute_tool(params_mallory, Some(mallory), "sess-mallory".to_string())
        .await;
    assert!(result_mallory.is_err(), "Denied policy must return error");
    match result_mallory.err().unwrap() {
        McpError::Unauthorized(msg) => {
            assert!(
                msg.contains("Tool call 'transfer_funds' was denied by policy"),
                "Expected unauthorized policy message, got: {msg}"
            );
        }
        other => panic!("Expected McpError::Unauthorized, got: {:?}", other),
    }

    // 3. Anonymous caller on execute_tool strictly returns McpError::Unauthorized
    let params_anon = ToolCallParams {
        name: "transfer_funds".to_string(),
        arguments: Some(json!({ "amount": 10, "to": "charlie" })),
    };
    let result_anon = router
        .execute_tool(params_anon, None, "sess-anon".to_string())
        .await;
    assert!(result_anon.is_err(), "Anonymous caller must be denied");
    match result_anon.err().unwrap() {
        McpError::Unauthorized(msg) => {
            assert!(msg.contains("denied by policy"));
        }
        other => panic!(
            "Expected McpError::Unauthorized for anonymous, got: {:?}",
            other
        ),
    }

    // 4. JSON-RPC protocol error mapping: denied policy maps to RPC_UNAUTHORIZED code
    let req_mallory = JsonRpcRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: Some(json!(42)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "transfer_funds",
            "arguments": { "amount": 50 }
        })),
    };
    let rpc_resp = router
        .handle_json_rpc(req_mallory, None, "sess-anon-rpc".to_string())
        .await;
    assert!(rpc_resp.result.is_none());
    let rpc_err = rpc_resp.error.expect("should return JsonRpcError");
    assert_eq!(rpc_err.code, RPC_UNAUTHORIZED);
}
