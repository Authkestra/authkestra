#![cfg(feature = "policy")]

use authkestra_engine::auth::state::Identity;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_mcp::{
    JsonRpcRequest, McpRouter, McpSecurityTier, ToolCallResult, ToolDefinition, JSONRPC_VERSION,
    RPC_UNAUTHORIZED,
};
use authkestra_policy::{MemoryResourceLoader, PolicyEngine};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn test_mcp_router_cedar_policy_permit_and_deny() {
    let policies = r#"
        permit(
            principal == User::"github|alice",
            action == Action::"call",
            resource == Tool::"admin_tool"
        );
        forbid(
            principal == User::"github|bob",
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

    let admin_tool = ToolDefinition::new(
        "admin_tool",
        json!({ "type": "object" }),
        McpSecurityTier::Public,
        |args, _ctx| async move { Ok(ToolCallResult::text(format!("admin executed: {args:?}"))) },
    );

    let router = McpRouter::builder(pending_store, execution_store)
        .tool(admin_tool)
        .with_policy_engine(Arc::new(engine))
        .build();

    let alice = Identity {
        provider_id: "github".to_string(),
        external_id: "alice".to_string(),
        email: None,
        username: None,
        attributes: Default::default(),
    };

    let bob = Identity {
        provider_id: "github".to_string(),
        external_id: "bob".to_string(),
        email: None,
        username: None,
        attributes: Default::default(),
    };

    // Alice calls admin_tool -> Allowed
    let req_alice = JsonRpcRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "admin_tool",
            "arguments": { "foo": "bar" }
        })),
    };
    let resp_alice = router
        .handle_json_rpc(req_alice, Some(alice), "session-1".to_string())
        .await;
    assert!(resp_alice.error.is_none());
    assert!(resp_alice.result.is_some());

    // Bob calls admin_tool -> Forbidden by Cedar policy (error code RPC_UNAUTHORIZED)
    let req_bob = JsonRpcRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: Some(json!(2)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "admin_tool",
            "arguments": { "foo": "bar" }
        })),
    };
    let resp_bob = router
        .handle_json_rpc(req_bob, Some(bob), "session-2".to_string())
        .await;
    assert!(resp_bob.result.is_none());
    let err = resp_bob.error.expect("should return error");
    assert_eq!(err.code, RPC_UNAUTHORIZED);
    assert!(err.message.contains("denied by policy"));
}
