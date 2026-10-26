use authkestra_engine::auth::state::Identity;
use authkestra_engine::auth::ReproofRequirement;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_mcp::{
    McpError, McpRouter, McpSecurityTier, ToolCallParams, ToolCallResult, ToolContext,
    ToolDefinition, APPROVAL_TOKEN_ARG_KEY,
};
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn make_human_identity(user_id: &str) -> Identity {
    let mut attributes = HashMap::new();
    attributes.insert("auth_time".to_string(), Utc::now().timestamp().to_string());
    attributes.insert("step_up_satisfied".to_string(), "true".to_string());
    attributes.insert("scope".to_string(), "orders:create".to_string());

    Identity {
        provider_id: "authkestra_idp".to_string(),
        external_id: user_id.to_string(),
        email: Some(format!("{user_id}@example.com")),
        username: Some(user_id.to_string()),
        attributes,
    }
}

fn create_test_router() -> McpRouter {
    let pending_store = Arc::new(MemoryStore::new());
    let execution_store = Arc::new(MemoryStore::new());

    let order_tool = ToolDefinition::new(
        "create_order",
        json!({
            "type": "object",
            "properties": {
                "item_id": { "type": "string" },
                "quantity": { "type": "integer" }
            },
            "required": ["item_id", "quantity"]
        }),
        McpSecurityTier::human_approved(vec!["orders:create"], ReproofRequirement::new(300), 300),
        |args, _ctx: ToolContext| async move {
            let item_id = args["item_id"].as_str().unwrap_or("unknown");
            let qty = args["quantity"].as_i64().unwrap_or(0);
            Ok(ToolCallResult::text(format!("ordered {qty} of {item_id}")))
        },
    );

    McpRouter::builder(pending_store, execution_store)
        .tool(order_tool)
        .build()
}

#[tokio::test]
async fn test_sequential_replay_rejected() {
    let router = create_test_router();
    let caller = make_human_identity("caller_1");
    let human = make_human_identity("human_1");
    let session_id = "sess_seq_replay".to_string();

    let initial_args = json!({
        "item_id": "laptop_pro",
        "quantity": 1
    });

    // 1. Initial call demands approval
    let err = router
        .execute_tool(
            ToolCallParams {
                name: "create_order".to_string(),
                arguments: Some(initial_args.clone()),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await
        .unwrap_err();

    let approval_id = match err {
        McpError::StepUpRequired(e) => e.approval_id,
        other => panic!("expected StepUpRequired, got {other:?}"),
    };

    // 2. Human approves
    let approval = router
        .approve_challenge(&approval_id, &human)
        .await
        .unwrap();
    let token = approval.execution_token;

    let retry_args = json!({
        "item_id": "laptop_pro",
        "quantity": 1,
        APPROVAL_TOKEN_ARG_KEY: token
    });

    // 3. First execution presentation: MUST SUCCEED
    let first_result = router
        .execute_tool(
            ToolCallParams {
                name: "create_order".to_string(),
                arguments: Some(retry_args.clone()),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await
        .expect("first execution presentation must succeed");

    assert_eq!(first_result.content[0].text, "ordered 1 of laptop_pro");

    // 4. Second execution presentation (REPLAY): MUST BE REJECTED
    let second_err = router
        .execute_tool(
            ToolCallParams {
                name: "create_order".to_string(),
                arguments: Some(retry_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("second execution presentation must be rejected as replay");

    assert!(matches!(second_err, McpError::TokenReplayOrExpired));
}

#[tokio::test]
async fn test_concurrent_replay_race_defense() {
    let router = Arc::new(create_test_router());
    let caller = make_human_identity("caller_race");
    let human = make_human_identity("human_race");
    let session_id = "sess_race".to_string();

    let initial_args = json!({
        "item_id": "cloud_credits",
        "quantity": 500
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "create_order".to_string(),
                arguments: Some(initial_args),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await
        .unwrap_err();

    let approval_id = match err {
        McpError::StepUpRequired(e) => e.approval_id,
        other => panic!("expected StepUpRequired, got {other:?}"),
    };

    let approval = router
        .approve_challenge(&approval_id, &human)
        .await
        .unwrap();
    let token = approval.execution_token;

    let success_count = Arc::new(AtomicUsize::new(0));
    let replay_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    let concurrency = 30;

    for _ in 0..concurrency {
        let router_clone = Arc::clone(&router);
        let caller_clone = caller.clone();
        let session_clone = session_id.clone();
        let token_clone = token.clone();
        let successes = Arc::clone(&success_count);
        let replays = Arc::clone(&replay_count);

        handles.push(tokio::spawn(async move {
            let args = json!({
                "item_id": "cloud_credits",
                "quantity": 500,
                APPROVAL_TOKEN_ARG_KEY: token_clone
            });

            let res = router_clone
                .execute_tool(
                    ToolCallParams {
                        name: "create_order".to_string(),
                        arguments: Some(args),
                    },
                    Some(caller_clone),
                    session_clone,
                )
                .await;

            match res {
                Ok(_) => {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
                Err(McpError::TokenReplayOrExpired) => {
                    replays.fetch_add(1, Ordering::SeqCst);
                }
                Err(other) => panic!("unexpected error during concurrency race: {other:?}"),
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // AtomicConsume guarantees exactly 1 success out of all racing tasks!
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "exactly 1 request must consume the token successfully"
    );
    assert_eq!(
        replay_count.load(Ordering::SeqCst),
        concurrency - 1,
        "all other concurrent requests must be rejected as replays"
    );
}

#[tokio::test]
async fn test_unminted_token_rejected() {
    let router = create_test_router();
    let caller = make_human_identity("caller_fake");
    let session_id = "sess_fake".to_string();

    let args = json!({
        "item_id": "unminted_item",
        "quantity": 1,
        APPROVAL_TOKEN_ARG_KEY: "fake-execution-token-never-minted"
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "create_order".to_string(),
                arguments: Some(args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("unminted token must be rejected");

    assert!(matches!(err, McpError::TokenReplayOrExpired));
}
