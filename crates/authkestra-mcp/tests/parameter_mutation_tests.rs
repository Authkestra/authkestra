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
use std::sync::Arc;

fn make_human_identity(user_id: &str) -> Identity {
    let mut attributes = HashMap::new();
    attributes.insert("auth_time".to_string(), Utc::now().timestamp().to_string());
    attributes.insert("step_up_satisfied".to_string(), "true".to_string());
    attributes.insert("scope".to_string(), "payments:transfer".to_string());

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

    let transfer_tool = ToolDefinition::new(
        "transfer_funds",
        json!({
            "type": "object",
            "properties": {
                "recipient": { "type": "string" },
                "amount": { "type": "number" }
            },
            "required": ["recipient", "amount"]
        }),
        McpSecurityTier::human_approved(
            vec!["payments:transfer"],
            ReproofRequirement::new(300).require_step_up(true),
            300,
        ),
        |args, _ctx: ToolContext| async move {
            let recipient = args["recipient"].as_str().unwrap_or("unknown");
            let amount = args["amount"].as_f64().unwrap_or(0.0);
            Ok(ToolCallResult::text(format!(
                "transferred ${:.2} to {}",
                amount, recipient
            )))
        },
    );

    McpRouter::builder(pending_store, execution_store)
        .tool(transfer_tool)
        .build()
}

#[tokio::test]
async fn test_exact_parameter_retry_succeeds() {
    let router = create_test_router();
    let caller = make_human_identity("alice_caller");
    let human = make_human_identity("alice_human");
    let session_id = "session_001".to_string();

    let initial_args = json!({
        "recipient": "bob",
        "amount": 50
    });

    // Step 1: Initial call demands step-up
    let call_params = ToolCallParams {
        name: "transfer_funds".to_string(),
        arguments: Some(initial_args.clone()),
    };
    let err = router
        .execute_tool(call_params, Some(caller.clone()), session_id.clone())
        .await
        .expect_err("must demand step-up");

    let approval_id = match err {
        McpError::StepUpRequired(elicitation) => elicitation.approval_id,
        other => panic!("expected StepUpRequired, got {other:?}"),
    };

    // Step 2: Human approves challenge
    let approval = router
        .approve_challenge(&approval_id, &human)
        .await
        .expect("approval succeeds");
    let token = approval.execution_token;

    // Step 3: Retry with identical parameters + approval token
    let retry_args = json!({
        "recipient": "bob",
        "amount": 50,
        APPROVAL_TOKEN_ARG_KEY: token
    });
    let result = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(retry_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect("execution must succeed with matching parameters");

    assert!(!result.is_error);
    assert_eq!(result.content[0].text, "transferred $50.00 to bob");
}

#[tokio::test]
async fn test_reordered_keys_retry_succeeds() {
    let router = create_test_router();
    let caller = make_human_identity("alice_caller");
    let human = make_human_identity("alice_human");
    let session_id = "session_002".to_string();

    let initial_args = json!({
        "recipient": "carol",
        "amount": 75
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(initial_args),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await
        .unwrap_err();

    let approval_id = match err {
        McpError::StepUpRequired(elicitation) => elicitation.approval_id,
        other => panic!("expected StepUpRequired, got {other:?}"),
    };

    let approval = router
        .approve_challenge(&approval_id, &human)
        .await
        .unwrap();

    // Reorder keys in retry: amount before recipient
    let retry_args = json!({
        "amount": 75,
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token,
        "recipient": "carol"
    });

    let result = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(retry_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect("JCS canonicalization ensures reordered keys succeed");

    assert_eq!(result.content[0].text, "transferred $75.00 to carol");
}

#[tokio::test]
async fn test_numeric_value_tampering_rejected() {
    let router = create_test_router();
    let caller = make_human_identity("alice_caller");
    let human = make_human_identity("alice_human");
    let session_id = "session_003".to_string();

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(json!({"recipient": "bob", "amount": 50})),
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

    // Attack: Change amount from 50 to 5000!
    let tampered_args = json!({
        "recipient": "bob",
        "amount": 5000,
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("tampered numeric value must be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_recipient_string_tampering_rejected() {
    let router = create_test_router();
    let caller = make_human_identity("alice_caller");
    let human = make_human_identity("alice_human");
    let session_id = "session_004".to_string();

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(json!({"recipient": "bob", "amount": 50})),
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

    // Attack: Change recipient to mallory!
    let tampered_args = json!({
        "recipient": "mallory",
        "amount": 50,
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("tampered recipient must be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_injected_argument_tampering_rejected() {
    let router = create_test_router();
    let caller = make_human_identity("alice_caller");
    let human = make_human_identity("alice_human");
    let session_id = "session_005".to_string();

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(json!({"recipient": "bob", "amount": 50})),
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

    // Attack: Inject an extra unapproved key
    let tampered_args = json!({
        "recipient": "bob",
        "amount": 50,
        "bypass_audit": true,
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("injected argument must be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_type_mutation_tampering_rejected() {
    let router = create_test_router();
    let caller = make_human_identity("alice_caller");
    let human = make_human_identity("alice_human");
    let session_id = "session_006".to_string();

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(json!({"recipient": "bob", "amount": 50})),
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

    // Attack: Mutate type from number 50 to string "50"
    let tampered_args = json!({
        "recipient": "bob",
        "amount": "50",
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("type mutation must be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}
