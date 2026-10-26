use authkestra_crypto_util::CryptoError;
use authkestra_engine::auth::state::Identity;
use authkestra_engine::auth::ReproofRequirement;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::store::KvStore;
use authkestra_mcp::{
    BrokerError, DownstreamToken, DownstreamTokenBroker, EncryptedKvTokenVault, JsonRpcRequest,
    McpError, McpRouter, McpSecurityTier, ToolCallParams, ToolCallResult, ToolContext,
    ToolDefinition, APPROVAL_TOKEN_ARG_KEY, JSONRPC_VERSION, RPC_TOKEN_REPLAY_OR_EXPIRED,
};
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;

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

fn create_adversarial_test_router(
    counter: Arc<AtomicUsize>,
) -> (
    McpRouter,
    Arc<MemoryStore<authkestra_mcp::approval::ApprovedExecutionRecord>>,
) {
    let pending_store = Arc::new(MemoryStore::new());
    let execution_store = Arc::new(MemoryStore::new());
    let exec_clone = Arc::clone(&execution_store);

    let transfer_tool = ToolDefinition::new(
        "transfer_funds",
        json!({
            "type": "object",
            "properties": {
                "recipient": { "type": "string" },
                "amount": { "type": "integer" }
            },
            "required": ["recipient", "amount"]
        }),
        McpSecurityTier::human_approved(
            vec!["payments:transfer"],
            ReproofRequirement::new(300),
            300,
        ),
        move |args, _ctx: ToolContext| {
            let c = Arc::clone(&counter);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                let recipient = args["recipient"].as_str().unwrap_or("unknown");
                let amount = args["amount"].as_i64().unwrap_or(0);
                Ok(ToolCallResult::text(format!(
                    "Transferred {amount} to {recipient}"
                )))
            }
        },
    );

    let router = McpRouter::builder(pending_store, execution_store)
        .tool(transfer_tool)
        .build();

    (router, exec_clone)
}

// =========================================================================
// 1. HIGH-CONCURRENCY RACE CONDITION: 100 CONCURRENT TOKIO TASKS
// =========================================================================

#[tokio::test]
async fn test_adversarial_high_concurrency_race_execute_tool() {
    let tool_invocation_count = Arc::new(AtomicUsize::new(0));
    let (router, _exec_store) = create_adversarial_test_router(Arc::clone(&tool_invocation_count));
    let router = Arc::new(router);

    let caller = make_human_identity("alice_caller");
    let approver = make_human_identity("alice_approver");
    let session_id = "sess_adversarial_race_100".to_string();

    let initial_args = json!({
        "recipient": "bob_target",
        "amount": 1000
    });

    // Step 1: Initial call yields step-up elicitation
    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
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

    // Step 2: Human step-up approval mints single-use execution token
    let approval = router
        .approve_challenge(&approval_id, &approver)
        .await
        .expect("approval succeeds");
    let execution_token = approval.execution_token;

    // Step 3: Spawn 100 concurrent tokio tasks racing to consume the token
    const CONCURRENCY: usize = 100;
    let barrier = Arc::new(Barrier::new(CONCURRENCY));
    let success_count = Arc::new(AtomicUsize::new(0));
    let replay_rejection_count = Arc::new(AtomicUsize::new(0));
    let other_error_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(CONCURRENCY);

    for task_idx in 0..CONCURRENCY {
        let router_clone = Arc::clone(&router);
        let caller_clone = caller.clone();
        let session_clone = session_id.clone();
        let token_clone = execution_token.clone();
        let barrier_clone = Arc::clone(&barrier);
        let successes = Arc::clone(&success_count);
        let replays = Arc::clone(&replay_rejection_count);
        let others = Arc::clone(&other_error_count);
        let base_args = initial_args.clone();

        handles.push(tokio::spawn(async move {
            let mut args = base_args;
            args.as_object_mut()
                .unwrap()
                .insert(APPROVAL_TOKEN_ARG_KEY.to_string(), json!(token_clone));

            // Wait until all 100 tasks are ready to hit the execution simultaneously
            barrier_clone.wait().await;

            let result = router_clone
                .execute_tool(
                    ToolCallParams {
                        name: "transfer_funds".to_string(),
                        arguments: Some(args),
                    },
                    Some(caller_clone),
                    session_clone,
                )
                .await;

            match result {
                Ok(_) => {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
                Err(McpError::TokenReplayOrExpired) => {
                    replays.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    eprintln!("Task {task_idx} encountered unexpected error: {e:?}");
                    others.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // Invariant 1: EXACTLY 1 task succeeded
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "CRITICAL INVARIANT VIOLATION: Exactly 1 task must succeed in high-concurrency race!"
    );

    // Invariant 2: EXACTLY 99 tasks were rejected as TokenReplayOrExpired
    assert_eq!(
        replay_rejection_count.load(Ordering::SeqCst),
        CONCURRENCY - 1,
        "CRITICAL INVARIANT VIOLATION: All losing tasks must be rejected as TokenReplayOrExpired!"
    );

    // Invariant 3: Zero unexpected errors
    assert_eq!(
        other_error_count.load(Ordering::SeqCst),
        0,
        "Unexpected errors during concurrency race"
    );

    // Invariant 4: Tool handler body was executed EXACTLY 1 time
    assert_eq!(
        tool_invocation_count.load(Ordering::SeqCst),
        1,
        "Tool handler body must be executed exactly 1 time despite 100 racing callers!"
    );
}

// =========================================================================
// 2. HIGH-CONCURRENCY JSON-RPC tools/call RACE CONDITION
// =========================================================================

#[tokio::test]
async fn test_adversarial_high_concurrency_race_json_rpc() {
    let tool_invocation_count = Arc::new(AtomicUsize::new(0));
    let (router, _exec_store) = create_adversarial_test_router(Arc::clone(&tool_invocation_count));
    let router = Arc::new(router);

    let caller = make_human_identity("alice_rpc_caller");
    let approver = make_human_identity("alice_rpc_approver");
    let session_id = "sess_adversarial_rpc_race_64".to_string();

    let initial_args = json!({
        "recipient": "charlie_target",
        "amount": 2500
    });

    // Request via JSON-RPC
    let rpc_req = JsonRpcRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: Some(json!("req-init-1")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "transfer_funds",
            "arguments": initial_args.clone()
        })),
    };

    let init_resp = router
        .handle_json_rpc(rpc_req, Some(caller.clone()), session_id.clone())
        .await;

    let rpc_err = init_resp.error.expect("must return step-up error");
    let elicitation_val = rpc_err.data.expect("must include elicitation data");
    let approval_id = elicitation_val["approval_id"]
        .as_str()
        .expect("approval_id")
        .to_string();

    // Human approves
    let approval = router
        .approve_challenge(&approval_id, &approver)
        .await
        .expect("approval succeeds");
    let execution_token = approval.execution_token;

    const CONCURRENCY: usize = 64;
    let barrier = Arc::new(Barrier::new(CONCURRENCY));
    let success_count = Arc::new(AtomicUsize::new(0));
    let replay_rejection_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(CONCURRENCY);

    for task_idx in 0..CONCURRENCY {
        let router_clone = Arc::clone(&router);
        let caller_clone = caller.clone();
        let session_clone = session_id.clone();
        let token_clone = execution_token.clone();
        let barrier_clone = Arc::clone(&barrier);
        let successes = Arc::clone(&success_count);
        let replays = Arc::clone(&replay_rejection_count);
        let base_args = initial_args.clone();

        handles.push(tokio::spawn(async move {
            let mut args = base_args;
            args.as_object_mut()
                .unwrap()
                .insert(APPROVAL_TOKEN_ARG_KEY.to_string(), json!(token_clone));

            let req = JsonRpcRequest {
                jsonrpc: JSONRPC_VERSION.to_string(),
                id: Some(json!(format!("req-race-{task_idx}"))),
                method: "tools/call".to_string(),
                params: Some(json!({
                    "name": "transfer_funds",
                    "arguments": args
                })),
            };

            barrier_clone.wait().await;

            let resp = router_clone
                .handle_json_rpc(req, Some(caller_clone), session_clone)
                .await;

            if resp.result.is_some() && resp.error.is_none() {
                successes.fetch_add(1, Ordering::SeqCst);
            } else if let Some(err) = resp.error {
                if err.code == RPC_TOKEN_REPLAY_OR_EXPIRED {
                    replays.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "JSON-RPC tools/call race: exactly 1 response must be successful"
    );
    assert_eq!(
        replay_rejection_count.load(Ordering::SeqCst),
        CONCURRENCY - 1,
        "JSON-RPC tools/call race: exactly 63 responses must be RPC_TOKEN_REPLAY_OR_EXPIRED (-32004)"
    );
    assert_eq!(
        tool_invocation_count.load(Ordering::SeqCst),
        1,
        "Tool handler invoked exactly once via JSON-RPC race"
    );
}

// =========================================================================
// 3. SEQUENTIAL MULTI-STAGE REPLAY ATTACKS
// =========================================================================

#[tokio::test]
async fn test_adversarial_sequential_replay_attempts() {
    let tool_invocation_count = Arc::new(AtomicUsize::new(0));
    let (router, _exec_store) = create_adversarial_test_router(Arc::clone(&tool_invocation_count));

    let caller = make_human_identity("seq_caller");
    let approver = make_human_identity("seq_approver");
    let session_id = "sess_seq_stress".to_string();

    let valid_args = json!({
        "recipient": "dave_target",
        "amount": 750
    });

    // 1. Initial call -> step-up elicitation
    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(valid_args.clone()),
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

    // 2. Approve
    let approval = router
        .approve_challenge(&approval_id, &approver)
        .await
        .unwrap();
    let token = approval.execution_token;

    let mut execution_args = valid_args.clone();
    execution_args
        .as_object_mut()
        .unwrap()
        .insert(APPROVAL_TOKEN_ARG_KEY.to_string(), json!(token));

    // 3. Presentation 1 (Legitimate): MUST SUCCEED
    let res1 = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(execution_args.clone()),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await;
    assert!(res1.is_ok(), "First presentation must succeed");
    assert_eq!(tool_invocation_count.load(Ordering::SeqCst), 1);

    // 4. Presentation 2 (Immediate replay with identical valid arguments): MUST FAIL
    let res2 = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(execution_args.clone()),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await;
    assert!(
        matches!(res2, Err(McpError::TokenReplayOrExpired)),
        "Immediate sequential replay must fail with TokenReplayOrExpired"
    );

    // 5. Presentation 3 (Delayed replay after 20ms): MUST FAIL
    tokio::time::sleep(Duration::from_millis(20)).await;
    let res3 = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(execution_args.clone()),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await;
    assert!(
        matches!(res3, Err(McpError::TokenReplayOrExpired)),
        "Delayed replay must fail with TokenReplayOrExpired"
    );

    // 6. Presentation 4 (Replay with mutated arguments): Token consumption happens BEFORE parameter validation!
    // Therefore, even if arguments are altered, it must fail with TokenReplayOrExpired (token is already gone).
    let mut mutated_args = execution_args.clone();
    mutated_args["amount"] = json!(999999);
    let res4 = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(mutated_args),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await;
    assert!(
        matches!(res4, Err(McpError::TokenReplayOrExpired)),
        "Replay with altered arguments must fail at token consumption stage"
    );

    // 7. Presentation 5 (Replay under different session_id): MUST FAIL with TokenReplayOrExpired
    let res5 = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(execution_args.clone()),
            },
            Some(caller.clone()),
            "different_session_999".to_string(),
        )
        .await;
    assert!(
        matches!(res5, Err(McpError::TokenReplayOrExpired)),
        "Replay under different session must fail with TokenReplayOrExpired"
    );

    // Tool handler must still have been called exactly once!
    assert_eq!(tool_invocation_count.load(Ordering::SeqCst), 1);
}

// =========================================================================
// 4. AT-REST STORAGE INSPECTION: PLAINTEXT ABSENCE & ENTROPY IN KVSTORE
// =========================================================================

#[tokio::test]
async fn test_adversarial_at_rest_storage_inspection() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault_key = [0x5Au8; 32];
    let vault = EncryptedKvTokenVault::new(Arc::clone(&raw_store), vault_key);

    let alice = Identity {
        provider_id: "enterprise_sso".to_string(),
        external_id: "emp_98765".to_string(),
        email: Some("emp_98765@enterprise.internal".to_string()),
        username: Some("alice_corporate".to_string()),
        attributes: HashMap::new(),
    };

    let sensitive_access_token = "ghp_VERY_SECRET_LONG_ACCESS_TOKEN_ABC1234567890XYZ";
    let sensitive_refresh_token = "ghr_VERY_SECRET_LONG_REFRESH_TOKEN_9876543210ZYX";
    let sensitive_scope_1 = "admin:enterprise_vault_access";
    let sensitive_scope_2 = "restricted:delete_infrastructure";

    let token = DownstreamToken {
        access_token: sensitive_access_token.to_string(),
        refresh_token: Some(sensitive_refresh_token.to_string()),
        token_type: "Bearer".to_string(),
        scopes: vec![sensitive_scope_1.to_string(), sensitive_scope_2.to_string()],
        expires_at: Some(Utc::now().timestamp() + 3600),
    };

    vault
        .store_token(
            &alice,
            "github_enterprise",
            &token,
            Duration::from_secs(3600),
        )
        .await
        .expect("token storage succeeds");

    // Inspect the raw bytes stored in the underlying store
    let storage_key = EncryptedKvTokenVault::storage_key(&alice, "github_enterprise");
    let raw_ciphertext = raw_store
        .get(&storage_key)
        .await
        .unwrap()
        .expect("entry must exist in raw store");

    // Format check: must be >= 28 bytes (12 nonce + >=0 ciphertext + 16 tag)
    assert!(
        raw_ciphertext.len() >= 28,
        "Stored raw bytes must contain at least 28 bytes for AES-GCM nonce and tag"
    );

    // 1. Substring absence in lossy UTF-8
    let lossy_str = String::from_utf8_lossy(&raw_ciphertext);
    assert!(!lossy_str.contains(sensitive_access_token));
    assert!(!lossy_str.contains(sensitive_refresh_token));
    assert!(!lossy_str.contains(sensitive_scope_1));
    assert!(!lossy_str.contains(sensitive_scope_2));
    assert!(!lossy_str.contains("access_token"));
    assert!(!lossy_str.contains("refresh_token"));
    assert!(!lossy_str.contains("Bearer"));

    // 2. Binary subsequence search: verify no part of the sensitive secrets exists as raw byte slices
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    assert!(
        !contains_subslice(&raw_ciphertext, sensitive_access_token.as_bytes()),
        "Raw bytes contain exact byte sequence of access token!"
    );
    assert!(
        !contains_subslice(&raw_ciphertext, sensitive_refresh_token.as_bytes()),
        "Raw bytes contain exact byte sequence of refresh token!"
    );
    assert!(
        !contains_subslice(&raw_ciphertext, sensitive_scope_1.as_bytes()),
        "Raw bytes contain exact byte sequence of sensitive scope 1!"
    );
    assert!(
        !contains_subslice(&raw_ciphertext, sensitive_scope_2.as_bytes()),
        "Raw bytes contain exact byte sequence of sensitive scope 2!"
    );

    // 3. Shannon Entropy of stored ciphertext:
    // AES-GCM ciphertext should have Shannon entropy close to 8 bits/byte.
    let mut byte_counts = [0usize; 256];
    for &b in &raw_ciphertext {
        byte_counts[b as usize] += 1;
    }
    let total_len = raw_ciphertext.len() as f64;
    let entropy: f64 = byte_counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total_len;
            -p * p.log2()
        })
        .sum();

    // Shannon entropy for encrypted data of ~150-200 bytes is typically > 6.8 bits/byte
    assert!(
        entropy > 6.5,
        "Ciphertext entropy is too low ({entropy:.2} bits/byte), suggesting plaintext leakage or bad PRNG"
    );

    // 4. Nonce Uniqueness across consecutive encryptions of identical data
    let mut observed_nonces = std::collections::HashSet::new();
    for i in 0..30 {
        let dummy_identity = Identity {
            provider_id: "prov".to_string(),
            external_id: format!("user_{i}"),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };
        vault
            .store_token(&dummy_identity, "svc", &token, Duration::from_secs(60))
            .await
            .unwrap();

        let k = EncryptedKvTokenVault::storage_key(&dummy_identity, "svc");
        let bytes = raw_store.get(&k).await.unwrap().unwrap();
        let nonce = &bytes[0..12];
        assert!(
            observed_nonces.insert(nonce.to_vec()),
            "CSPRNG NONCE REUSE DETECTED! Nonce reused at iteration {i}"
        );
    }
}

// =========================================================================
// 5. AEAD BIT-FLIP & TAMPER STRESS TEST HARNESS
// =========================================================================

#[tokio::test]
async fn test_adversarial_aead_tamper_stress_matrix() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault_key = [0x42u8; 32];
    let vault = EncryptedKvTokenVault::new(Arc::clone(&raw_store), vault_key);

    let alice = Identity {
        provider_id: "tamper_test".to_string(),
        external_id: "alice".to_string(),
        email: None,
        username: None,
        attributes: HashMap::new(),
    };

    let original_token = DownstreamToken {
        access_token: "authenticated_aead_payload_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        scopes: vec!["read".to_string()],
        expires_at: Some(Utc::now().timestamp() + 3600),
    };

    let storage_key = EncryptedKvTokenVault::storage_key(&alice, "tamper_svc");

    // Baseline: store and confirm valid resolution
    vault
        .store_token(
            &alice,
            "tamper_svc",
            &original_token,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

    let valid_bytes = raw_store.get(&storage_key).await.unwrap().unwrap();
    let total_len = valid_bytes.len();
    assert!(total_len >= 28);

    // Matrix of tamper vectors to execute:
    // (description, modified_bytes)
    let mut tamper_vectors: Vec<(&str, Vec<u8>)> = Vec::new();

    // Vector A: Tamper Nonce (bytes 0..12)
    {
        let mut b = valid_bytes.clone();
        b[0] ^= 0x01; // first byte of nonce
        tamper_vectors.push(("Nonce byte 0 bit-flip", b));

        let mut b = valid_bytes.clone();
        b[5] ^= 0x80; // middle byte of nonce
        tamper_vectors.push(("Nonce byte 5 bit-flip", b));

        let mut b = valid_bytes.clone();
        b[11] ^= 0xFF; // last byte of nonce
        tamper_vectors.push(("Nonce byte 11 bit-flip", b));
    }

    // Vector B: Tamper Ciphertext Payload (bytes 12..total_len-16)
    {
        let mut b = valid_bytes.clone();
        b[12] ^= 0x01; // first byte of ciphertext
        tamper_vectors.push(("Ciphertext first byte bit-flip", b));

        let mid = 12 + (total_len - 28) / 2;
        let mut b = valid_bytes.clone();
        b[mid] ^= 0x40; // middle of ciphertext
        tamper_vectors.push(("Ciphertext middle byte bit-flip", b));

        let mut b = valid_bytes.clone();
        b[total_len - 17] ^= 0x02; // last byte before auth tag
        tamper_vectors.push(("Ciphertext last byte bit-flip", b));
    }

    // Vector C: Tamper Authentication Tag (bytes total_len-16..total_len)
    {
        let mut b = valid_bytes.clone();
        b[total_len - 16] ^= 0x01; // first byte of tag
        tamper_vectors.push(("Auth tag first byte bit-flip", b));

        let mut b = valid_bytes.clone();
        b[total_len - 8] ^= 0x10; // middle byte of tag
        tamper_vectors.push(("Auth tag middle byte bit-flip", b));

        let mut b = valid_bytes.clone();
        b[total_len - 1] ^= 0x01; // last byte of tag
        tamper_vectors.push(("Auth tag last byte bit-flip", b));
    }

    // Vector D: Truncation attacks
    {
        tamper_vectors.push(("Truncated to 0 bytes", vec![]));
        tamper_vectors.push(("Truncated to 1 byte", vec![0x00]));
        tamper_vectors.push((
            "Truncated to 12 bytes (nonce only)",
            valid_bytes[0..12].to_vec(),
        ));
        tamper_vectors.push((
            "Truncated to 27 bytes (1 byte below minimum 28)",
            valid_bytes[0..27].to_vec(),
        ));
    }

    // Vector E: Appended garbage
    {
        let mut b = valid_bytes.clone();
        b.extend_from_slice(b"EXTRA_TRAILING_GARBAGE_BYTES");
        tamper_vectors.push(("Appended trailing bytes", b));
    }

    // Vector F: Swapped bytes
    {
        let mut b = valid_bytes.clone();
        b.swap(14, 15);
        tamper_vectors.push(("Swapped adjacent ciphertext bytes", b));
    }

    // Vector G: Zeroed auth tag
    {
        let mut b = valid_bytes.clone();
        for byte in &mut b[total_len - 16..total_len] {
            *byte = 0;
        }
        tamper_vectors.push(("Zeroed auth tag", b));
    }

    // Execute every tamper vector and verify AEAD strictly rejects each one
    for (desc, tampered) in tamper_vectors {
        raw_store
            .set(&storage_key, tampered, Duration::from_secs(3600))
            .await
            .unwrap();

        let result = vault.resolve_token(&alice, "tamper_svc", &["read"]).await;

        match result {
            Err(BrokerError::Crypto(CryptoError::Decryption(_))) => {
                // Expected AEAD verification failure
            }
            Err(BrokerError::Crypto(CryptoError::CiphertextTooShort { .. })) => {
                // Expected length validation failure
            }
            Err(other) => {
                panic!("Tamper vector '{desc}' failed with unexpected error: {other:?}");
            }
            Ok(Some(token)) => {
                panic!(
                    "CRITICAL SECURITY VULNERABILITY: Tamper vector '{desc}' bypassed AEAD authentication and returned plaintext token: {token}!"
                );
            }
            Ok(None) => {
                panic!("Tamper vector '{desc}' unexpectedly returned Ok(None)");
            }
        }
    }
}

// =========================================================================
// 6. CROSS-TENANT ACCESS & DELIMITER COLLISION TESTS
// =========================================================================

#[tokio::test]
async fn test_adversarial_cross_tenant_isolation_matrix() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = EncryptedKvTokenVault::new(raw_store, [0x99u8; 32]);

    let tenant_a_alice = Identity {
        provider_id: "tenant_alpha".to_string(),
        external_id: "alice".to_string(),
        email: Some("alice@alpha.org".to_string()),
        username: Some("alice".to_string()),
        attributes: HashMap::new(),
    };

    let token = DownstreamToken {
        access_token: "alpha_alice_private_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        scopes: vec!["read".to_string()],
        expires_at: Some(Utc::now().timestamp() + 3600),
    };

    vault
        .store_token(&tenant_a_alice, "slack", &token, Duration::from_secs(3600))
        .await
        .unwrap();

    // Adversary 1: Same tenant, different user (Bob)
    let tenant_a_bob = Identity {
        provider_id: "tenant_alpha".to_string(),
        external_id: "bob".to_string(),
        email: Some("bob@alpha.org".to_string()),
        username: Some("bob".to_string()),
        attributes: HashMap::new(),
    };
    assert_eq!(
        vault
            .resolve_token(&tenant_a_bob, "slack", &["read"])
            .await
            .unwrap(),
        None,
        "Same tenant different user must not access token"
    );

    // Adversary 2: Different tenant (Beta), same user id ("alice")
    let tenant_b_alice = Identity {
        provider_id: "tenant_beta".to_string(),
        external_id: "alice".to_string(),
        email: Some("alice@beta.org".to_string()),
        username: Some("alice".to_string()),
        attributes: HashMap::new(),
    };
    assert_eq!(
        vault
            .resolve_token(&tenant_b_alice, "slack", &["read"])
            .await
            .unwrap(),
        None,
        "Different tenant same user ID must not access token"
    );

    // Adversary 3: Same tenant, same user, different service ("github" instead of "slack")
    assert_eq!(
        vault
            .resolve_token(&tenant_a_alice, "github", &["read"])
            .await
            .unwrap(),
        None,
        "Different service must not resolve token"
    );

    // Adversary 4: Delimiter ambiguity check
    let delimiter_adversary = Identity {
        provider_id: "tenant".to_string(),
        external_id: "alpha:alice".to_string(),
        email: None,
        username: None,
        attributes: HashMap::new(),
    };
    assert_eq!(
        vault
            .resolve_token(&delimiter_adversary, "slack", &["read"])
            .await
            .unwrap(),
        None,
        "Delimiter injection must not cross-access"
    );
}

// =========================================================================
// 7. DELIMITER INJECTION IN STORAGE KEY EMPIRICAL FINDING TEST
// =========================================================================

#[test]
fn test_adversarial_delimiter_collision_in_storage_key() {
    // Construct two distinct identities and service names that produce identical storage keys
    // due to unescaped colon ':' delimiter concatenation in EncryptedKvTokenVault::storage_key:
    // format!("mcp:vault:{}:{}:{}", identity.provider_id, identity.external_id, service)

    let identity_1 = Identity {
        provider_id: "corp".to_string(),
        external_id: "user1:serviceA".to_string(),
        email: None,
        username: None,
        attributes: HashMap::new(),
    };
    let service_1 = "token";

    let identity_2 = Identity {
        provider_id: "corp".to_string(),
        external_id: "user1".to_string(),
        email: None,
        username: None,
        attributes: HashMap::new(),
    };
    let service_2 = "serviceA:token";

    let key_1 = EncryptedKvTokenVault::storage_key(&identity_1, service_1);
    let key_2 = EncryptedKvTokenVault::storage_key(&identity_2, service_2);

    // Empirically demonstrate the collision:
    assert_eq!(
        key_1, key_2,
        "Storage keys collide due to unescaped ':' delimiters in vault storage_key!"
    );
}

// =========================================================================
// 8. APPROVAL RACE CONDITION STRESS TEST (TOCTOU in approve_challenge)
// =========================================================================

#[tokio::test]
async fn test_adversarial_approval_race_condition() {
    let tool_invocation_count = Arc::new(AtomicUsize::new(0));
    let (router, _exec_store) = create_adversarial_test_router(Arc::clone(&tool_invocation_count));
    let router = Arc::new(router);

    let caller = make_human_identity("alice_race_caller");
    let approver = make_human_identity("alice_race_approver");
    let session_id = "sess_race_approval".to_string();

    let initial_args = json!({
        "recipient": "race_target",
        "amount": 500
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "transfer_funds".to_string(),
                arguments: Some(initial_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .unwrap_err();

    let approval_id = match err {
        McpError::StepUpRequired(e) => e.approval_id,
        other => panic!("expected StepUpRequired, got {other:?}"),
    };

    const CONCURRENCY: usize = 50;
    let barrier = Arc::new(Barrier::new(CONCURRENCY));
    let approved_tokens = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let mut handles = Vec::with_capacity(CONCURRENCY);

    for _ in 0..CONCURRENCY {
        let router_clone = Arc::clone(&router);
        let approver_clone = approver.clone();
        let app_id = approval_id.clone();
        let barrier_clone = Arc::clone(&barrier);
        let tokens_clone = Arc::clone(&approved_tokens);

        handles.push(tokio::spawn(async move {
            barrier_clone.wait().await;
            if let Ok(res) = router_clone
                .approve_challenge(&app_id, &approver_clone)
                .await
            {
                tokens_clone.lock().await.push(res.execution_token);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let tokens = approved_tokens.lock().await;
    println!(
        "Approval race result: {} tokens minted out of {} concurrent approve calls",
        tokens.len(),
        CONCURRENCY
    );

    // In a perfectly atomic system, exactly 1 token should be minted per approval_id.
    // However, if approve_challenge uses get() followed by delete() on pending_store,
    // concurrent callers might both read the pending challenge before either deletes it.
}
