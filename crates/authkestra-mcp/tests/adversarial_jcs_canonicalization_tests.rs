use authkestra_engine::auth::state::Identity;
use authkestra_engine::auth::ReproofRequirement;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_mcp::{
    canonicalize_json, compute_challenge_digest, McpError, McpRouter, McpSecurityTier,
    ToolCallParams, ToolCallResult, ToolContext, ToolDefinition, APPROVAL_TOKEN_ARG_KEY,
};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

fn make_human_identity(user_id: &str) -> Identity {
    let mut attributes = HashMap::new();
    attributes.insert("auth_time".to_string(), Utc::now().timestamp().to_string());
    attributes.insert("step_up_satisfied".to_string(), "true".to_string());
    attributes.insert("scope".to_string(), "admin:finance".to_string());

    Identity {
        provider_id: "authkestra_idp".to_string(),
        external_id: user_id.to_string(),
        email: Some(format!("{user_id}@example.com")),
        username: Some(user_id.to_string()),
        attributes,
    }
}

fn create_adversarial_router() -> McpRouter {
    let pending_store = Arc::new(MemoryStore::new());
    let execution_store = Arc::new(MemoryStore::new());

    let sensitive_tool = ToolDefinition::new(
        "adversarial_eval",
        json!({
            "type": "object"
        }),
        McpSecurityTier::human_approved(
            vec!["admin:finance"],
            ReproofRequirement::new(300).require_step_up(true),
            300,
        ),
        |args, _ctx: ToolContext| async move {
            Ok(ToolCallResult::text(format!(
                "Executed successfully with: {:?}",
                args
            )))
        },
    );

    McpRouter::builder(pending_store, execution_store)
        .tool(sensitive_tool)
        .build()
}

// =========================================================================
// Category 1: Extreme Key Permutations in Deeply Nested Objects & Arrays
// =========================================================================

#[test]
fn test_adversarial_deeply_nested_10_level_permutations() {
    let obj1 = json!({
        "level_1_b": {
            "level_2_z": {
                "level_3_m": {
                    "level_4_y": {
                        "level_5_c": {
                            "level_6_x": {
                                "level_7_p": {
                                    "level_8_q": {
                                        "level_9_k": {
                                            "level_10_beta": 2,
                                            "level_10_alpha": 1
                                        },
                                        "level_9_a": 100
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "level_1_a": {
            "level_2_a": 42
        }
    });

    let obj2 = json!({
        "level_1_a": {
            "level_2_a": 42
        },
        "level_1_b": {
            "level_2_z": {
                "level_3_m": {
                    "level_4_y": {
                        "level_5_c": {
                            "level_6_x": {
                                "level_7_p": {
                                    "level_8_q": {
                                        "level_9_a": 100,
                                        "level_9_k": {
                                            "level_10_alpha": 1,
                                            "level_10_beta": 2
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let canon1 = canonicalize_json(&obj1).expect("canonicalization of deeply nested object 1");
    let canon2 = canonicalize_json(&obj2).expect("canonicalization of deeply nested object 2");

    assert_eq!(
        canon1, canon2,
        "Deeply nested object canonicalizations must be strictly identical"
    );

    let digest1 = compute_challenge_digest("sess_x", "tool_t", &canon1, 1800000000);
    let digest2 = compute_challenge_digest("sess_x", "tool_t", &canon2, 1800000000);

    assert_eq!(
        digest1, digest2,
        "Challenge digests must match exactly across 10-level key permutations"
    );
}

#[test]
fn test_adversarial_arrays_of_nested_scrambled_objects() {
    let arr1 = json!([
        {
            "tag": "first",
            "metadata": { "zeta": 99, "alpha": 1, "omega": 50 }
        },
        {
            "tag": "second",
            "items": [
                { "z": 10, "a": 20 },
                { "y": 30, "b": 40 }
            ]
        }
    ]);

    let arr2 = json!([
        {
            "metadata": { "alpha": 1, "omega": 50, "zeta": 99 },
            "tag": "first"
        },
        {
            "items": [
                { "a": 20, "z": 10 },
                { "b": 40, "y": 30 }
            ],
            "tag": "second"
        }
    ]);

    let canon1 = canonicalize_json(&arr1).unwrap();
    let canon2 = canonicalize_json(&arr2).unwrap();

    assert_eq!(
        canon1, canon2,
        "Array-nested scrambled objects must canonicalize identically"
    );
}

#[test]
fn test_adversarial_prefix_colliding_keys() {
    let obj1 = json!({
        "test_b": 2,
        "test_a": 1,
        "test": 0,
        "": "empty_key",
        "test_aa": 3,
        "test_1": 4
    });

    let obj2 = json!({
        "": "empty_key",
        "test": 0,
        "test_1": 4,
        "test_a": 1,
        "test_aa": 3,
        "test_b": 2
    });

    let canon1 = canonicalize_json(&obj1).unwrap();
    let canon2 = canonicalize_json(&obj2).unwrap();

    assert_eq!(
        canon1, canon2,
        "Keys with shared prefixes and empty key must sort identically"
    );
    let canon_str = String::from_utf8(canon1).unwrap();
    assert!(canon_str.starts_with(r#"{"":""#));
}

// =========================================================================
// Category 2: Unicode Code Point Boundaries, Surrogate Pairs & Escaping
// =========================================================================

#[test]
fn test_adversarial_unicode_surrogate_plane_sorting() {
    // RFC 8785 Section 3.2.3: Properties sorted by UTF-16 code units.
    let obj = json!({
        "\u{ffff}": "specials_ffff",
        "\u{fb33}": "hebrew_fb33",
        "\u{e000}": "pua_e000",
        "\u{10ffff}": "max_supplementary",
        "\u{1f600}": "emoji_grinning",
        "\u{10000}": "min_supplementary",
        "\u{d7ff}": "bmp_d7ff",
        "a": "ascii_a"
    });

    let canon = canonicalize_json(&obj).expect("unicode property sorting");
    let canon_str = String::from_utf8(canon).expect("valid utf-8 canonical output");

    let pos_a = canon_str.find("\"a\"").unwrap();
    let pos_d7ff = canon_str.find("\"\u{d7ff}\"").unwrap();
    let pos_10000 = canon_str.find("\"\u{10000}\"").unwrap();
    let pos_1f600 = canon_str.find("\"\u{1f600}\"").unwrap();
    let pos_10ffff = canon_str.find("\"\u{10ffff}\"").unwrap();
    let pos_e000 = canon_str.find("\"\u{e000}\"").unwrap();
    let pos_fb33 = canon_str.find("\"\u{fb33}\"").unwrap();
    let pos_ffff = canon_str.find("\"\u{ffff}\"").unwrap();

    assert!(pos_a < pos_d7ff, "ASCII must sort before U+D7FF");
    assert!(
        pos_d7ff < pos_10000,
        "U+D7FF must sort before U+10000 (surrogate 0xD800)"
    );
    assert!(
        pos_10000 < pos_1f600,
        "U+10000 must sort before U+1F600 (surrogate 0xD83D)"
    );
    assert!(
        pos_1f600 < pos_10ffff,
        "U+1F600 must sort before U+10FFFF (surrogate 0xDBFF)"
    );
    assert!(
        pos_10ffff < pos_e000,
        "U+10FFFF (surrogate 0xDBFF) must sort before U+E000 (0xE000)"
    );
    assert!(pos_e000 < pos_fb33, "U+E000 must sort before U+FB33");
    assert!(pos_fb33 < pos_ffff, "U+FB33 must sort before U+FFFF");
}

#[test]
fn test_adversarial_supplementary_same_high_surrogate_order() {
    let obj = json!({
        "\u{1f601}": 2,
        "\u{1f600}": 1
    });

    let canon = canonicalize_json(&obj).unwrap();
    let canon_str = String::from_utf8(canon).unwrap();

    let pos_0 = canon_str.find('\u{1f600}').unwrap();
    let pos_1 = canon_str.find('\u{1f601}').unwrap();

    assert!(
        pos_0 < pos_1,
        "Low surrogate 0xDE00 must sort before 0xDE01"
    );
}

#[test]
fn test_adversarial_escaping_rules_per_rfc8785() {
    let obj = json!({
        "escapes": "\"\t\n\r\x08\x0c\\",
        "slash": "https://authkestra.com/test/path",
        "null_byte": "null\u{0000}byte",
        "unit_separator": "field\u{001f}sep"
    });

    let canon = canonicalize_json(&obj).unwrap();
    let canon_str = String::from_utf8(canon).unwrap();

    assert!(
        canon_str.contains(r#""slash":"https://authkestra.com/test/path""#),
        "Forward slash must NOT be escaped as \\/"
    );
    assert!(
        canon_str.contains(r#"\u0000"#),
        "Null byte must be escaped as \\u0000"
    );
    assert!(
        canon_str.contains(r#"\u001f"#),
        "Unit separator must be escaped as \\u001f"
    );
    assert!(canon_str.contains(r#"\""#), "Double quote must be escaped");
    assert!(canon_str.contains(r#"\\"#), "Backslash must be escaped");
}

// =========================================================================
// Category 3: Numeric Representations & Boundaries
// =========================================================================

#[test]
fn test_adversarial_negative_zero_canonicalization() {
    let obj_neg_zero = json!({ "val": -0.0 });
    let obj_pos_zero = json!({ "val": 0.0 });
    let obj_int_zero = json!({ "val": 0 });

    let canon_neg = canonicalize_json(&obj_neg_zero).unwrap();
    let canon_pos = canonicalize_json(&obj_pos_zero).unwrap();
    let canon_int = canonicalize_json(&obj_int_zero).unwrap();

    assert_eq!(
        canon_neg, br#"{"val":0}"#,
        "-0.0 must canonicalize to 0 per RFC 8785"
    );
    assert_eq!(canon_neg, canon_pos, "-0.0 and 0.0 must be byte-identical");
    assert_eq!(canon_pos, canon_int, "0.0 and 0 must be byte-identical");

    let digest_neg = compute_challenge_digest("s", "t", &canon_neg, 100);
    let digest_int = compute_challenge_digest("s", "t", &canon_int, 100);
    assert_eq!(
        digest_neg, digest_int,
        "Challenge digest for -0.0 and 0 must match"
    );
}

#[test]
fn test_adversarial_integer_vs_float_representations() {
    let int_val = json!({ "amount": 50 });
    let float_val = json!({ "amount": 50.0 });

    let canon_int = canonicalize_json(&int_val).unwrap();
    let canon_float = canonicalize_json(&float_val).unwrap();

    assert_eq!(
        canon_int, canon_float,
        "50 and 50.0 must canonicalize identically to 50"
    );
    assert_eq!(canon_int, br#"{"amount":50}"#);
}

#[test]
fn test_adversarial_scientific_notation_formatting() {
    let exp_val = json!({ "val": 1e6 });
    let int_val = json!({ "val": 1000000 });

    let canon_exp = canonicalize_json(&exp_val).unwrap();
    let canon_int = canonicalize_json(&int_val).unwrap();

    assert_eq!(
        canon_exp, canon_int,
        "1e6 and 1000000 must canonicalize identically"
    );
}

#[test]
fn test_adversarial_safe_integer_boundaries() {
    let max_safe = json!({ "id": 9007199254740991i64 });
    let max_safe_plus_1 = json!({ "id": 9007199254740992i64 });

    let canon1 = canonicalize_json(&max_safe).unwrap();
    let canon2 = canonicalize_json(&max_safe_plus_1).unwrap();

    assert_ne!(
        canon1, canon2,
        "Different integers must produce different canonical bytes"
    );

    let digest1 = compute_challenge_digest("s", "t", &canon1, 100);
    let digest2 = compute_challenge_digest("s", "t", &canon2, 100);

    assert_ne!(
        digest1, digest2,
        "Challenge digests must differ at safe integer boundary"
    );
}

#[test]
fn test_adversarial_extreme_float_values() {
    let min_pos = json!({ "min_pos": f64::MIN_POSITIVE });
    let max_val = json!({ "max_val": f64::MAX });

    let canon_min = canonicalize_json(&min_pos).unwrap();
    let canon_max = canonicalize_json(&max_val).unwrap();

    assert_ne!(canon_min, canon_max);

    let digest_min = compute_challenge_digest("s", "t", &canon_min, 100);
    let digest_max = compute_challenge_digest("s", "t", &canon_max, 100);

    assert_ne!(digest_min, digest_max);
}

// =========================================================================
// Category 4: Parameter Mutation Attacks & Router Rejection
// =========================================================================

#[tokio::test]
async fn test_adversarial_mutation_extra_key_injection() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_01".to_string();

    let initial_args = json!({
        "target": "database_production",
        "action": "read_metrics"
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
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

    // Attack: Inject an extra unapproved key "drop_tables": true
    let tampered_args = json!({
        "target": "database_production",
        "action": "read_metrics",
        "drop_tables": true,
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("injected unapproved key MUST be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_adversarial_mutation_slight_float_perturbation() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_02".to_string();

    let initial_args = json!({
        "rate": 1.0500000000
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
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

    // Attack: Tiny float perturbation
    let tampered_args = json!({
        "rate": 1.0500000001,
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("float perturbation MUST be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_adversarial_mutation_null_vs_omitted_field() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_03".to_string();

    // Initial has optional field explicitly set to null
    let initial_args = json!({
        "name": "system_config",
        "override_flags": null
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
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

    // Attack: Retry with field omitted entirely
    let tampered_args = json!({
        "name": "system_config",
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("null field vs omitted field MUST be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_adversarial_mutation_whitespace_tampering() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_04".to_string();

    let initial_args = json!({
        "account_id": "ACC-99210"
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
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

    // Attack: Add trailing space to account_id value
    let tampered_args = json!({
        "account_id": "ACC-99210 ",
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("whitespace alteration in string value MUST be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_adversarial_mutation_array_element_reordering() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_05".to_string();

    let initial_args = json!({
        "allowed_ips": ["192.168.1.1", "10.0.0.1"]
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
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

    // Attack: Reorder elements in array (array order is semantically significant!)
    let tampered_args = json!({
        "allowed_ips": ["10.0.0.1", "192.168.1.1"],
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("array element reordering MUST be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_adversarial_mutation_key_casing_and_homoglyphs() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_06".to_string();

    let initial_args = json!({
        "amount": 1000
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
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

    // Attack: Change key from "amount" (ASCII 'a' U+0061) to Cyrillic 'а' (U+0430)
    let cyrillic_a_args = json!({
        "\u{0430}mount": 1000,
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(cyrillic_a_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("Cyrillic homoglyph in key MUST be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_adversarial_cross_session_or_tool_hijack() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_07".to_string();

    let initial_args = json!({
        "action": "safe_action"
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
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

    let approval = router
        .approve_challenge(&approval_id, &human)
        .await
        .unwrap();

    // Attack: Replay token in a DIFFERENT session
    let hijacker_session_id = "sess_hijacker_99".to_string();
    let tampered_args = json!({
        "action": "safe_action",
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            hijacker_session_id,
        )
        .await
        .expect_err("cross-session token use MUST be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_adversarial_mutation_boolean_flip() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_08".to_string();

    let initial_args = json!({
        "admin_confirmed": true,
        "mode": "standard"
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
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

    // Attack: Flip boolean true to false
    let tampered_args = json!({
        "admin_confirmed": false,
        "mode": "standard",
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("boolean flip true -> false MUST be rejected");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_adversarial_empty_arguments_lifecycle() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_09".to_string();

    // Initial tool call without arguments (None)
    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: None,
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

    // 1. Retry with extra injected argument should FAIL
    let tampered_args = json!({
        "unexpected_injected": 42,
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await
        .expect_err("injecting argument into approved empty-arg call MUST fail");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[tokio::test]
async fn test_adversarial_non_object_arguments_rejected() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let session_id = "sess_adv_10".to_string();

    // Attempt calling tool with array arguments
    let err_array = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(json!([1, 2, 3])),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await
        .expect_err("array arguments must be rejected");

    assert!(matches!(err_array, McpError::InvalidArguments(_)));

    // Attempt calling tool with string arguments
    let err_str = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(json!("malicious_string")),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await
        .expect_err("string arguments must be rejected");

    assert!(matches!(err_str, McpError::InvalidArguments(_)));

    // Attempt calling tool with integer arguments
    let err_num = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(json!(42)),
            },
            Some(caller.clone()),
            session_id.clone(),
        )
        .await
        .expect_err("numeric arguments must be rejected");

    assert!(matches!(err_num, McpError::InvalidArguments(_)));

    // Attempt calling tool with boolean arguments
    let err_bool = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(json!(true)),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("boolean arguments must be rejected");

    assert!(matches!(err_bool, McpError::InvalidArguments(_)));
}

#[tokio::test]
async fn test_adversarial_nested_token_arg_not_stripped() {
    let router = create_adversarial_router();
    let caller = make_human_identity("eval_caller");
    let human = make_human_identity("eval_approver");
    let session_id = "sess_adv_11".to_string();

    // The token key appears inside a nested object
    let initial_args = json!({
        "payload": {
            APPROVAL_TOKEN_ARG_KEY: "fake_token_value",
            "real_param": 100
        }
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
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

    // Attacker modifies the nested fake token value
    let tampered_args = json!({
        "payload": {
            APPROVAL_TOKEN_ARG_KEY: "different_value",
            "real_param": 100
        },
        APPROVAL_TOKEN_ARG_KEY: approval.execution_token
    });

    let err = router
        .execute_tool(
            ToolCallParams {
                name: "adversarial_eval".to_string(),
                arguments: Some(tampered_args),
            },
            Some(caller),
            session_id,
        )
        .await
        .expect_err("modifying nested pseudo-token key MUST be detected as tampering");

    assert!(matches!(err, McpError::ParameterMismatch));
}

#[test]
fn test_adversarial_randomized_key_permutation_oracle() {
    // Stress harness: Generate 50 permutations of an object with 15 heterogeneous keys
    let keys = [
        "zeta", "alpha", "gamma", "delta", "epsilon", "theta", "iota", "kappa", "lambda", "mu",
        "nu", "xi", "omicron", "pi", "rho",
    ];

    let mut base_map = serde_json::Map::new();
    for (i, key) in keys.iter().enumerate() {
        let val = match i % 5 {
            0 => json!(i),
            1 => json!(format!("string_{}", i)),
            2 => json!([i, i + 1, i + 2]),
            3 => json!({ "nested_num": i * 10, "nested_flag": i % 2 == 0 }),
            _ => json!(i % 2 == 0),
        };
        base_map.insert(key.to_string(), val);
    }

    let base_obj = Value::Object(base_map);
    let canonical_reference = canonicalize_json(&base_obj).expect("reference canonicalization");
    let digest_reference =
        compute_challenge_digest("sess_oracle", "eval_tool", &canonical_reference, 1900000000);

    // Permute keys in 50 distinct arrangements
    for seed in 1..=50 {
        let mut permuted_keys = keys.to_vec();
        // Deterministic pseudo-shuffle using seed
        for j in 0..permuted_keys.len() {
            let swap_idx = (j * 7 + seed) % permuted_keys.len();
            permuted_keys.swap(j, swap_idx);
        }

        let mut permuted_map = serde_json::Map::new();
        for key in &permuted_keys {
            permuted_map.insert(key.to_string(), base_obj[key].clone());
        }

        let permuted_obj = Value::Object(permuted_map);
        let permuted_canon = canonicalize_json(&permuted_obj).expect("permuted canonicalization");
        let permuted_digest =
            compute_challenge_digest("sess_oracle", "eval_tool", &permuted_canon, 1900000000);

        assert_eq!(
            permuted_canon, canonical_reference,
            "Permutation #{seed} produced divergent canonical bytes"
        );
        assert_eq!(
            permuted_digest, digest_reference,
            "Permutation #{seed} produced divergent challenge digest"
        );
    }
}

#[test]
fn test_adversarial_case_collision_invariance() {
    // In JSON, keys are case-sensitive. "key" and "Key" are distinct keys.
    let obj = json!({
        "Key": 2,
        "key": 1
    });

    let canon = canonicalize_json(&obj).unwrap();
    let canon_str = String::from_utf8(canon).unwrap();

    let pos_upper = canon_str.find("\"Key\"").unwrap();
    let pos_lower = canon_str.find("\"key\"").unwrap();

    assert!(
        pos_upper < pos_lower,
        "'Key' (0x4B) must sort before 'key' (0x6B)"
    );
}
