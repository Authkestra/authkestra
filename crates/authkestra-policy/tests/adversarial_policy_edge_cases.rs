//! Empirical edge cases in policy evaluation for Milestone 2 Challenger 2:
//! - Missing principal attributes (missing field evaluation errors, fail-closed on forbid, safe has-guards)
//! - Empty policies (parse, build, reload, default-deny)
//! - Invalid syntax (parse error, reserved id, duplicate id, reload safety)

use authkestra_policy::cedar_policy::RestrictedExpression;
use authkestra_policy::{
    parse_entity_uid, parse_policies, AuthorizationRequest, EntityRecord, MemoryResourceLoader,
    PolicyEngine,
};

fn uid(source: &str) -> authkestra_policy::cedar_policy::EntityUid {
    parse_entity_uid(source).expect("valid entity uid")
}

fn request(principal: &str, action: &str, resource: &str) -> AuthorizationRequest {
    AuthorizationRequest::builder()
        .principal_str(principal)
        .action_str(action)
        .resource_str(resource)
        .build()
        .expect("valid request")
}

// ---------------------------------------------------------------------------
// 1. Missing principal attributes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_missing_principal_attribute_in_permit_causes_evaluation_error_and_denies() {
    // Policy directly accesses `principal.department`, but principal has no such attribute.
    let policy = r#"
        @id("dept-access")
        permit(principal, action == Action::"read", resource)
        when { principal.department == "engineering" };
    "#;

    let loader = MemoryResourceLoader::new();
    loader.extend([
        EntityRecord::new(uid(r#"User::"alice""#)), // No attributes added!
        EntityRecord::new(uid(r#"Doc::"report""#)),
    ]);

    let engine = PolicyEngine::builder()
        .policies(policy)
        .loader(loader)
        .build()
        .expect("engine builds");

    let req = request(r#"User::"alice""#, r#"Action::"read""#, r#"Doc::"report""#);
    let decision = engine
        .is_authorized(&req)
        .await
        .expect("evaluation succeeds");

    // The permit is skipped due to evaluation error on missing attribute, resulting in default deny.
    assert!(!decision.is_allowed(), "Must be denied by default");
    assert!(
        !decision.errors().is_empty(),
        "Must record evaluation error for missing attribute"
    );
    assert!(
        decision.errors()[0].contains("department") || decision.errors()[0].contains("attribute"),
        "Diagnostic error must mention attribute: {:?}",
        decision.errors()
    );
}

#[tokio::test]
async fn test_missing_principal_attribute_in_forbid_fails_closed_with_unreliable_decision() {
    // Blanket permit, but a forbid that checks a missing principal attribute.
    // If Cedar skips the forbid, granting an allow would fail-open.
    // PolicyEngine must refuse and return PolicyError::UnreliableDecision.
    let policy = r#"
        @id("allow-read")
        permit(principal, action == Action::"read", resource);

        @id("block-suspended")
        forbid(principal, action, resource)
        when { principal.is_suspended == true };
    "#;

    let loader = MemoryResourceLoader::new();
    loader.extend([
        EntityRecord::new(uid(r#"User::"charlie""#)), // Has NO is_suspended attribute!
        EntityRecord::new(uid(r#"Doc::"report""#)),
    ]);

    let engine = PolicyEngine::builder()
        .policies(policy)
        .loader(loader)
        .build()
        .expect("engine builds");

    let req = request(
        r#"User::"charlie""#,
        r#"Action::"read""#,
        r#"Doc::"report""#,
    );
    let error = engine.is_authorized(&req).await.expect_err(
        "Allow that skipped a forbid with missing attribute must be rejected as unreliable",
    );

    assert_eq!(error.code(), "unreliable_decision");
    assert!(
        error.to_string().contains("block-suspended"),
        "Error must name the skipped forbid policy: {error}"
    );
}

#[tokio::test]
async fn test_principal_attribute_guarded_with_has_evaluates_cleanly_without_error() {
    // Using `has` guard prevents Cedar evaluation error when attribute is absent.
    let policy = r#"
        @id("safe-dept-check")
        permit(principal, action == Action::"read", resource)
        when { principal has department && principal.department == "engineering" };
    "#;

    let loader = MemoryResourceLoader::new();
    loader.extend([
        EntityRecord::new(uid(r#"User::"bob""#)), // No department attribute
        EntityRecord::new(uid(r#"Doc::"report""#)),
    ]);

    let engine = PolicyEngine::builder()
        .policies(policy)
        .loader(loader)
        .build()
        .expect("engine builds");

    let req = request(r#"User::"bob""#, r#"Action::"read""#, r#"Doc::"report""#);
    let decision = engine
        .is_authorized(&req)
        .await
        .expect("evaluation succeeds");

    assert!(
        !decision.is_allowed(),
        "Denied cleanly because condition was false"
    );
    assert!(
        decision.errors().is_empty(),
        "Guard with `has` must produce zero evaluation errors: {:?}",
        decision.errors()
    );
}

#[tokio::test]
async fn test_principal_with_valid_attribute_permits_successfully() {
    let policy = r#"
        @id("dept-access")
        permit(principal, action == Action::"read", resource)
        when { principal.department == "engineering" };
    "#;

    let loader = MemoryResourceLoader::new();
    loader.extend([
        EntityRecord::new(uid(r#"User::"engineer_dave""#)).attribute(
            "department",
            RestrictedExpression::new_string("engineering".to_string()),
        ),
        EntityRecord::new(uid(r#"Doc::"report""#)),
    ]);

    let engine = PolicyEngine::builder()
        .policies(policy)
        .loader(loader)
        .build()
        .expect("engine builds");

    let req = request(
        r#"User::"engineer_dave""#,
        r#"Action::"read""#,
        r#"Doc::"report""#,
    );
    let decision = engine
        .is_authorized(&req)
        .await
        .expect("evaluation succeeds");

    assert!(decision.is_allowed(), "Permitted with matching attribute");
    assert_eq!(decision.reasons(), ["dept-access"]);
    assert!(decision.errors().is_empty());
}

// ---------------------------------------------------------------------------
// 2. Empty policies
// ---------------------------------------------------------------------------

#[test]
fn test_empty_policies_parsing_yields_zero_policies() {
    let parsed = parse_policies("").expect("empty policy string is syntactically valid");
    assert_eq!(parsed.policies().count(), 0);
}

#[tokio::test]
async fn test_empty_policies_engine_defaults_to_strict_deny() {
    let loader = MemoryResourceLoader::new();
    let engine = PolicyEngine::builder()
        .policies("")
        .loader(loader)
        .build()
        .expect("build with empty policies succeeds");

    assert_eq!(engine.policy_count(), 0);

    let req = request(r#"User::"any""#, r#"Action::"read""#, r#"Doc::"any""#);
    let decision = engine
        .is_authorized(&req)
        .await
        .expect("evaluation succeeds");

    assert!(
        !decision.is_allowed(),
        "Empty policy engine must deny every request"
    );
    assert!(decision.reasons().is_empty());
    assert!(decision.errors().is_empty());
}

#[test]
fn test_missing_policy_set_in_builder_fails_configuration() {
    let loader = MemoryResourceLoader::new();
    let err = PolicyEngine::builder()
        .loader(loader)
        .build()
        .expect_err("building without policies must fail");

    assert_eq!(err.code(), "configuration");
    assert!(err.to_string().contains("policy set"));
}

#[tokio::test]
async fn test_reload_to_empty_policies_clears_active_policies_and_denies() {
    let loader = MemoryResourceLoader::new();
    let engine = PolicyEngine::builder()
        .policies(r#"permit(principal, action, resource);"#)
        .loader(loader)
        .build()
        .expect("engine builds");

    assert_eq!(engine.policy_count(), 1);

    let req = request(r#"User::"u""#, r#"Action::"a""#, r#"Doc::"d""#);
    assert!(engine.is_authorized(&req).await.unwrap().is_allowed());

    // Reload with empty string -> 0 policies
    engine
        .reload("")
        .expect("reload with empty policy set succeeds");
    assert_eq!(engine.policy_count(), 0);

    // Subsequent request must be denied
    assert!(!engine.is_authorized(&req).await.unwrap().is_allowed());
}

// ---------------------------------------------------------------------------
// 3. Invalid syntax
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_syntax_syntax_error_reported() {
    let err = parse_policies("permit(principal, ").expect_err("truncated policy syntax");
    assert_eq!(err.code(), "policy_parse");
}

#[test]
fn test_invalid_syntax_reserved_policy_id_rejected() {
    let err = parse_policies(r#"@id("policy0") permit(principal, action, resource);"#)
        .expect_err("reserved id policy0 must be rejected");
    assert_eq!(err.code(), "reserved_policy_id");
}

#[test]
fn test_invalid_syntax_duplicate_policy_id_rejected() {
    let source = r#"
        @id("unique_rule")
        permit(principal, action, resource);

        @id("unique_rule")
        forbid(principal, action, resource);
    "#;
    let err = parse_policies(source).expect_err("duplicate policy id must be rejected");
    assert_eq!(err.code(), "policy_parse");
    assert!(err.to_string().contains("unique_rule"));
}

#[tokio::test]
async fn test_reload_with_invalid_syntax_preserves_active_policy_set() {
    let loader = MemoryResourceLoader::new();
    let engine = PolicyEngine::builder()
        .policies(r#"@id("initial-allow") permit(principal, action, resource);"#)
        .loader(loader)
        .build()
        .expect("engine builds");

    let req = request(r#"User::"alice""#, r#"Action::"read""#, r#"Doc::"doc""#);
    assert!(engine.is_authorized(&req).await.unwrap().is_allowed());

    // Attempt reload with completely invalid syntax
    let err = engine
        .reload("INVALID SYNTAX !!! [[[ NOT CEDAR")
        .expect_err("invalid syntax reload must error");
    assert_eq!(err.code(), "policy_parse");

    // Engine must still retain 1 active policy and continue serving traffic!
    assert_eq!(engine.policy_count(), 1);
    let decision = engine.is_authorized(&req).await.expect("still functional");
    assert!(decision.is_allowed());
    assert_eq!(decision.reasons(), ["initial-allow"]);
}
