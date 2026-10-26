use authkestra_axum::AuthPolicyGuard;
use authkestra_engine::auth::state::Identity;
use authkestra_policy::{MemoryResourceLoader, PolicyEngine};
use authkestra_resource::PolicyGuard;
use axum::{
    body::Body,
    extract::{FromRef, State},
    http::{Request, StatusCode},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Clone)]
struct AppState {
    policy_guard: Arc<PolicyGuard>,
}

impl FromRef<AppState> for Arc<PolicyGuard> {
    fn from_ref(state: &AppState) -> Self {
        state.policy_guard.clone()
    }
}

async fn view_document(
    guard: AuthPolicyGuard,
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let alice = Identity {
        provider_id: "github".to_string(),
        external_id: "alice".to_string(),
        email: None,
        username: None,
        attributes: Default::default(),
    };

    let decision = guard
        .authorize(&alice, "read", "doc_1", None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if decision.is_allowed() {
        Ok(Json(json!({ "status": "ok", "doc": "secret document" })))
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

async fn admin_action(
    guard: AuthPolicyGuard,
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bob = Identity {
        provider_id: "github".to_string(),
        external_id: "bob".to_string(),
        email: None,
        username: None,
        attributes: Default::default(),
    };

    let decision = guard
        .authorize(&bob, "delete", "system", None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if decision.is_allowed() {
        Ok(Json(json!({ "status": "deleted" })))
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

#[tokio::test]
async fn test_axum_policy_guard_permit_and_deny() {
    let policies = r#"
        permit(
            principal == User::"github|alice",
            action == Action::"read",
            resource == Resource::"doc_1"
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
        .expect("engine build");

    let policy_guard = Arc::new(PolicyGuard::new(Arc::new(engine)));
    let state = AppState { policy_guard };

    let app = Router::new()
        .route("/document", get(view_document))
        .route("/admin", get(admin_action))
        .with_state(state);

    // Alice reading doc_1 -> 200 OK
    let req = Request::builder()
        .uri("/document")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Bob deleting system -> 403 Forbidden
    let req = Request::builder()
        .uri("/admin")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
