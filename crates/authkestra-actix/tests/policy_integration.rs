use actix_web::{http::StatusCode, test, web, App, HttpResponse};
use authkestra_actix::AuthPolicyGuard;
use authkestra_engine::auth::state::Identity;
use authkestra_policy::{MemoryResourceLoader, PolicyEngine};
use authkestra_resource::PolicyGuard;
use serde_json::json;
use std::sync::Arc;

async fn view_document(guard: AuthPolicyGuard) -> Result<HttpResponse, actix_web::Error> {
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
        .map_err(|_| actix_web::error::ErrorInternalServerError("policy error"))?;

    if decision.is_allowed() {
        Ok(HttpResponse::Ok().json(json!({ "status": "ok", "doc": "secret document" })))
    } else {
        Ok(HttpResponse::Forbidden().finish())
    }
}

async fn admin_action(guard: AuthPolicyGuard) -> Result<HttpResponse, actix_web::Error> {
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
        .map_err(|_| actix_web::error::ErrorInternalServerError("policy error"))?;

    if decision.is_allowed() {
        Ok(HttpResponse::Ok().json(json!({ "status": "deleted" })))
    } else {
        Ok(HttpResponse::Forbidden().finish())
    }
}

#[actix_web::test]
async fn test_actix_policy_guard_permit_and_deny() {
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

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(policy_guard))
            .route("/document", web::get().to(view_document))
            .route("/admin", web::get().to(admin_action)),
    )
    .await;

    // Alice reading doc_1 -> 200 OK
    let req = test::TestRequest::get().uri("/document").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Bob deleting system -> 403 Forbidden
    let req = test::TestRequest::get().uri("/admin").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
