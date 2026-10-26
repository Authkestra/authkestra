//! Actix-web extractors and helpers for Cedar ABAC policy authorization.

use actix_web::{dev::Payload, web, Error, FromRequest, HttpRequest};
use authkestra_resource::PolicyGuard;
use futures::future::{err, ok, Ready};
use std::sync::Arc;

/// An Actix-web extractor that pulls [`Arc<PolicyGuard>`] out of `app_data`.
pub struct AuthPolicyGuard(pub Arc<PolicyGuard>);

impl std::ops::Deref for AuthPolicyGuard {
    type Target = PolicyGuard;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for AuthPolicyGuard {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        if let Some(guard) = req.app_data::<web::Data<Arc<PolicyGuard>>>() {
            ok(AuthPolicyGuard(guard.get_ref().clone()))
        } else if let Some(guard) = req.app_data::<web::Data<PolicyGuard>>() {
            ok(AuthPolicyGuard(guard.clone().into_inner()))
        } else {
            err(actix_web::error::ErrorInternalServerError(
                "PolicyGuard not found in Actix app_data",
            ))
        }
    }
}
