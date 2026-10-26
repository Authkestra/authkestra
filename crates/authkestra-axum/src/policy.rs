//! Axum extractors and helpers for Cedar ABAC policy authorization.

use crate::helpers::AxumError;
use authkestra_resource::PolicyGuard;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use std::sync::Arc;

/// An Axum extractor that pulls [`Arc<PolicyGuard>`] out of the application state.
pub struct AuthPolicyGuard(pub Arc<PolicyGuard>);

impl std::ops::Deref for AuthPolicyGuard {
    type Target = PolicyGuard;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for AuthPolicyGuard
where
    S: Send + Sync,
    Arc<PolicyGuard>: FromRef<S>,
{
    type Rejection = AxumError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let guard = Arc::<PolicyGuard>::from_ref(state);
        Ok(AuthPolicyGuard(guard))
    }
}
