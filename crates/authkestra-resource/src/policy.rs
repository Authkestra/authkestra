//! Cedar ABAC policy guard and principal mapping for resource server authorization.

use authkestra_engine::auth::state::Identity;
use authkestra_policy::{
    cedar_policy::EntityUid, parse_entity_uid, AuthorizationRequest, CedarPolicyEngine, Decision,
    PolicyError,
};
use std::sync::Arc;

/// Trait for mapping an authenticated [`Identity`] to a Cedar principal [`EntityUid`] and request context.
pub trait PrincipalMapper: Send + Sync {
    /// Derives a Cedar principal UID from the authenticated identity.
    fn principal(&self, identity: &Identity) -> Result<EntityUid, PolicyError>;

    /// Returns claims to expose to Cedar policies as the request `context`.
    ///
    /// Defaults to an empty JSON object `{}`.
    fn context(&self, _identity: &Identity) -> serde_json::Value {
        serde_json::json!({})
    }
}

/// Default [`PrincipalMapper`] producing `User::"{provider_id}|{external_id}"`
/// (or `User::"{external_id}"` if `provider_id` is empty).
#[derive(Debug, Default, Clone)]
pub struct DefaultPrincipalMapper;

impl PrincipalMapper for DefaultPrincipalMapper {
    fn principal(&self, identity: &Identity) -> Result<EntityUid, PolicyError> {
        let escaped_ext = identity
            .external_id
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let uid_str = if identity.provider_id.is_empty() {
            format!(r#"User::"{escaped_ext}""#)
        } else {
            let escaped_prov = identity
                .provider_id
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            format!(r#"User::"{escaped_prov}|{escaped_ext}""#)
        };
        parse_entity_uid(&uid_str)
    }
}

/// A policy-enforcing guard that evaluates Cedar authorization policies for authenticated identities.
pub struct PolicyGuard {
    engine: Arc<CedarPolicyEngine>,
    mapper: Box<dyn PrincipalMapper>,
}

impl PolicyGuard {
    /// Creates a new `PolicyGuard` wrapping the given Cedar policy engine with [`DefaultPrincipalMapper`].
    pub fn new(engine: Arc<CedarPolicyEngine>) -> Self {
        Self {
            engine,
            mapper: Box::new(DefaultPrincipalMapper),
        }
    }

    /// Sets a custom [`PrincipalMapper`].
    pub fn with_mapper<M: PrincipalMapper + 'static>(mut self, mapper: M) -> Self {
        self.mapper = Box::new(mapper);
        self
    }

    /// Returns a reference to the inner policy engine.
    pub fn engine(&self) -> &Arc<CedarPolicyEngine> {
        &self.engine
    }

    /// Returns a reference to the principal mapper.
    pub fn mapper(&self) -> &dyn PrincipalMapper {
        &*self.mapper
    }

    /// Authorizes an identity for `action` on `resource`, optionally merging extra `context`.
    pub async fn authorize(
        &self,
        identity: &Identity,
        action: &str,
        resource: &str,
        context: Option<serde_json::Value>,
    ) -> Result<Decision, PolicyError> {
        let principal = self.mapper.principal(identity)?;
        let action_uid = if action.contains("::") {
            parse_entity_uid(action)?
        } else {
            let escaped = action.replace('\\', "\\\\").replace('"', "\\\"");
            parse_entity_uid(&format!(r#"Action::"{escaped}""#))?
        };
        let resource_uid = if resource.contains("::") {
            parse_entity_uid(resource)?
        } else {
            let escaped = resource.replace('\\', "\\\\").replace('"', "\\\"");
            parse_entity_uid(&format!(r#"Resource::"{escaped}""#))?
        };

        let mut req_context = self.mapper.context(identity);
        if let Some(ctx) = context {
            if let (serde_json::Value::Object(ref mut base), serde_json::Value::Object(extra)) =
                (&mut req_context, ctx)
            {
                for (k, v) in extra {
                    base.insert(k, v);
                }
            }
        }

        let request = AuthorizationRequest::builder()
            .principal(principal)
            .action(action_uid)
            .resource(resource_uid)
            .context(req_context)
            .build()?;

        self.authorize_request(&request).await
    }

    /// Evaluates a raw [`AuthorizationRequest`], emitting structured tracing on permit or deny.
    pub async fn authorize_request(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Decision, PolicyError> {
        let decision = self.engine.is_authorized(request).await?;
        if decision.is_allowed() {
            tracing::info!(
                principal = %request.principal,
                action = %request.action,
                resource = %request.resource,
                reasons = ?decision.reasons(),
                "Cedar policy authorization PERMIT"
            );
        } else {
            tracing::warn!(
                principal = %request.principal,
                action = %request.action,
                resource = %request.resource,
                reasons = ?decision.reasons(),
                errors = ?decision.errors(),
                "Cedar policy authorization DENY"
            );
        }
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkestra_policy::{MemoryResourceLoader, PolicyEngine};

    #[tokio::test]
    async fn test_policy_guard_permit_and_deny() {
        let policies = r#"
            permit(
                principal == User::"github|alice",
                action == Action::"read",
                resource == Resource::"document_1"
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

        let guard = PolicyGuard::new(Arc::new(engine));

        let alice = Identity {
            provider_id: "github".to_string(),
            external_id: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            username: Some("alice".to_string()),
            attributes: Default::default(),
        };

        let bob = Identity {
            provider_id: "github".to_string(),
            external_id: "bob".to_string(),
            email: Some("bob@example.com".to_string()),
            username: Some("bob".to_string()),
            attributes: Default::default(),
        };

        let charlie = Identity {
            provider_id: "github".to_string(),
            external_id: "charlie".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        };

        // Alice reading document_1 -> Permit
        let decision = guard
            .authorize(&alice, "read", "document_1", None)
            .await
            .expect("auth alice");
        assert!(decision.is_allowed());

        // Alice writing document_1 -> Deny (default deny)
        let decision = guard
            .authorize(&alice, "write", "document_1", None)
            .await
            .expect("auth alice write");
        assert!(!decision.is_allowed());

        // Bob reading document_1 -> Deny (explicit forbid)
        let decision = guard
            .authorize(&bob, "read", "document_1", None)
            .await
            .expect("auth bob");
        assert!(!decision.is_allowed());

        // Charlie reading document_1 -> Deny (default deny)
        let decision = guard
            .authorize(&charlie, "read", "document_1", None)
            .await
            .expect("auth charlie");
        assert!(!decision.is_allowed());
    }
}
