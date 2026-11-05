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

/// Percent-encodes `:` and `%` in a principal identity component to prevent delimiter collisions
/// while preserving all other Unicode characters unchanged.
pub fn encode_principal_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            ':' => out.push_str("%3A"),
            _ => out.push(ch),
        }
    }
    out
}

/// Constructs a Cedar `User` entity UID string from provider and external IDs
/// using unambiguous percent-encoding and a `:` separator (`{encoded_provider}:{encoded_external_id}`).
///
/// # Migration Note
///
/// Earlier versions formatted composite principal IDs with an unescaped `|` delimiter
/// (`User::"{provider_id}|{external_id}"`), or omitted the provider prefix when `provider_id`
/// was empty. This function always includes the `:` delimiter (`User::"{prov}:{ext}"`) and
/// percent-encodes `%` (`%25`) and `:` (`%3A`) within each component so `("a:b", "c")` and
/// `("a", "b:c")` cannot collide. When upgrading existing Cedar policy sets or entity stores,
/// update any hardcoded `User::"provider|id"` literals (especially in `forbid` rules) to the
/// `User::"provider:id"` format.
pub fn format_principal_uid_str(provider_id: &str, external_id: &str) -> String {
    let enc_prov = encode_principal_component(provider_id);
    let enc_ext = encode_principal_component(external_id);
    let combined = format!("{enc_prov}:{enc_ext}");
    let escaped = combined.replace('\\', "\\\\").replace('"', "\\\"");
    format!(r#"User::"{escaped}""#)
}

/// Default [`PrincipalMapper`] producing `User::"{encoded_provider}:{encoded_external_id}"`.
#[derive(Debug, Default, Clone)]
pub struct DefaultPrincipalMapper;

impl PrincipalMapper for DefaultPrincipalMapper {
    fn principal(&self, identity: &Identity) -> Result<EntityUid, PolicyError> {
        let uid_str = format_principal_uid_str(&identity.provider_id, &identity.external_id);
        tracing::debug!(
            provider_id = %identity.provider_id,
            external_id = %identity.external_id,
            uid_str = %uid_str,
            "mapped identity to principal entity UID"
        );
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
                principal == User::"github:alice",
                action == Action::"read",
                resource == Resource::"document_1"
            );
            forbid(
                principal == User::"github:bob",
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

    /// Verifies that `DefaultPrincipalMapper` prevents collisions across delimiter boundaries
    /// and preserves non-ASCII Unicode characters in identity components.
    #[test]
    fn test_principal_id_collision_prevention() {
        let mapper = DefaultPrincipalMapper;

        // Identity 1: empty provider, external_id "github:alice"
        let id1 = Identity {
            provider_id: "".to_string(),
            external_id: "github:alice".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        };

        // Identity 2: provider "github", external_id "alice"
        let id2 = Identity {
            provider_id: "github".to_string(),
            external_id: "alice".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        };

        // Identity 3: provider "github:sub", external_id "alice"
        let id3 = Identity {
            provider_id: "github:sub".to_string(),
            external_id: "alice".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        };

        // Identity 4: provider "github", external_id "sub:alice"
        let id4 = Identity {
            provider_id: "github".to_string(),
            external_id: "sub:alice".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        };

        let uid1 = mapper.principal(&id1).unwrap().to_string();
        let uid2 = mapper.principal(&id2).unwrap().to_string();
        let uid3 = mapper.principal(&id3).unwrap().to_string();
        let uid4 = mapper.principal(&id4).unwrap().to_string();

        assert_eq!(uid1, r#"User::":github%3Aalice""#);
        assert_eq!(uid2, r#"User::"github:alice""#);
        assert_eq!(uid3, r#"User::"github%3Asub:alice""#);
        assert_eq!(uid4, r#"User::"github:sub%3Aalice""#);

        assert_ne!(
            uid1, uid2,
            "empty provider must not collide with non-empty provider"
        );
        assert_ne!(
            uid3, uid4,
            "colon inside provider must not collide with colon inside external_id"
        );

        // Non-ASCII external_id is preserved without UTF-8 byte corruption
        let unicode_id = Identity {
            provider_id: "oidc".to_string(),
            external_id: "müller:अदिति%100".to_string(),
            email: None,
            username: None,
            attributes: Default::default(),
        };
        assert_eq!(
            encode_principal_component(&unicode_id.external_id),
            "müller%3Aअदिति%25100"
        );
        let unicode_uid = mapper.principal(&unicode_id).unwrap().to_string();
        assert_eq!(unicode_uid, r#"User::"oidc:müller%3Aअदिति%25100""#);
    }
}
