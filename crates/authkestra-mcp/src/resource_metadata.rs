use serde::{Deserialize, Serialize};

/// RFC 9728 OAuth 2.0 Protected Resource Metadata document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
    /// The protected resource's canonical URI.
    pub resource: String,
    /// Authorization server issuer identifiers that can issue tokens for this resource.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authorization_servers: Vec<String>,
    /// List of OAuth 2.0 scopes supported/accepted by this resource.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub scopes_supported: Vec<String>,
    /// Token transmission methods supported (e.g. `["header"]`).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub bearer_methods_supported: Vec<String>,
    /// URL pointing to developer documentation for this protected resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,
    /// Human-readable name of the protected resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
}

impl ProtectedResourceMetadata {
    /// Creates a new `ProtectedResourceMetadata` with the required `resource` URI.
    pub fn new(resource: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            authorization_servers: Vec::new(),
            scopes_supported: Vec::new(),
            bearer_methods_supported: vec!["header".to_string()],
            resource_documentation: None,
            resource_name: None,
        }
    }

    /// Appends an authorization server issuer URI.
    pub fn with_auth_server(mut self, auth_server: impl Into<String>) -> Self {
        self.authorization_servers.push(auth_server.into());
        self
    }

    /// Sets supported scopes.
    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes_supported = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets developer documentation URL.
    pub fn with_documentation(mut self, doc_url: impl Into<String>) -> Self {
        self.resource_documentation = Some(doc_url.into());
        self
    }

    /// Sets human-readable resource name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.resource_name = Some(name.into());
        self
    }
}

/// Formats the RFC 9728 / RFC 6750 `WWW-Authenticate` header value for an unauthenticated request.
pub fn www_authenticate_unauthorized(metadata_url: &str) -> String {
    format!("Bearer resource_metadata=\"{metadata_url}\"")
}

/// Formats the RFC 9728 / RFC 6750 `WWW-Authenticate` header value when caller presents insufficient scope.
pub fn www_authenticate_insufficient_scope(
    metadata_url: &str,
    required_scopes: &[String],
) -> String {
    let scopes_str = required_scopes.join(" ");
    format!(
        "Bearer error=\"insufficient_scope\", scope=\"{scopes_str}\", resource_metadata=\"{metadata_url}\""
    )
}

/// Formats the RFC 9728 / RFC 6750 `WWW-Authenticate` header value when token is invalid or expired.
pub fn www_authenticate_invalid_token(metadata_url: &str) -> String {
    format!("Bearer error=\"invalid_token\", resource_metadata=\"{metadata_url}\"")
}
