use authkestra_engine::auth::ReproofRequirement;

/// Security tier demanded of callers before a tool may be invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpSecurityTier {
    /// Callable without authentication or with optional caller identity.
    Public,

    /// Requires a valid Bearer or DPoP-bound token validated via `authkestra-resource`
    /// containing all `required_scopes`.
    /// Returns RFC 9728 `WWW-Authenticate: Bearer resource_metadata="..."` on 401 Unauthorized,
    /// and `insufficient_scope` on 403 Forbidden.
    Scoped { required_scopes: Vec<String> },

    /// Demands both scope validation and a single-use cryptographic step-up approval
    /// bound to the exact tool name and JCS-canonicalized arguments.
    HumanApproved {
        required_scopes: Vec<String>,
        reproof: ReproofRequirement,
        approval_ttl_secs: u64,
    },
}

impl McpSecurityTier {
    /// Convenience helper for creating a `Public` security tier.
    pub fn public() -> Self {
        Self::Public
    }

    /// Convenience helper for creating a `Scoped` security tier.
    pub fn scoped(scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Scoped {
            required_scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }

    /// Convenience helper for creating a `HumanApproved` security tier.
    pub fn human_approved(
        scopes: impl IntoIterator<Item = impl Into<String>>,
        reproof: ReproofRequirement,
        approval_ttl_secs: u64,
    ) -> Self {
        Self::HumanApproved {
            required_scopes: scopes.into_iter().map(Into::into).collect(),
            reproof,
            approval_ttl_secs,
        }
    }
}
