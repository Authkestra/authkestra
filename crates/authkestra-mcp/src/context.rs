use crate::broker::{BrokerError, DownstreamTokenBroker};
use authkestra_engine::auth::state::Identity;
use std::sync::Arc;

/// Execution context provided to tool handlers.
///
/// Encapsulates caller identity, approver identity (from human step-up approval),
/// session identifiers, and credential resolution without exposing credentials to the LLM.
#[derive(Clone)]
pub struct ToolContext {
    /// The authenticated identity of the agent or caller making the tool call.
    pub identity: Option<Identity>,
    /// The human identity that approved the step-up challenge (if tool is HumanApproved).
    pub approver_identity: Option<Identity>,
    /// The MCP session identifier.
    pub session_id: String,
    /// Optional zero-trust downstream token broker.
    pub token_broker: Option<Arc<dyn DownstreamTokenBroker>>,
}

impl ToolContext {
    /// Creates a new `ToolContext` for a given `session_id`.
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            identity: None,
            approver_identity: None,
            session_id: session_id.into(),
            token_broker: None,
        }
    }

    /// Attaches the caller identity.
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Attaches the human approver identity.
    pub fn with_approver_identity(mut self, identity: Identity) -> Self {
        self.approver_identity = Some(identity);
        self
    }

    /// Attaches the downstream token broker.
    pub fn with_broker(mut self, broker: Arc<dyn DownstreamTokenBroker>) -> Self {
        self.token_broker = Some(broker);
        self
    }

    /// Resolves an active downstream API token for the caller's identity on `service` with `scopes`.
    pub async fn get_downstream_token(
        &self,
        service: &str,
        scopes: &[&str],
    ) -> Result<Option<String>, BrokerError> {
        let Some(identity) = &self.identity else {
            tracing::debug!("no identity present in ToolContext to resolve downstream token");
            return Ok(None);
        };
        let Some(broker) = &self.token_broker else {
            tracing::debug!("no DownstreamTokenBroker configured in ToolContext");
            return Ok(None);
        };
        broker.resolve_token(identity, service, scopes).await
    }
}
