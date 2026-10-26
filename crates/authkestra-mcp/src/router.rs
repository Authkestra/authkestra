use crate::approval::*;
use crate::broker::DownstreamTokenBroker;
use crate::canonicalize::*;
use crate::context::ToolContext;
use crate::error::McpError;
use crate::protocol::*;
use crate::resource_metadata::ProtectedResourceMetadata;
use crate::security::McpSecurityTier;
use authkestra_engine::auth::state::Identity;
use authkestra_engine::store::{AtomicConsume, KvStore};
use chrono::Utc;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Type alias for boxed asynchronous tool handler functions.
pub type BoxedToolHandler = Box<
    dyn Fn(
            serde_json::Value,
            ToolContext,
        ) -> Pin<Box<dyn Future<Output = Result<ToolCallResult, McpError>> + Send>>
        + Send
        + Sync,
>;

/// Definition of an MCP tool registered in `McpRouter`.
pub struct ToolDefinition {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: serde_json::Value,
    pub security_tier: McpSecurityTier,
    pub handler: BoxedToolHandler,
}

impl ToolDefinition {
    /// Creates a new `ToolDefinition` with asynchronous handler.
    pub fn new<F, Fut>(
        name: impl Into<String>,
        input_schema: serde_json::Value,
        security_tier: McpSecurityTier,
        handler: F,
    ) -> Self
    where
        F: Fn(serde_json::Value, ToolContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ToolCallResult, McpError>> + Send + 'static,
    {
        Self {
            name: name.into(),
            description: None,
            input_schema,
            security_tier,
            handler: Box::new(move |args, ctx| Box::pin(handler(args, ctx))),
        }
    }

    /// Attaches an optional description for the tool.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Core Model Context Protocol router and execution coordinator.
///
/// Handles `tools/list` discovery and `tools/call` execution with composable security tiers,
/// RFC 8785 JCS cryptographic parameter binding, pending step-up challenges, atomic replay defense,
/// and zero-trust downstream credential isolation.
#[derive(Clone)]
pub struct McpRouter {
    tools: Arc<HashMap<String, ToolDefinition>>,
    resource_metadata: Option<ProtectedResourceMetadata>,
    metadata_url: String,
    approval_base_url: String,
    token_broker: Option<Arc<dyn DownstreamTokenBroker>>,
    pending_store: Arc<dyn KvStore<PendingApprovalChallenge>>,
    execution_store: Arc<dyn AtomicConsume<ApprovedExecutionRecord>>,
    #[cfg(feature = "policy")]
    policy_engine: Option<Arc<authkestra_policy::CedarPolicyEngine>>,
}

impl McpRouter {
    /// Starts building a new `McpRouter`.
    pub fn builder(
        pending_store: Arc<dyn KvStore<PendingApprovalChallenge>>,
        execution_store: Arc<dyn AtomicConsume<ApprovedExecutionRecord>>,
    ) -> McpRouterBuilder {
        McpRouterBuilder::new(pending_store, execution_store)
    }

    /// Returns a reference to the configured Cedar policy engine, if any.
    #[cfg(feature = "policy")]
    pub fn policy_engine(&self) -> Option<&Arc<authkestra_policy::CedarPolicyEngine>> {
        self.policy_engine.as_ref()
    }

    /// Returns the protected resource metadata if configured.
    pub fn resource_metadata(&self) -> Option<&ProtectedResourceMetadata> {
        self.resource_metadata.as_ref()
    }

    /// Returns the configured protected resource metadata discovery URL.
    pub fn metadata_url(&self) -> &str {
        &self.metadata_url
    }

    /// Returns the base URL for step-up verification.
    pub fn approval_base_url(&self) -> &str {
        &self.approval_base_url
    }

    /// Returns a reference to the pending approval challenge store.
    pub fn pending_store(&self) -> &Arc<dyn KvStore<PendingApprovalChallenge>> {
        &self.pending_store
    }

    /// Returns a reference to the atomic execution record store.
    pub fn execution_store(&self) -> &Arc<dyn AtomicConsume<ApprovedExecutionRecord>> {
        &self.execution_store
    }

    /// Returns the registered tools map.
    pub fn tools(&self) -> &Arc<HashMap<String, ToolDefinition>> {
        &self.tools
    }

    /// Handles an incoming MCP JSON-RPC 2.0 request.
    pub async fn handle_json_rpc(
        &self,
        request: JsonRpcRequest,
        identity: Option<Identity>,
        session_id: String,
    ) -> JsonRpcResponse {
        tracing::debug!(
            method = %request.method,
            session_id = %session_id,
            identity = ?identity.as_ref().map(|i| (&i.provider_id, &i.external_id)),
            "handling MCP JSON-RPC request"
        );

        let id = request.id.clone();

        if request.jsonrpc != JSONRPC_VERSION {
            tracing::warn!(version = %request.jsonrpc, "invalid JSON-RPC version presented");
            return JsonRpcResponse {
                jsonrpc: JSONRPC_VERSION.to_string(),
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: RPC_INVALID_REQUEST,
                    message: format!(
                        "Invalid JSON-RPC version '{}': expected '{}'",
                        request.jsonrpc, JSONRPC_VERSION
                    ),
                    data: None,
                }),
            };
        }

        match request.method.as_str() {
            "tools/list" => {
                let mut tools_info: Vec<ToolInfo> = self
                    .tools
                    .values()
                    .map(|t| ToolInfo {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        input_schema: t.input_schema.clone(),
                    })
                    .collect();

                // Sort tools alphabetically for deterministic ordering
                tools_info.sort_by(|a, b| a.name.cmp(&b.name));

                tracing::debug!(count = tools_info.len(), "returning tools list");
                JsonRpcResponse {
                    jsonrpc: JSONRPC_VERSION.to_string(),
                    id,
                    result: serde_json::to_value(ToolListResult { tools: tools_info }).ok(),
                    error: None,
                }
            }
            "tools/call" => {
                let Some(params_val) = request.params else {
                    tracing::warn!("missing params object in tools/call request");
                    return JsonRpcResponse {
                        jsonrpc: JSONRPC_VERSION.to_string(),
                        id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: RPC_INVALID_PARAMS,
                            message: "Missing params in tools/call".to_string(),
                            data: None,
                        }),
                    };
                };

                let params: ToolCallParams = match serde_json::from_value(params_val) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse ToolCallParams");
                        return JsonRpcResponse {
                            jsonrpc: JSONRPC_VERSION.to_string(),
                            id,
                            result: None,
                            error: Some(JsonRpcError {
                                code: RPC_INVALID_PARAMS,
                                message: format!("Failed to parse params: {e}"),
                                data: None,
                            }),
                        };
                    }
                };

                match self.execute_tool(params, identity, session_id).await {
                    Ok(result) => JsonRpcResponse {
                        jsonrpc: JSONRPC_VERSION.to_string(),
                        id,
                        result: serde_json::to_value(result).ok(),
                        error: None,
                    },
                    Err(err) => {
                        tracing::debug!(error = ?err, "tool execution error returned to client");
                        JsonRpcResponse {
                            jsonrpc: JSONRPC_VERSION.to_string(),
                            id,
                            result: None,
                            error: Some(err.to_json_rpc_error()),
                        }
                    }
                }
            }
            other => {
                tracing::warn!(method = %other, "requested unknown JSON-RPC method");
                JsonRpcResponse {
                    jsonrpc: JSONRPC_VERSION.to_string(),
                    id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: RPC_METHOD_NOT_FOUND,
                        message: format!("Unknown method '{other}'"),
                        data: None,
                    }),
                }
            }
        }
    }

    /// Internal tool execution pipeline enforcing security tiers, cryptographic parameter binding,
    /// atomic replay defense, and context isolation.
    pub async fn execute_tool(
        &self,
        params: ToolCallParams,
        identity: Option<Identity>,
        session_id: String,
    ) -> Result<ToolCallResult, McpError> {
        let tool = self
            .tools
            .get(&params.name)
            .ok_or_else(|| McpError::ToolNotFound(params.name.clone()))?;

        let mut raw_args = match params.arguments {
            Some(serde_json::Value::Object(map)) => serde_json::Value::Object(map),
            None | Some(serde_json::Value::Null) => {
                serde_json::Value::Object(serde_json::Map::new())
            }
            _ => {
                return Err(McpError::InvalidArguments(
                    "Tool arguments must be a JSON object".to_string(),
                ));
            }
        };

        let mut tool_context = ToolContext::new(session_id.clone());
        if let Some(ref id) = identity {
            tool_context = tool_context.with_identity(id.clone());
        }
        if let Some(ref broker) = self.token_broker {
            tool_context = tool_context.with_broker(broker.clone());
        }

        #[cfg(feature = "policy")]
        if let Some(ref engine) = self.policy_engine {
            let principal_str = match identity {
                Some(ref id) => {
                    let escaped_ext = id.external_id.replace('\\', "\\\\").replace('"', "\\\"");
                    if id.provider_id.is_empty() {
                        format!(r#"User::"{escaped_ext}""#)
                    } else {
                        let escaped_prov =
                            id.provider_id.replace('\\', "\\\\").replace('"', "\\\"");
                        format!(r#"User::"{escaped_prov}|{escaped_ext}""#)
                    }
                }
                None => r#"User::"anonymous""#.to_string(),
            };

            let principal = authkestra_policy::parse_entity_uid(&principal_str).map_err(|e| {
                McpError::Internal(format!("Failed to parse principal entity uid: {e}"))
            })?;
            let action = authkestra_policy::parse_entity_uid(r#"Action::"call""#).map_err(|e| {
                McpError::Internal(format!("Failed to parse action entity uid: {e}"))
            })?;
            let escaped_tool = tool.name.replace('\\', "\\\\").replace('"', "\\\"");
            let resource =
                authkestra_policy::parse_entity_uid(&format!(r#"Tool::"{escaped_tool}""#))
                    .map_err(|e| {
                        McpError::Internal(format!("Failed to parse tool entity uid: {e}"))
                    })?;

            let tier_str = match &tool.security_tier {
                McpSecurityTier::Public => "Public",
                McpSecurityTier::Scoped { .. } => "Scoped",
                McpSecurityTier::HumanApproved { .. } => "HumanApproved",
            };

            let req_context = serde_json::json!({
                "arguments": raw_args,
                "session_id": session_id,
                "tier": tier_str,
            });

            let auth_request = authkestra_policy::AuthorizationRequest::builder()
                .principal(principal)
                .action(action)
                .resource(resource)
                .context(req_context)
                .build()
                .map_err(|e| {
                    McpError::Internal(format!("Failed to build authorization request: {e}"))
                })?;

            tracing::debug!(
                tool = %tool.name,
                principal = %auth_request.principal,
                "evaluating Cedar policy for MCP tool call"
            );

            let decision = engine
                .is_authorized(&auth_request)
                .await
                .map_err(|e| McpError::Internal(format!("Cedar policy evaluation error: {e}")))?;

            if decision.is_allowed() {
                tracing::info!(
                    tool = %tool.name,
                    principal = %auth_request.principal,
                    reasons = ?decision.reasons(),
                    "Cedar policy permitted MCP tool call"
                );
            } else {
                tracing::warn!(
                    tool = %tool.name,
                    principal = %auth_request.principal,
                    reasons = ?decision.reasons(),
                    errors = ?decision.errors(),
                    "Cedar policy DENIED MCP tool call"
                );
                return Err(McpError::Unauthorized(format!(
                    "Tool call '{}' was denied by policy",
                    tool.name
                )));
            }
        }

        match &tool.security_tier {
            McpSecurityTier::Public => {
                tracing::info!(tool = %tool.name, "executing Public tier tool");
                (tool.handler)(raw_args, tool_context).await
            }
            McpSecurityTier::Scoped { required_scopes } => {
                tracing::info!(
                    tool = %tool.name,
                    required_scopes = ?required_scopes,
                    "evaluating Scoped tier tool"
                );
                let caller_identity = identity.ok_or_else(|| {
                    tracing::warn!(tool = %tool.name, "unauthenticated call rejected for scoped tool");
                    McpError::Unauthorized("Caller identity or bearer token missing for scoped tool".to_string())
                })?;

                self.assert_scopes(&caller_identity, required_scopes)?;
                (tool.handler)(raw_args, tool_context).await
            }
            McpSecurityTier::HumanApproved {
                required_scopes,
                reproof,
                approval_ttl_secs,
            } => {
                tracing::info!(
                    tool = %tool.name,
                    required_scopes = ?required_scopes,
                    approval_ttl_secs = *approval_ttl_secs,
                    "evaluating HumanApproved tier tool"
                );
                let caller_identity = identity.ok_or_else(|| {
                    tracing::warn!(tool = %tool.name, "unauthenticated call rejected for HumanApproved tool");
                    McpError::Unauthorized(
                        "Caller identity or bearer token missing for HumanApproved tool".to_string(),
                    )
                })?;

                self.assert_scopes(&caller_identity, required_scopes)?;

                // Extract potential execution token from arguments
                let execution_token_opt = if let serde_json::Value::Object(ref mut map) = raw_args {
                    map.remove(APPROVAL_TOKEN_ARG_KEY)
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                } else {
                    None
                };

                let Some(execution_token) = execution_token_opt else {
                    // No execution token provided -> Mint PendingApprovalChallenge and return elicitation
                    let approval_id = Uuid::new_v4().to_string();
                    let expires_at = Utc::now().timestamp() + *approval_ttl_secs as i64;
                    let jcs_bytes = canonicalize_json(&raw_args)?;
                    let challenge_digest =
                        compute_challenge_digest(&session_id, &tool.name, &jcs_bytes, expires_at);

                    let challenge = PendingApprovalChallenge {
                        approval_id: approval_id.clone(),
                        session_id: session_id.clone(),
                        tool_name: tool.name.clone(),
                        challenge_digest: challenge_digest.clone(),
                        expires_at,
                        reproof_max_age_secs: reproof.max_age_secs,
                        reproof_require_step_up: reproof.require_step_up,
                        created_at: Utc::now().timestamp(),
                    };

                    tracing::info!(
                        approval_id = %approval_id,
                        tool = %tool.name,
                        challenge_digest = %challenge_digest,
                        expires_at = expires_at,
                        "persisting pending approval challenge in KvStore"
                    );

                    self.pending_store
                        .set(
                            &format!("mcp:pending:{}", approval_id),
                            challenge,
                            Duration::from_secs(*approval_ttl_secs),
                        )
                        .await
                        .map_err(|e| McpError::Store(e.to_string()))?;

                    let verification_url = if self.approval_base_url.is_empty() {
                        format!("/mcp/approve?id={}", approval_id)
                    } else {
                        format!("{}/mcp/approve?id={}", self.approval_base_url, approval_id)
                    };

                    let elicitation = StepUpElicitation {
                        approval_id: approval_id.clone(),
                        challenge_digest,
                        verification_url,
                        expires_at,
                        instructions: "Step-up human approval required. Verify the challenge digest with your authenticator or passkey.".to_string(),
                    };

                    return Err(McpError::StepUpRequired(Box::new(elicitation)));
                };

                // Single-use atomic consumption of execution token
                let record_key = format!("mcp:exec:{}", execution_token);
                let record_opt = self
                    .execution_store
                    .consume(&record_key)
                    .await
                    .map_err(|e| McpError::Store(e.to_string()))?;

                let Some(record) = record_opt else {
                    tracing::warn!(
                        token = %execution_token,
                        "execution token replay, expired, or invalid token rejected via AtomicConsume"
                    );
                    return Err(McpError::TokenReplayOrExpired);
                };

                // Validate binding attributes
                if record.tool_name != tool.name || record.session_id != session_id {
                    tracing::warn!(
                        record_tool = %record.tool_name,
                        target_tool = %tool.name,
                        record_session = %record.session_id,
                        session_id = %session_id,
                        "execution record mismatch: tool name or session does not match"
                    );
                    return Err(McpError::ParameterMismatch);
                }

                if Utc::now().timestamp() > record.expires_at {
                    tracing::warn!(expires_at = record.expires_at, "execution record expired");
                    return Err(McpError::TokenReplayOrExpired);
                }

                // Verify cryptographic parameter binding: canonicalize remaining arguments
                let jcs_bytes = canonicalize_json(&raw_args)?;
                let recomputed_digest = compute_challenge_digest(
                    &session_id,
                    &tool.name,
                    &jcs_bytes,
                    record.expires_at,
                );

                if recomputed_digest != record.challenge_digest {
                    tracing::error!(
                        expected = %record.challenge_digest,
                        computed = %recomputed_digest,
                        "CRITICAL: Parameter tampering detected! Arguments modified after human approval."
                    );
                    return Err(McpError::ParameterMismatch);
                }

                // Attach approver identity to tool context
                tool_context = tool_context.with_approver_identity(Identity {
                    provider_id: record.approver_provider_id,
                    external_id: record.approver_external_id,
                    email: None,
                    username: None,
                    attributes: HashMap::new(),
                });

                tracing::info!(
                    tool = %tool.name,
                    token = %execution_token,
                    "step-up verification passed, executing approved tool"
                );
                (tool.handler)(raw_args, tool_context).await
            }
        }
    }

    /// Verifies that all required scopes are granted on the identity.
    pub fn assert_scopes(&self, identity: &Identity, required: &[String]) -> Result<(), McpError> {
        let granted_str = identity
            .attributes
            .get("scope")
            .cloned()
            .unwrap_or_default();
        let granted_scopes: Vec<&str> = granted_str.split_whitespace().collect();

        for req in required {
            if !granted_scopes.iter().any(|s| s == req) {
                tracing::warn!(
                    required = %req,
                    granted = ?granted_scopes,
                    "caller lacks required scope"
                );
                return Err(McpError::Forbidden {
                    required: required.to_vec(),
                });
            }
        }
        Ok(())
    }

    /// Queries a pending approval challenge by `approval_id`.
    pub async fn query_pending_approval(
        &self,
        approval_id: &str,
    ) -> Result<Option<PendingApprovalChallenge>, McpError> {
        let key = format!("mcp:pending:{}", approval_id);
        self.pending_store
            .get(&key)
            .await
            .map_err(|e| McpError::Store(e.to_string()))
    }

    /// Approves a pending challenge on behalf of a human identity, checks reproof freshness,
    /// and mints a single-use execution proof token.
    pub async fn approve_challenge(
        &self,
        approval_id: &str,
        human_identity: &Identity,
    ) -> Result<ApprovalResult, McpError> {
        let key = format!("mcp:pending:{}", approval_id);
        let challenge = self
            .pending_store
            .get(&key)
            .await
            .map_err(|e| McpError::Store(e.to_string()))?
            .ok_or_else(|| {
                tracing::warn!(approval_id = %approval_id, "pending approval challenge not found or expired");
                McpError::Unauthorized("Pending approval challenge not found or expired".to_string())
            })?;

        // Check reproof requirements if tool definition specifies them
        if let Some(tool) = self.tools.get(&challenge.tool_name) {
            if let McpSecurityTier::HumanApproved { reproof, .. } = &tool.security_tier {
                tracing::debug!(
                    approval_id = %approval_id,
                    max_age_secs = reproof.max_age_secs,
                    require_step_up = reproof.require_step_up,
                    "checking reproof requirement for human approver identity"
                );
                reproof.check(human_identity)?;
            }
        }

        // Delete pending challenge so it cannot be approved twice
        let _ = self.pending_store.delete(&key).await;

        // Mint single-use execution token
        let execution_token = Uuid::new_v4().to_string();
        let record = ApprovedExecutionRecord {
            execution_token: execution_token.clone(),
            approval_id: challenge.approval_id,
            session_id: challenge.session_id,
            tool_name: challenge.tool_name,
            challenge_digest: challenge.challenge_digest,
            approver_external_id: human_identity.external_id.clone(),
            approver_provider_id: human_identity.provider_id.clone(),
            expires_at: challenge.expires_at,
            created_at: Utc::now().timestamp(),
        };

        let exec_key = format!("mcp:exec:{}", execution_token);
        let ttl_secs = (challenge.expires_at - Utc::now().timestamp()).max(1) as u64;
        self.execution_store
            .set(&exec_key, record, Duration::from_secs(ttl_secs))
            .await
            .map_err(|e| McpError::Store(e.to_string()))?;

        tracing::info!(
            approval_id = %approval_id,
            execution_token = %execution_token,
            approver = %human_identity.external_id,
            "human step-up approval recorded and execution proof token minted"
        );
        Ok(ApprovalResult {
            status: "approved".to_string(),
            execution_token,
        })
    }
}

/// Builder for constructing [`McpRouter`].
pub struct McpRouterBuilder {
    tools: HashMap<String, ToolDefinition>,
    resource_metadata: Option<ProtectedResourceMetadata>,
    metadata_url: String,
    approval_base_url: String,
    token_broker: Option<Arc<dyn DownstreamTokenBroker>>,
    pending_store: Arc<dyn KvStore<PendingApprovalChallenge>>,
    execution_store: Arc<dyn AtomicConsume<ApprovedExecutionRecord>>,
    #[cfg(feature = "policy")]
    policy_engine: Option<Arc<authkestra_policy::CedarPolicyEngine>>,
}

impl McpRouterBuilder {
    /// Creates a new builder with the required storage backends.
    pub fn new(
        pending_store: Arc<dyn KvStore<PendingApprovalChallenge>>,
        execution_store: Arc<dyn AtomicConsume<ApprovedExecutionRecord>>,
    ) -> Self {
        Self {
            tools: HashMap::new(),
            resource_metadata: None,
            metadata_url: "/.well-known/oauth-protected-resource".to_string(),
            approval_base_url: "".to_string(),
            token_broker: None,
            pending_store,
            execution_store,
            #[cfg(feature = "policy")]
            policy_engine: None,
        }
    }

    /// Sets the Cedar policy engine for declarative tool authorization.
    #[cfg(feature = "policy")]
    pub fn with_policy_engine(mut self, engine: Arc<authkestra_policy::CedarPolicyEngine>) -> Self {
        self.policy_engine = Some(engine);
        self
    }

    /// Registers a tool in the router.
    pub fn tool(mut self, definition: ToolDefinition) -> Self {
        self.tools.insert(definition.name.clone(), definition);
        self
    }

    /// Sets RFC 9728 Protected Resource Metadata document.
    pub fn resource_metadata(mut self, metadata: ProtectedResourceMetadata) -> Self {
        self.resource_metadata = Some(metadata);
        self
    }

    /// Sets the path or URL where RFC 9728 metadata is served.
    pub fn metadata_url(mut self, url: impl Into<String>) -> Self {
        self.metadata_url = url.into();
        self
    }

    /// Sets the base URL used in step-up verification URLs.
    pub fn approval_base_url(mut self, url: impl Into<String>) -> Self {
        self.approval_base_url = url.into();
        self
    }

    /// Sets the downstream token broker.
    pub fn token_broker(mut self, broker: Arc<dyn DownstreamTokenBroker>) -> Self {
        self.token_broker = Some(broker);
        self
    }

    /// Builds the configured [`McpRouter`].
    pub fn build(self) -> McpRouter {
        McpRouter {
            tools: Arc::new(self.tools),
            resource_metadata: self.resource_metadata,
            metadata_url: self.metadata_url,
            approval_base_url: self.approval_base_url,
            token_broker: self.token_broker,
            pending_store: self.pending_store,
            execution_store: self.execution_store,
            #[cfg(feature = "policy")]
            policy_engine: self.policy_engine,
        }
    }
}
