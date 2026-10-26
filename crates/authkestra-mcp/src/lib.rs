//! # Authkestra MCP
//!
//! Embedded Model Context Protocol (MCP) security, delegated authorization,
//! and cryptographic step-up approval crate for Authkestra.
//!
//! Provides:
//! - Three composable security tiers: `Public`, `Scoped`, and `HumanApproved`.
//! - Cryptographic parameter binding via RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256.
//! - Human-in-the-loop (HITL) step-up approval ceremonies with single-use replay defense via `AtomicConsume`.
//! - Parameter tampering defense rejecting altered arguments between approval and execution.
//! - Zero-trust downstream credential isolation via `EncryptedKvTokenVault` and `ToolContext`.
//! - RFC 9728 OAuth 2.0 Protected Resource Metadata and `WWW-Authenticate` response formatting.

pub mod approval;
pub mod broker;
pub mod canonicalize;
pub mod context;
pub mod error;
pub mod protocol;
pub mod resource_metadata;
pub mod router;
pub mod security;
pub mod vault;

pub use approval::{
    ApprovalResult, ApprovalSubmission, ApprovedExecutionRecord, PendingApprovalChallenge,
    StepUpElicitation, APPROVAL_TOKEN_ARG_KEY, APPROVAL_TOKEN_HEADER,
};
pub use broker::{BrokerError, DownstreamToken, DownstreamTokenBroker};
pub use canonicalize::{canonicalize_arguments, canonicalize_json, compute_challenge_digest};
pub use context::ToolContext;
pub use error::{McpError, McpResult};
pub use protocol::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, ToolCallParams, ToolCallResult, ToolContent,
    ToolInfo, ToolListResult, JSONRPC_VERSION, RPC_INTERNAL_ERROR, RPC_INVALID_PARAMS,
    RPC_INVALID_REQUEST, RPC_METHOD_NOT_FOUND, RPC_PARAMETER_MISMATCH, RPC_PARSE_ERROR,
    RPC_STEP_UP_REQUIRED, RPC_TOKEN_REPLAY_OR_EXPIRED, RPC_UNAUTHORIZED,
};
pub use resource_metadata::{
    www_authenticate_insufficient_scope, www_authenticate_invalid_token,
    www_authenticate_unauthorized, ProtectedResourceMetadata,
};
pub use router::{BoxedToolHandler, McpRouter, McpRouterBuilder, ToolDefinition};
pub use security::McpSecurityTier;
pub use vault::EncryptedKvTokenVault;
