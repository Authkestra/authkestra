use crate::approval::StepUpElicitation;
use crate::broker::BrokerError;
use crate::protocol::*;
use authkestra_engine::auth::ReproofFailure;
use thiserror::Error;

pub type McpResult<T> = Result<T, McpError>;

/// Primary error type for the `authkestra-mcp` crate.
#[derive(Debug, Error)]
pub enum McpError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: insufficient scope. required: {required:?}")]
    Forbidden { required: Vec<String> },

    #[error("human step-up approval required")]
    StepUpRequired(Box<StepUpElicitation>),

    #[error("parameter mismatch: tool arguments do not match approved challenge")]
    ParameterMismatch,

    #[error("execution token invalid, expired, or already consumed")]
    TokenReplayOrExpired,

    #[error("tool '{0}' not found")]
    ToolNotFound(String),

    #[error("invalid arguments: {0}")]
    InvalidArguments(String),

    #[error("tool execution failed: {0}")]
    Execution(String),

    #[error("canonicalization failed: {0}")]
    Canonicalization(String),

    #[error("storage error: {0}")]
    Store(String),

    #[error("broker error: {0}")]
    Broker(#[from] BrokerError),

    #[error("reproof error: {0:?}")]
    Reproof(#[from] ReproofFailure),

    #[error("internal error: {0}")]
    Internal(String),
}

impl McpError {
    /// Maps this `McpError` to its canonical JSON-RPC 2.0 error representation.
    pub fn to_json_rpc_error(&self) -> JsonRpcError {
        match self {
            Self::StepUpRequired(elicitation) => JsonRpcError {
                code: RPC_STEP_UP_REQUIRED,
                message: "Human step-up approval required".to_string(),
                data: serde_json::to_value(elicitation).ok(),
            },
            Self::Unauthorized(msg) => JsonRpcError {
                code: RPC_UNAUTHORIZED,
                message: format!("Unauthorized: {msg}"),
                data: None,
            },
            Self::Forbidden { required } => JsonRpcError {
                code: RPC_UNAUTHORIZED,
                message: format!("Insufficient scope. Required: {required:?}"),
                data: None,
            },
            Self::ParameterMismatch => JsonRpcError {
                code: RPC_PARAMETER_MISMATCH,
                message: "Parameter mismatch: tool arguments modified after step-up approval"
                    .to_string(),
                data: None,
            },
            Self::TokenReplayOrExpired => JsonRpcError {
                code: RPC_TOKEN_REPLAY_OR_EXPIRED,
                message: "Execution proof token is invalid, expired, or already consumed"
                    .to_string(),
                data: None,
            },
            Self::ToolNotFound(name) => JsonRpcError {
                code: RPC_METHOD_NOT_FOUND,
                message: format!("Tool '{name}' not found"),
                data: None,
            },
            Self::InvalidArguments(msg) => JsonRpcError {
                code: RPC_INVALID_PARAMS,
                message: format!("Invalid params: {msg}"),
                data: None,
            },
            Self::Execution(msg)
            | Self::Canonicalization(msg)
            | Self::Store(msg)
            | Self::Internal(msg) => JsonRpcError {
                code: RPC_INTERNAL_ERROR,
                message: msg.clone(),
                data: None,
            },
            Self::Broker(e) => JsonRpcError {
                code: RPC_INTERNAL_ERROR,
                message: e.to_string(),
                data: None,
            },
            Self::Reproof(e) => JsonRpcError {
                code: RPC_UNAUTHORIZED,
                message: format!("Reproof check failed: {e:?}"),
                data: None,
            },
        }
    }
}
