use serde::{Deserialize, Serialize};

/// The internal argument parameter key used to pass the single-use execution token
/// upon retry of an approved tool call.
pub const APPROVAL_TOKEN_ARG_KEY: &str = "_authkestra_approval_token";

/// Standard HTTP header where clients can alternatively supply the execution proof token.
pub const APPROVAL_TOKEN_HEADER: &str = "x-authkestra-approval-token";

/// Pending approval challenge persisted in `KvStore` awaiting human step-up proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingApprovalChallenge {
    pub approval_id: String,
    pub session_id: String,
    pub tool_name: String,
    pub challenge_digest: String,
    pub expires_at: i64,
    pub reproof_max_age_secs: u64,
    pub reproof_require_step_up: bool,
    pub created_at: i64,
}

/// Approved execution record persisted in `KvStore` for single-use consumption via `AtomicConsume`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovedExecutionRecord {
    pub execution_token: String,
    pub approval_id: String,
    pub session_id: String,
    pub tool_name: String,
    pub challenge_digest: String,
    pub approver_external_id: String,
    pub approver_provider_id: String,
    pub expires_at: i64,
    pub created_at: i64,
}

/// Structured elicitation response returned to client when step-up approval is required.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepUpElicitation {
    pub approval_id: String,
    pub challenge_digest: String,
    pub verification_url: String,
    pub expires_at: i64,
    pub instructions: String,
}

/// Request payload submitted to the approval endpoint to verify and approve a pending challenge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalSubmission {
    pub approval_id: String,
}

/// Result returned from the step-up approval ceremony.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalResult {
    /// Status description, e.g. "approved"
    pub status: String,
    /// The minted single-use execution token
    pub execution_token: String,
}
