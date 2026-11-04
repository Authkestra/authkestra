use crate::auth::error::AuthError;
use async_trait::async_trait;

/// Pluggable storage backend for user credentials (Passwords, Passkeys, TOTP keys).
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Save a generic credential serialized as a JSON Value mapped to a user and credential type.
    ///
    /// The `credential_id` (or `id`) field of `data`, when present, identifies the credential:
    /// an implementation is expected to *replace* an existing credential stored under the same
    /// id rather than store a second copy alongside it. Callers rely on this to rotate a
    /// credential without a window in which the user has none — TOTP re-enrollment writes the
    /// new secret under a stable id before retiring the old ones. A store that appends instead
    /// will keep serving the superseded credential from [`Self::get_credentials`].
    ///
    /// Credentials with no id are always appended.
    async fn save_credential(
        &self,
        user_id: &str,
        cred_type: &str,
        data: serde_json::Value,
    ) -> Result<(), AuthError>;

    /// Retrieve all credentials of a specific type mapped to a user.
    async fn get_credentials(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> Result<Vec<serde_json::Value>, AuthError>;

    /// Update transient fields of an existing credential (e.g. signature counter).
    async fn update_credential(
        &self,
        credential_id: &str,
        data: serde_json::Value,
    ) -> Result<(), AuthError>;

    /// Delete a specific credential by its id for a user and credential type.
    ///
    /// Returns `Ok(true)` if the credential existed and was deleted,
    /// `Ok(false)` if the credential did not exist,
    /// and `Err(AuthError::Unsupported)` if the store does not implement deletion.
    ///
    /// # Atomicity
    ///
    /// `Ok(true)` means **this call** removed the credential. Among
    /// concurrent callers naming the same `credential_id`, at most one may
    /// observe `true`.
    ///
    /// This is a requirement on implementations, not a description of what
    /// most of them happen to do, because callers are entitled to treat the
    /// `true` as winning a race. A single-use credential — a recovery code,
    /// say — is redeemed by looking it up and then accepting only if this
    /// returns `true`, which is sound exactly as far as this promise holds. A
    /// store implementing deletion as "look it up, then delete it" would let
    /// two concurrent redemptions of the same code both see `true`, and the
    /// resulting defect is invisible in serial tests.
    ///
    /// A single `DELETE ... WHERE id = ?` reporting affected rows satisfies
    /// this, as does a map removal under a lock. A read followed by a
    /// separate write does not.
    ///
    /// The default implementation returns `Err(AuthError::Unsupported)`.
    /// Out-of-tree stores that cannot implement deletion will receive an error
    /// rather than a silent no-op, making revocation failures visible to the
    /// caller. A store that cannot delete atomically should return that error
    /// too: `Ok(false)` from a store that never deletes anything is the silent
    /// no-op this contract exists to rule out.
    async fn delete_credential(
        &self,
        user_id: &str,
        cred_type: &str,
        credential_id: &str,
    ) -> Result<bool, AuthError> {
        let _ = (user_id, cred_type, credential_id);
        Err(AuthError::Unsupported)
    }

    /// Delete all credentials of a specific type for a user.
    ///
    /// Returns `Ok(n)` where `n` is the number of credentials deleted (0 if none existed),
    /// and `Err(AuthError::Unsupported)` if the store does not implement deletion.
    ///
    /// The default implementation returns `Err(AuthError::Unsupported)`.
    /// Out-of-tree stores that cannot implement deletion will receive an error
    /// rather than a silent no-op, making revocation failures visible to the caller.
    async fn delete_credentials(&self, user_id: &str, cred_type: &str) -> Result<u64, AuthError> {
        let _ = (user_id, cred_type);
        Err(AuthError::Unsupported)
    }

    /// Atomically claim a TOTP step for a credential, advancing its `last_used_step`
    /// to `matched_step` if and only if `matched_step > last_used_step` (or if `last_used_step` was unset).
    ///
    /// # Atomicity
    ///
    /// Returns `Ok(true)` if this call successfully claimed and advanced the step.
    /// Returns `Ok(false)` if the step was already claimed (i.e. `matched_step <= last_used_step`).
    /// Returns `Err(AuthError::Unsupported)` by default for stores that do not implement atomic claim.
    async fn claim_totp_step(
        &self,
        user_id: &str,
        credential_id: &str,
        matched_step: u64,
    ) -> Result<bool, AuthError> {
        let _ = (user_id, credential_id, matched_step);
        Err(AuthError::Unsupported)
    }
}
