use crate::auth::{
    error::AuthError, state::Identity, AuthInput, AuthMethod, CredentialStore, ReproofRequirement,
};
use async_trait::async_trait;
use totp_rs::{Algorithm, TOTP};

/// Extracts the non-empty credential identifier (`credential_id` or fallback `id`) from a TOTP credential object.
fn extract_totp_credential_id(cred: &serde_json::Value) -> Option<&str> {
    for key in ["credential_id", "id"] {
        if let Some(id) = cred
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|id| !id.trim().is_empty())
        {
            return Some(id);
        }
    }
    None
}

/// TOTP authentication method.
///
/// # Credential Format
///
/// Stored TOTP credentials must be JSON objects containing a non-empty `"secret"` (Base32) and
/// a non-empty `"credential_id"` (or `"id"`) field so replay-protection step claims can address
/// the record atomically. Legacy raw-string secrets without a credential identifier are not
/// accepted by [`TotpAuthMethod::authenticate`] or counted by [`TotpAuthMethod::has_enrolled`],
/// and are retired via [`CredentialStore::delete_credentials`] when the user re-enrolls with
/// [`TotpAuthMethod::register_totp`].
#[non_exhaustive]
pub struct TotpAuthMethod<S: CredentialStore> {
    store: S,
}

impl<S: CredentialStore> TotpAuthMethod<S> {
    /// Create a new `TotpAuthMethod` with the given CredentialStore.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Helper to generate a new TOTP secret and return the Base32 secret and registration URI (e.g. for QR codes).
    ///
    /// TOTP re-enrolment replaces any existing secret for the user rather than accumulating them.
    /// This prevents the situation where a user scans a new QR code but gets an authenticator that
    /// never works because the old secret still matches first.
    ///
    /// The new secret is saved *before* the old ones are removed, so a failure part way through
    /// never leaves the user without a working TOTP credential; see the comments below.
    ///
    /// # Re-proof
    ///
    /// Enrolment is gated on `gate`: `identity` must satisfy it or nothing is
    /// written and the call fails with [`AuthError::Credentials`]. A live
    /// session is deliberately not enough — a stolen one would otherwise be
    /// able to enrol a factor its holder controls and the account's owner
    /// does not know about. See [`ReproofRequirement`] for the full
    /// reasoning, and pick the window there rather than here.
    ///
    /// The secret is filed under `identity.external_id`, which is why the
    /// account to enrol is named by the re-proved identity rather than by a
    /// separate `user_id` argument. Letting the caller pass the two
    /// independently would reinstate the same vulnerability one level up: a
    /// freshly re-proved session for one account could name another
    /// account's id. It is also the id the authentication path already
    /// requires — [`AuthInput::Totp`]'s `user_id` is the credential-store
    /// key, and `Engine::authenticate` rejects a step-up whose verified
    /// identity does not match the `sub` its continuation token names.
    pub async fn register_totp(
        &self,
        identity: &Identity,
        gate: &ReproofRequirement,
        issuer: &str,
        account_name: &str,
    ) -> Result<(String, String), AuthError> {
        gate.check(identity)?;
        let user_id = identity.external_id.as_str();
        let secret = totp_rs::Secret::generate_secret();
        let secret_b32 = match secret.to_encoded() {
            totp_rs::Secret::Encoded(s) => s,
            _ => unreachable!(),
        }; // Base32 encoded secret
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret
                .to_bytes()
                .map_err(|e| AuthError::Internal(e.to_string()))?,
            Some(issuer.to_string()),
            account_name.to_string(),
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let url = totp.get_url();

        // Use a stable credential_id derived from user_id so re-enrollment replaces the old secret.
        // A user can only have one TOTP secret at a time, so use a deterministic ID.
        let credential_id = format!("totp:{}", user_id);

        // Snapshot the TOTP credentials that already exist. Superseded credentials under
        // non-deterministic identifiers (stale_ids) must be retired before saving the new
        // credential so that a retirement failure does not leave an existing usable secret
        // replaced by a new secret that is never returned.
        let existing = self.store.get_credentials(user_id, "totp").await?;
        let mut stale_ids = Vec::new();
        let mut unidentified = 0usize;
        let mut has_legacy_raw_string = false;
        let mut replacing = false;
        for cred in &existing {
            if cred.is_string() {
                has_legacy_raw_string = true;
                continue;
            }
            match extract_totp_credential_id(cred) {
                // Stored under the deterministic id: `save_credential` is expected to replace it.
                Some(id) if id == credential_id => replacing = true,
                Some(id) => stale_ids.push(id.to_string()),
                None => unidentified += 1,
            }
        }
        if unidentified > 0 {
            tracing::error!(
                user_id = %user_id,
                count = unidentified,
                "Cannot rotate TOTP: existing credentials carry no credential_id and cannot be safely retired"
            );
            return Err(AuthError::Internal(
                "Cannot rotate TOTP: existing credentials carry no credential_id and cannot be safely retired".into(),
            ));
        }
        if has_legacy_raw_string {
            tracing::info!(
                user_id = %user_id,
                "Retiring legacy raw-string TOTP credentials via delete_credentials before re-enrollment"
            );
            self.store.delete_credentials(user_id, "totp").await?;
            stale_ids.clear();
            replacing = false;
        }

        // Retire superseded secrets before saving the new secret. If retirement fails,
        // the existing usable secret (if any) is preserved intact and no new unreturned secret is written.
        for stale_id in &stale_ids {
            match self
                .store
                .delete_credential(user_id, "totp", stale_id)
                .await
            {
                Ok(true) => {
                    tracing::debug!(user_id = %user_id, credential_id = %stale_id, "Deleted superseded TOTP credential");
                }
                Ok(false) => {
                    tracing::error!(
                        user_id = %user_id,
                        credential_id = %stale_id,
                        "Failed to delete superseded TOTP credential: not found"
                    );
                    return Err(AuthError::Internal(format!(
                        "Failed to retire superseded TOTP credential {stale_id}"
                    )));
                }
                Err(AuthError::Unsupported) => {
                    tracing::error!(
                        user_id = %user_id,
                        count = stale_ids.len(),
                        "Store does not support delete_credential; cannot safely retire superseded TOTP secrets"
                    );
                    return Err(AuthError::Unsupported);
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        user_id = %user_id,
                        credential_id = %stale_id,
                        "Failed to delete superseded TOTP credential"
                    );
                    return Err(e);
                }
            }
        }

        let val = serde_json::json!({
            "credential_id": credential_id,
            "secret": secret_b32.clone(),
            "last_used_step": 0
        });
        self.store
            .save_credential(user_id, "totp", val.clone())
            .await?;

        // `CredentialStore::save_credential` is documented to replace a credential stored under
        // the same id, which is what makes the save above safe to do. Not every store
        // honours that, and one that appends leaves two secrets sharing the deterministic id —
        // indistinguishable to `delete_credential`, so the only way to retire the old one is to
        // drop the id and write the secret again. That reintroduces the window this ordering
        // avoids, but only for non-conforming stores, and only on re-enrollment.
        if replacing {
            let duplicates = self
                .store
                .get_credentials(user_id, "totp")
                .await?
                .iter()
                .filter(|c| extract_totp_credential_id(c) == Some(credential_id.as_str()))
                .count();
            if duplicates > 1 {
                tracing::warn!(
                    user_id = %user_id,
                    duplicates,
                    "Credential store appended instead of replacing the TOTP secret; rewriting it"
                );
                match self
                    .store
                    .delete_credential(user_id, "totp", &credential_id)
                    .await
                {
                    // Only rewrite once the copies are known to be gone; saving again after a
                    // delete that removed nothing would just add a third copy.
                    Ok(true) => self.store.save_credential(user_id, "totp", val).await?,
                    Ok(false) => {
                        tracing::error!(
                            user_id = %user_id,
                            "Store reported nothing to delete under the TOTP credential id; duplicate credentials remain"
                        );
                        return Err(AuthError::Internal(
                            "Failed to retire duplicate TOTP credentials".into(),
                        ));
                    }
                    Err(AuthError::Unsupported) => {
                        tracing::error!(
                            user_id = %user_id,
                            "Store neither replaces nor deletes credentials; aborting TOTP rotation"
                        );
                        return Err(AuthError::Unsupported);
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        Ok((secret_b32, url))
    }
}

#[async_trait]
#[async_trait]
impl<S: CredentialStore + 'static> AuthMethod for TotpAuthMethod<S> {
    fn name(&self) -> &str {
        crate::auth::state::METHOD_NAME_TOTP
    }

    async fn has_enrolled(&self, user_id: &str) -> Result<bool, AuthError> {
        let creds = self.store.get_credentials(user_id, "totp").await?;
        Ok(creds.iter().any(|c| {
            extract_totp_credential_id(c).is_some()
                && c.get("secret")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
        }))
    }

    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError> {
        let AuthInput::Totp { user_id, code } = input else {
            return Err(AuthError::InvalidInput);
        };

        let creds = self.store.get_credentials(&user_id, "totp").await?;
        let Some(secret_val) = creds.first() else {
            return Err(AuthError::Credentials(
                "TOTP not registered for this user".into(),
            ));
        };

        let (secret_b32, credential_id, last_used_step) = if let Some(obj) = secret_val.as_object()
        {
            let secret = obj
                .get("secret")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let cred_id = extract_totp_credential_id(secret_val).map(|s| s.to_string());
            let step = obj
                .get("last_used_step")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            (secret, cred_id, step)
        } else if secret_val.is_string() {
            (String::new(), None, 0)
        } else {
            return Err(AuthError::Internal(
                "Invalid stored TOTP secret format".to_string(),
            ));
        };

        let cred_id = match credential_id {
            Some(id) if !id.trim().is_empty() => id,
            _ => {
                tracing::error!(
                    user_id = %user_id,
                    "TOTP credential has no valid credential_id; rejecting identifierless credential"
                );
                return Err(AuthError::Credentials(
                    "TOTP credential missing required identifier".into(),
                ));
            }
        };

        if secret_b32.is_empty() {
            return Err(AuthError::Internal(
                "Invalid stored TOTP secret".to_string(),
            ));
        }

        let secret = totp_rs::Secret::Encoded(secret_b32.clone());
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret
                .to_bytes()
                .map_err(|e| AuthError::Internal(e.to_string()))?,
            None,
            "".to_string(),
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        // Time calculations for replay protection
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .as_secs();

        let basestep = t / totp.step - (totp.skew as u64);
        let mut matched_step = None;
        for i in 0..(totp.skew as u16) * 2 + 1 {
            let step = basestep + (i as u64);
            let step_time = step * totp.step;
            if totp.generate(step_time) == code && step > last_used_step {
                matched_step = Some(step);
                break;
            }
        }

        if let Some(step) = matched_step {
            match self.store.claim_totp_step(&user_id, &cred_id, step).await {
                Ok(true) => {
                    tracing::debug!(
                        user_id = %user_id,
                        credential_id = %cred_id,
                        step = step,
                        "Successfully claimed TOTP step"
                    );
                }
                Ok(false) => {
                    tracing::warn!(
                        user_id = %user_id,
                        credential_id = %cred_id,
                        step = step,
                        "TOTP step was already consumed or is outdated"
                    );
                    return Err(AuthError::Credentials(
                        "Invalid or replayed TOTP code".into(),
                    ));
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        user_id = %user_id,
                        credential_id = %cred_id,
                        "Failed to claim TOTP step in credential store"
                    );
                    return Err(e);
                }
            }

            Ok(Identity {
                provider_id: "totp".to_string(),
                external_id: user_id.clone(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            })
        } else {
            Err(AuthError::Credentials(
                "Invalid or replayed TOTP code".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::auth::state::IDENTITY_ATTR_AUTH_TIME;

    use std::collections::HashMap;
    use std::sync::Mutex;

    /// An identity that authenticated just now, as `Engine::authenticate`
    /// would have stamped it — enough to satisfy [`permissive_gate`].
    fn fresh_identity(user_id: &str) -> Identity {
        let mut attributes = std::collections::HashMap::new();
        attributes.insert(
            IDENTITY_ATTR_AUTH_TIME.to_string(),
            chrono::Utc::now().timestamp().to_string(),
        );
        Identity {
            provider_id: "test".to_string(),
            external_id: user_id.to_string(),
            email: None,
            username: None,
            attributes,
        }
    }

    /// A wide window, so these tests exercise enrolment rather than the gate.
    /// The gate has its own tests in `auth::reproof`, and the tests that
    /// assert it actually blocks enrolment build their own narrow one.
    fn permissive_gate() -> ReproofRequirement {
        ReproofRequirement::new(3600)
    }

    struct MockStore {
        creds: Mutex<HashMap<String, Vec<serde_json::Value>>>,
    }

    #[async_trait]
    impl CredentialStore for MockStore {
        async fn save_credential(
            &self,
            user_id: &str,
            cred_type: &str,
            data: serde_json::Value,
        ) -> Result<(), AuthError> {
            let key = format!("{user_id}:{cred_type}");
            self.creds
                .lock()
                .unwrap()
                .entry(key)
                .or_default()
                .push(data);
            Ok(())
        }

        async fn get_credentials(
            &self,
            user_id: &str,
            cred_type: &str,
        ) -> Result<Vec<serde_json::Value>, AuthError> {
            let key = format!("{user_id}:{cred_type}");
            Ok(self
                .creds
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_default())
        }

        async fn update_credential(
            &self,
            credential_id: &str,
            data: serde_json::Value,
        ) -> Result<(), AuthError> {
            let mut creds = self.creds.lock().unwrap();
            for val_list in creds.values_mut() {
                for val in val_list.iter_mut() {
                    if let Some(obj) = val.as_object_mut() {
                        if obj.get("credential_id").and_then(|v| v.as_str()) == Some(credential_id)
                        {
                            if let Some(update_obj) = data.as_object() {
                                for (k, v) in update_obj {
                                    obj.insert(k.clone(), v.clone());
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        }

        async fn delete_credential(
            &self,
            user_id: &str,
            cred_type: &str,
            credential_id: &str,
        ) -> Result<bool, AuthError> {
            let key = format!("{user_id}:{cred_type}");
            let mut creds = self.creds.lock().unwrap();
            if let Some(val_list) = creds.get_mut(&key) {
                let original_len = val_list.len();
                val_list.retain(|val| extract_totp_credential_id(val) != Some(credential_id));
                Ok(val_list.len() < original_len)
            } else {
                Ok(false)
            }
        }

        async fn delete_credentials(
            &self,
            user_id: &str,
            cred_type: &str,
        ) -> Result<u64, AuthError> {
            let key = format!("{user_id}:{cred_type}");
            let mut creds = self.creds.lock().unwrap();
            if let Some(val_list) = creds.remove(&key) {
                Ok(val_list.len() as u64)
            } else {
                Ok(0)
            }
        }

        async fn claim_totp_step(
            &self,
            user_id: &str,
            credential_id: &str,
            matched_step: u64,
        ) -> Result<bool, AuthError> {
            let key = format!("{user_id}:totp");
            let mut creds = self.creds.lock().unwrap();
            let Some(val_list) = creds.get_mut(&key) else {
                return Ok(false);
            };
            for val in val_list.iter_mut() {
                if extract_totp_credential_id(val) == Some(credential_id) {
                    if let Some(obj) = val.as_object_mut() {
                        let current = obj
                            .get("last_used_step")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        if matched_step > current {
                            obj.insert(
                                "last_used_step".to_string(),
                                serde_json::json!(matched_step),
                            );
                            return Ok(true);
                        } else {
                            return Ok(false);
                        }
                    }
                }
            }
            Ok(false)
        }
    }

    /// The vulnerability this gate closes (#382): a session alone must not
    /// be enough to enrol a factor. A stale identity is what a stolen cookie
    /// looks like — still a valid session, but no recent proof of identity —
    /// and it must not be able to write a secret it controls.
    #[tokio::test]
    async fn a_stale_identity_cannot_enrol_a_secret() {
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };
        let totp_method = TotpAuthMethod::new(store);

        let mut attributes = HashMap::new();
        attributes.insert(
            IDENTITY_ATTR_AUTH_TIME.to_string(),
            (chrono::Utc::now().timestamp() - 3600).to_string(),
        );
        let stale = Identity {
            provider_id: "test".to_string(),
            external_id: "victim".to_string(),
            email: None,
            username: None,
            attributes,
        };

        let result = totp_method
            .register_totp(&stale, &ReproofRequirement::new(300), "Engine", "victim")
            .await;

        assert!(matches!(result, Err(AuthError::Credentials(_))));
        // The point of the assertion: not merely that the call reported an
        // error, but that nothing was written. An attacker who gets a secret
        // stored and *then* sees an error has still taken the account.
        assert!(totp_method
            .store
            .get_credentials("victim", "totp")
            .await
            .unwrap()
            .is_empty());
    }

    /// An identity that never went through `Engine::authenticate` carries no
    /// `auth_time`, and is refused rather than waved through.
    #[tokio::test]
    async fn an_identity_with_no_auth_time_cannot_enrol_a_secret() {
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };
        let totp_method = TotpAuthMethod::new(store);

        let unproven = Identity {
            provider_id: "test".to_string(),
            external_id: "victim".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let result = totp_method
            .register_totp(&unproven, &ReproofRequirement::new(300), "Engine", "victim")
            .await;

        assert!(matches!(result, Err(AuthError::Credentials(_))));
        assert!(totp_method
            .store
            .get_credentials("victim", "totp")
            .await
            .unwrap()
            .is_empty());
    }

    /// The secret is filed under the re-proved identity, never under a
    /// separately supplied id — which is what stops a freshly re-proved
    /// session for one account from enrolling a factor against another.
    #[tokio::test]
    async fn the_secret_is_filed_under_the_re_proved_identity() {
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };
        let totp_method = TotpAuthMethod::new(store);

        totp_method
            .register_totp(
                &fresh_identity("attacker"),
                &permissive_gate(),
                "Engine",
                "victim@example.com",
            )
            .await
            .unwrap();

        assert_eq!(
            totp_method
                .store
                .get_credentials("attacker", "totp")
                .await
                .unwrap()
                .len(),
            1
        );
        // The account name is only ever cosmetic — it lands in the otpauth
        // URI, not in the store key.
        assert!(totp_method
            .store
            .get_credentials("victim@example.com", "totp")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_totp_flow() {
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };
        let totp_method = TotpAuthMethod::new(store);

        // Register a TOTP key for user
        let (secret_b32, uri) = totp_method
            .register_totp(
                &fresh_identity("user123"),
                &permissive_gate(),
                "Engine",
                "user123",
            )
            .await
            .unwrap();
        assert!(!secret_b32.is_empty());
        assert!(uri.contains("otpauth://totp/"));

        // Get the current TOTP code using the totp crate
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(secret_b32).to_bytes().unwrap(),
            None,
            "".to_string(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();

        // Verify successful auth
        let identity = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: code.clone(),
            })
            .await
            .unwrap();

        assert_eq!(identity.external_id, "user123");

        // Verify failure on wrong code
        let err = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: "000000".to_string(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Credentials(_)));

        // Verify replay protection (re-submitting the exact same valid code should fail)
        let replay_err = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: code.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(replay_err, AuthError::Credentials(_)));
    }

    #[tokio::test]
    async fn test_totp_reenrollment_replaces_secret() {
        // Regression test for issue #326: TOTP re-enrollment should replace the old secret,
        // not accumulate. A user scanning a new QR code must get a working authenticator.
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };
        let totp_method = TotpAuthMethod::new(store);

        // First enrollment
        let (secret1_b32, _) = totp_method
            .register_totp(
                &fresh_identity("user123"),
                &permissive_gate(),
                "Engine",
                "user123",
            )
            .await
            .unwrap();

        // Verify first secret works
        let totp1 = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(secret1_b32.clone())
                .to_bytes()
                .unwrap(),
            None,
            "".to_string(),
        )
        .unwrap();
        let code1 = totp1.generate_current().unwrap();

        let identity = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: code1,
            })
            .await
            .unwrap();
        assert_eq!(identity.external_id, "user123");

        // Second enrollment (re-registration)
        let (secret2_b32, _) = totp_method
            .register_totp(
                &fresh_identity("user123"),
                &permissive_gate(),
                "Engine",
                "user123",
            )
            .await
            .unwrap();

        // secret2 should be different from secret1
        assert_ne!(secret1_b32, secret2_b32);

        // Verify the NEW secret works
        let totp2 = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(secret2_b32.clone())
                .to_bytes()
                .unwrap(),
            None,
            "".to_string(),
        )
        .unwrap();
        let code2 = totp2.generate_current().unwrap();

        let identity = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: code2,
            })
            .await
            .unwrap();
        assert_eq!(identity.external_id, "user123");

        // Verify the OLD secret NO LONGER works (crucial check!)
        let totp1_new = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(secret1_b32).to_bytes().unwrap(),
            None,
            "".to_string(),
        )
        .unwrap();
        let code1_new = totp1_new.generate_current().unwrap();

        let auth_result = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: code1_new,
            })
            .await;
        assert!(matches!(auth_result, Err(AuthError::Credentials(_))));

        // Verify the store holds exactly one TOTP credential
        let creds = totp_method
            .store
            .get_credentials("user123", "totp")
            .await
            .unwrap();
        assert_eq!(
            creds.len(),
            1,
            "Store should hold exactly one TOTP credential after re-enrollment"
        );
    }

    #[tokio::test]
    async fn test_totp_reenrollment_retires_legacy_uuid_credential() {
        // Credentials written before the deterministic id scheme carry a random uuid, so the
        // new `totp:{user_id}` id never collides with them. Re-enrollment must still retire
        // them, or the revoked secret keeps authenticating from the front of the list.
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };

        let legacy_secret = match totp_rs::Secret::generate_secret().to_encoded() {
            totp_rs::Secret::Encoded(s) => s,
            _ => unreachable!(),
        };
        store
            .save_credential(
                "user123",
                "totp",
                serde_json::json!({
                    "credential_id": uuid::Uuid::new_v4().to_string(),
                    "secret": legacy_secret.clone(),
                    "last_used_step": 0
                }),
            )
            .await
            .unwrap();

        let totp_method = TotpAuthMethod::new(store);
        let (new_secret_b32, _) = totp_method
            .register_totp(
                &fresh_identity("user123"),
                &permissive_gate(),
                "Engine",
                "user123",
            )
            .await
            .unwrap();

        let creds = totp_method
            .store
            .get_credentials("user123", "totp")
            .await
            .unwrap();
        assert_eq!(
            creds.len(),
            1,
            "Legacy uuid-keyed credential should be retired by re-enrollment"
        );

        // The freshly scanned authenticator works.
        let new_totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(new_secret_b32).to_bytes().unwrap(),
            None,
            "".to_string(),
        )
        .unwrap();
        totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: new_totp.generate_current().unwrap(),
            })
            .await
            .unwrap();

        // The superseded one does not.
        let legacy_totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(legacy_secret).to_bytes().unwrap(),
            None,
            "".to_string(),
        )
        .unwrap();
        let replayed = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: legacy_totp.generate_current().unwrap(),
            })
            .await;
        assert!(matches!(replayed, Err(AuthError::Credentials(_))));
    }

    #[tokio::test]
    async fn test_credential_store_delete_methods() {
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };

        // Test delete_credential when credential exists
        store
            .save_credential(
                "user1",
                "totp",
                serde_json::json!({"credential_id": "totp_cred1", "secret": "SECRET1"}),
            )
            .await
            .unwrap();

        let result = store
            .delete_credential("user1", "totp", "totp_cred1")
            .await
            .unwrap();
        assert!(
            result,
            "delete_credential should return true when credential exists"
        );

        let creds = store.get_credentials("user1", "totp").await.unwrap();
        assert_eq!(creds.len(), 0, "Credential should be deleted");

        // Test delete_credential when credential does not exist
        let result = store
            .delete_credential("user1", "totp", "totp_cred1")
            .await
            .unwrap();
        assert!(
            !result,
            "delete_credential should return false when credential does not exist"
        );

        // Test delete_credentials when credentials exist
        store
            .save_credential(
                "user2",
                "webauthn",
                serde_json::json!({"credential_id": "webauthn_cred1"}),
            )
            .await
            .unwrap();
        store
            .save_credential(
                "user2",
                "webauthn",
                serde_json::json!({"credential_id": "webauthn_cred2"}),
            )
            .await
            .unwrap();

        let count = store.delete_credentials("user2", "webauthn").await.unwrap();
        assert_eq!(
            count, 2,
            "delete_credentials should return count of deleted credentials"
        );

        let creds = store.get_credentials("user2", "webauthn").await.unwrap();
        assert_eq!(creds.len(), 0, "All credentials should be deleted");

        // Test delete_credentials when no credentials exist
        let count = store.delete_credentials("user2", "webauthn").await.unwrap();
        assert_eq!(
            count, 0,
            "delete_credentials should return 0 when no credentials exist"
        );
    }

    /// Test that stores not implementing delete_credentials return Unsupported error.
    struct NoDeleteStore;

    #[async_trait]
    impl CredentialStore for NoDeleteStore {
        async fn save_credential(
            &self,
            _user_id: &str,
            _cred_type: &str,
            _data: serde_json::Value,
        ) -> Result<(), AuthError> {
            Ok(())
        }

        async fn get_credentials(
            &self,
            _user_id: &str,
            _cred_type: &str,
        ) -> Result<Vec<serde_json::Value>, AuthError> {
            Ok(vec![])
        }

        async fn update_credential(
            &self,
            _credential_id: &str,
            _data: serde_json::Value,
        ) -> Result<(), AuthError> {
            Ok(())
        }
        // delete_credential and delete_credentials use the default implementation
    }

    #[tokio::test]
    async fn test_delete_unsupported_returns_error() {
        let store = NoDeleteStore;

        // Verify that the default implementation returns Unsupported
        let result = store.delete_credential("user1", "totp", "cred_id").await;
        assert!(matches!(result, Err(AuthError::Unsupported)));

        let result = store.delete_credentials("user1", "totp").await;
        assert!(matches!(result, Err(AuthError::Unsupported)));
    }

    /// Verifies that identifierless TOTP credentials are rejected during authentication
    /// and ignored by `has_enrolled`.
    #[tokio::test]
    async fn test_totp_rejects_identifierless_credentials() {
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };
        // Insert a TOTP credential with no credential_id and a legacy raw-string secret
        store.creds.lock().unwrap().insert(
            "user_no_id:totp".to_string(),
            vec![
                serde_json::json!({
                    "secret": "JBSWY3DPEHPK3PXP",
                    "algorithm": "SHA1",
                    "digits": 6,
                    "step": 30,
                }),
                serde_json::Value::String("JBSWY3DPEHPK3PXP".to_string()),
            ],
        );

        let totp_method = TotpAuthMethod::new(store);
        assert!(
            !totp_method.has_enrolled("user_no_id").await.unwrap(),
            "has_enrolled must not report identifierless or raw-string credentials as enrolled"
        );
        let err = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user_no_id".to_string(),
                code: "123456".to_string(),
            })
            .await
            .unwrap_err();
        match err {
            AuthError::Credentials(msg) => {
                assert!(msg.contains("missing required identifier"));
            }
            other => panic!("expected AuthError::Credentials, got {:?}", other),
        }
    }

    /// Verifies that legacy TOTP credentials keyed under `"id"` or stored as raw strings
    /// are properly retired on re-enrollment.
    #[tokio::test]
    async fn test_totp_reenrollment_retires_id_fallback_and_raw_string() {
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };
        store.creds.lock().unwrap().insert(
            "user_legacy:totp".to_string(),
            vec![
                serde_json::json!({
                    "id": "legacy_id_1",
                    "secret": "JBSWY3DPEHPK3PXP",
                }),
                serde_json::Value::String("JBSWY3DPEHPK3PXP".to_string()),
            ],
        );

        let totp_method = TotpAuthMethod::new(store);
        assert!(
            totp_method.has_enrolled("user_legacy").await.unwrap(),
            "credential with 'id' fallback should count as enrolled"
        );

        let (_new_secret, _) = totp_method
            .register_totp(
                &fresh_identity("user_legacy"),
                &permissive_gate(),
                "Engine",
                "user_legacy",
            )
            .await
            .unwrap();

        let creds = totp_method
            .store
            .get_credentials("user_legacy", "totp")
            .await
            .unwrap();
        assert_eq!(
            creds.len(),
            1,
            "Only the newly enrolled credential should remain"
        );
        assert_eq!(
            creds[0].get("credential_id").and_then(|v| v.as_str()),
            Some("totp:user_legacy")
        );
    }

    struct FailingRetirementStore {
        creds: Mutex<HashMap<String, Vec<serde_json::Value>>>,
    }

    #[async_trait]
    impl CredentialStore for FailingRetirementStore {
        async fn save_credential(
            &self,
            user_id: &str,
            cred_type: &str,
            data: serde_json::Value,
        ) -> Result<(), AuthError> {
            let key = format!("{user_id}:{cred_type}");
            self.creds
                .lock()
                .unwrap()
                .entry(key)
                .or_default()
                .push(data);
            Ok(())
        }
        async fn get_credentials(
            &self,
            user_id: &str,
            cred_type: &str,
        ) -> Result<Vec<serde_json::Value>, AuthError> {
            let key = format!("{user_id}:{cred_type}");
            Ok(self
                .creds
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_default())
        }
        async fn update_credential(
            &self,
            _credential_id: &str,
            _data: serde_json::Value,
        ) -> Result<(), AuthError> {
            Ok(())
        }
        async fn delete_credential(
            &self,
            _user_id: &str,
            _cred_type: &str,
            _credential_id: &str,
        ) -> Result<bool, AuthError> {
            Err(AuthError::Internal("simulated store delete failure".into()))
        }
        async fn delete_credentials(
            &self,
            _user_id: &str,
            _cred_type: &str,
        ) -> Result<u64, AuthError> {
            Err(AuthError::Internal("simulated store delete failure".into()))
        }
        async fn claim_totp_step(
            &self,
            _user_id: &str,
            _credential_id: &str,
            _matched_step: u64,
        ) -> Result<bool, AuthError> {
            Ok(true)
        }
    }

    /// Verifies that `register_totp` propagates an error if retiring existing credentials fails,
    /// and that the existing credentials remain preserved without being replaced by an unreturned secret.
    #[tokio::test]
    async fn test_register_totp_fails_if_retirement_fails() {
        let store = FailingRetirementStore {
            creds: Mutex::new(HashMap::new()),
        };
        // Seed an existing deterministic credential and a stale credential
        store.creds.lock().unwrap().insert(
            "user1:totp".to_string(),
            vec![
                serde_json::json!({
                    "credential_id": "totp:user1",
                    "secret": "JBSWY3DPEHPK3PXP",
                    "algorithm": "SHA1",
                    "digits": 6,
                    "step": 30,
                }),
                serde_json::json!({
                    "credential_id": "old_cred",
                    "secret": "OLDSECRET3DPEHPK",
                    "algorithm": "SHA1",
                    "digits": 6,
                    "step": 30,
                }),
            ],
        );

        let totp_method = TotpAuthMethod::new(store);
        let err = totp_method
            .register_totp(
                &fresh_identity("user1"),
                &permissive_gate(),
                "Engine",
                "user1",
            )
            .await
            .unwrap_err();

        match err {
            AuthError::Internal(msg) => {
                assert!(msg.contains("simulated store delete failure"));
            }
            other => panic!("expected AuthError::Internal, got {:?}", other),
        }

        // Verify the existing secret was not overwritten/replaced by an unreturned secret
        let creds = totp_method
            .store
            .get_credentials("user1", "totp")
            .await
            .unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0]["secret"], "JBSWY3DPEHPK3PXP");
    }

    /// Verifies that extract_totp_credential_id falls back to "id" if "credential_id" is null or empty.
    #[test]
    fn test_extract_totp_credential_id_fallback_when_credential_id_is_empty_or_null() {
        let cred_null = serde_json::json!({
            "credential_id": null,
            "id": "valid-id-1",
            "secret": "JBSWY3DPEHPK3PXP"
        });
        assert_eq!(extract_totp_credential_id(&cred_null), Some("valid-id-1"));

        let cred_empty = serde_json::json!({
            "credential_id": "",
            "id": "valid-id-2",
            "secret": "JBSWY3DPEHPK3PXP"
        });
        assert_eq!(extract_totp_credential_id(&cred_empty), Some("valid-id-2"));

        let cred_primary = serde_json::json!({
            "credential_id": "primary-id",
            "id": "fallback-id",
            "secret": "JBSWY3DPEHPK3PXP"
        });
        assert_eq!(
            extract_totp_credential_id(&cred_primary),
            Some("primary-id")
        );
    }
}
