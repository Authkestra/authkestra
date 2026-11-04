//! Email and SMS one-time codes.
//!
//! See `docs/rfc-011-otp.md` for the design record. It is the sibling of
//! [`magic_link`](crate::auth::magic_link), and the interesting part is where
//! it cannot follow it.
//!
//! Magic link stores its record under the hash of the secret, which is what
//! buys single use for free. A six-digit code cannot: a wrong code hashes to
//! a key that does not exist, so the server would have no idea whose code was
//! being guessed, could not count the attempt, and could not tell a typo from
//! an attack — while any guess colliding with *anybody's* live code would
//! succeed. So the challenge is keyed by **subject**, with the code's hash as
//! a value, and everything else here follows from that.
//!
//! Delivery stays the application's, exactly as for magic link: no transport,
//! no templates, no address book, and no way for this module to leak whether
//! an account exists, because it is never told. The one exception is the
//! channel, which the engine must know because RFC 8176 gives SMS its own
//! `amr` value and the engine cannot map what it was not told.

use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::auth::state::{
    IDENTITY_ATTR_OTP_CHANNEL, METHOD_NAME_OTP, OTP_CHANNEL_EMAIL, OTP_CHANNEL_SMS,
};
use crate::auth::{AuthError, AuthInput, AuthMethod, Identity};
use crate::store::{AtomicConsume, AtomicDecrement, AtomicInsert, KvStore};

/// How many digits a code has.
///
/// Digits rather than alphanumerics because the code is typed on a phone
/// keypad and sometimes read aloud, where `0`/`O` and `1`/`l` cost more in
/// support than they earn in entropy.
///
/// Six of them is 10^6, which is not much, and nothing here pretends
/// otherwise: the attempt budget is what makes the method safe, not the
/// length. A deployment wanting more margin should shorten the TTL rather
/// than lengthen the code past what people will actually type.
const CODE_DIGITS: u32 = 6;

/// Which way the code was delivered.
///
/// The engine's only interest in delivery, and only because the wire format
/// forces it: RFC 8176 registers `sms`, so an SMS code and an emailed one
/// produce different `amr` claims. This module still sends nothing and never
/// sees an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OtpChannel {
    /// Delivered to a mailbox.
    Email,
    /// Delivered to a phone number.
    Sms,
}

/// A freshly minted code. Returned once and never recoverable.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct OtpCode {
    /// The digits to deliver.
    pub code: String,
    /// Unix seconds after which the code stops being accepted.
    pub expires_at: i64,
}

/// What the store holds against a subject.
///
fn default_challenge_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// What the store holds against a subject.
///
/// Immutable for its whole life: the attempt budget lives in a counter beside
/// it rather than in here, because a field inside a serialised record cannot
/// be decremented atomically. See [`AtomicDecrement`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct OtpChallenge {
    /// Unique generation ID for this challenge (UUID v4).
    #[serde(default = "default_challenge_id")]
    pub challenge_id: String,
    /// SHA-256 of the code, never the code.
    pub code_hash: String,
    /// The channel it went out on, so `amr` can name it later.
    pub channel: OtpChannel,
    /// Unix seconds at which the challenge expires.
    #[serde(default)]
    pub expires_at: i64,
}

/// Derives the store key for an attempt counter bound to a specific challenge generation.
fn counter_key(key: &str, challenge_id: &str) -> String {
    format!("{key}:gen:{challenge_id}")
}

/// Derives the key that holds a subject's resend cooldown.
///
/// Distinct from [`challenge_key`], so a cooldown can outlive the challenge
/// it followed — which it must, since the point is to refuse the *next* mint.
fn cooldown_key(subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(subject.as_bytes());
    format!("otp:cooldown:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Derives the store key for a subject's live challenge.
fn challenge_key(subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(subject.as_bytes());
    format!("otp:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Hashes a code for storage and comparison.
///
/// Worth being precise about what this buys, because it is less than the
/// equivalent in `magic_link`. A six-digit code has only 10^6 preimages, so
/// anyone holding the store brute-forces this in microseconds — it is not
/// protecting against a store compromise the way a 256-bit token's hash does.
///
/// It is still right to do: it keeps live codes out of logs, backups and
/// replicas that get read by humans and grepped by accident. Anyone relying
/// on it for more than that has misread the threat model.
fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Generates a uniformly distributed code.
///
/// Rejection sampling via `random_range` rather than `% 1_000_000` over a
/// uniform draw: modulo biases the low codes measurably, and a biased OTP is
/// a smaller keyspace wearing the right number of digits.
fn generate_code() -> String {
    let bound = 10u32.pow(CODE_DIGITS);
    let n = rand::rng().random_range(0..bound);
    format!("{n:0width$}", width = CODE_DIGITS as usize)
}

/// One-time codes delivered out of band.
pub struct OtpAuthMethod<S> {
    store: S,
    resend_cooldown: Option<Duration>,
}

/// What the cooldown key holds.
///
/// Nothing reads it — only whether the insert succeeded matters. It is
/// challenge-shaped because the store is typed to `OtpChallenge`, and its
/// hash is deliberately empty: [`hash_code`] always produces a non-empty
/// digest, so this can never match a presented code even if some future bug
/// routed a lookup at this key.
fn cooldown_marker() -> OtpChallenge {
    OtpChallenge {
        challenge_id: String::new(),
        code_hash: String::new(),
        channel: OtpChannel::Email,
        expires_at: 0,
    }
}

impl<S> OtpAuthMethod<S>
where
    S: KvStore<OtpChallenge>
        + AtomicConsume<OtpChallenge>
        + AtomicDecrement<OtpChallenge>
        + AtomicInsert<OtpChallenge>,
{
    /// Wrap a store.
    pub fn new(store: S) -> Self {
        Self {
            store,
            resend_cooldown: None,
        }
    }

    /// Refuse to mint again for the same subject within `interval`.
    ///
    /// Off by default, because the right interval depends on how the codes
    /// travel and no framework-chosen number would be reviewed as often as it
    /// was obeyed.
    ///
    /// Worth turning on, and more so for SMS than for email. Minting is free
    /// to the caller and costs the *operator* a message each time, so an
    /// unthrottled endpoint is a way to spend someone else's money at a rate
    /// an attacker chooses — and to bury a victim's phone under messages they
    /// did not ask for. That is a worse failure than the mail-bombing an
    /// emailed link risks.
    ///
    /// This does not replace rate limiting at the HTTP edge, and is not
    /// trying to. Edge limits are per-IP and an attacker rotating addresses
    /// walks through them; this is per-subject, which is the dimension the
    /// abuse actually has. The same argument the attempt budget rests on.
    ///
    /// Enforced with [`AtomicInsert::insert_if_absent`], so two simultaneous
    /// requests cannot both find the coast clear — and the TTL does the
    /// expiry, so nothing has to sweep it.
    ///
    /// That primitive rounds its TTL up to whole seconds and floors it at
    /// one, deliberately (see `ttl_ceil_secs`), so sub-second intervals are
    /// not honoured as written and the effective minimum is one second. That
    /// is not a limitation worth working around: a sub-second resend brake
    /// would stop nothing a human does and nothing an attacker minds.
    pub fn with_resend_cooldown(mut self, interval: Duration) -> Self {
        self.resend_cooldown = Some(interval);
        self
    }

    /// Mint a code for an already-resolved subject, replacing any live
    /// challenge for that subject.
    ///
    /// Replacement rather than accumulation: several concurrent codes
    /// multiply the guessing surface for no benefit and make "how many
    /// attempts remain" ambiguous. It also gives resend the obvious meaning —
    /// the new code works, the old one stops.
    ///
    /// `ttl` and `max_attempts` are both required. Any default would be wrong
    /// for somebody and the failure is silent: a too-long window or too
    /// generous a budget produces no error, just a wider target.
    #[tracing::instrument(skip(self), fields(ttl_secs = ttl.as_secs()))]
    pub async fn mint(
        &self,
        subject: &str,
        ttl: Duration,
        channel: OtpChannel,
        max_attempts: u32,
    ) -> Result<OtpCode, AuthError> {
        if max_attempts == 0 {
            // A zero budget is a challenge that can never be satisfied. Far
            // more likely a caller bug than an intent, and silently minting
            // an unusable code would be debugged as "OTP is broken".
            return Err(AuthError::InvalidInput);
        }

        if ttl.as_secs() == 0 {
            tracing::warn!(
                subject = %subject,
                ttl = ?ttl,
                "otp mint refused: TTL must be at least one second"
            );
            return Err(AuthError::InvalidInput);
        }

        // Before anything is generated or written: a refused mint should cost
        // nothing and leave no trace.
        if let Some(cooldown) = self.resend_cooldown {
            let claimed = self
                .store
                .insert_if_absent(&cooldown_key(subject), cooldown_marker(), cooldown)
                .await
                .map_err(|e| AuthError::Internal(format!("otp cooldown check failed: {e}")))?;

            if !claimed {
                tracing::warn!(subject = %subject, "otp mint refused: still within the resend cooldown");
                return Err(AuthError::Throttled);
            }
        }

        let code = generate_code();
        let key = challenge_key(subject);
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;

        let challenge = OtpChallenge {
            challenge_id,
            code_hash: hash_code(&code),
            channel,
            expires_at,
        };

        // Anything that fails from here on has to hand the cooldown back. It
        // was claimed before the write — it must be, or two simultaneous
        // requests would both get past the check — but a claim that outlives
        // a mint which never delivered anything is a lockout for the whole
        // interval caused by one transient store error. The user would be
        // refused a code they never received.
        if let Err(e) = self
            .write_challenge(&key, challenge, ttl, max_attempts)
            .await
        {
            self.release_cooldown(subject).await;
            return Err(e);
        }

        tracing::debug!(
            subject = %subject,
            ?channel,
            max_attempts,
            expires_at,
            "minted a one-time code"
        );

        Ok(OtpCode { code, expires_at })
    }

    /// Writes the challenge and its budget.
    ///
    /// Split out so [`Self::mint`] has a single fallible step to unwind the
    /// cooldown around, rather than two places to remember.
    async fn write_challenge(
        &self,
        key: &str,
        challenge: OtpChallenge,
        ttl: Duration,
        max_attempts: u32,
    ) -> Result<(), AuthError> {
        let counter_k = counter_key(key, &challenge.challenge_id);
        self.store
            .set(key, challenge, ttl)
            .await
            .map_err(|e| AuthError::Internal(format!("otp store write failed: {e}")))?;

        // After the challenge, so a crash between the two leaves a challenge
        // with no budget — which fails closed, since a missing counter reads
        // as no attempts left.
        self.store
            .init_counter(&counter_k, max_attempts, ttl)
            .await
            .map_err(|e| AuthError::Internal(format!("otp counter init failed: {e}")))?;

        Ok(())
    }

    /// Hands back a cooldown claimed for a mint that then failed.
    ///
    /// Best effort, and loud when it fails: at that point the subject really
    /// is locked out for the interval with nothing to show for it, which is a
    /// double fault worth finding in the logs rather than in a support queue.
    async fn release_cooldown(&self, subject: &str) {
        if self.resend_cooldown.is_none() {
            return;
        }
        if let Err(e) = self.store.delete(&cooldown_key(subject)).await {
            tracing::error!(
                error = %e,
                subject = %subject,
                "could not release the resend cooldown after a failed mint; \
                 this subject cannot request a code until it expires"
            );
        }
    }

    /// Drops a challenge whose budget is gone.
    ///
    /// Best effort. A failure leaves a challenge its own TTL will collect,
    /// and whose counter is spent — and since acceptance requires winning
    /// `consume` rather than merely finding the record, a challenge left
    /// behind here is not a usable one.
    ///
    /// The counter is left to expire. It cannot be inherited by a later
    /// challenge for the same subject, because `mint` replaces it.
    async fn discard(&self, key: &str, challenge_id: &str) {
        if let Err(e) = self.store.delete(key).await {
            tracing::warn!(error = %e, "failed to discard a spent otp challenge");
        }
        if !challenge_id.is_empty() {
            let counter_k = counter_key(key, challenge_id);
            if let Err(e) = self.store.delete(&counter_k).await {
                tracing::debug!(error = %e, "failed to clean up otp counter key");
            }
        }
    }
}

#[async_trait]
impl<S> AuthMethod for OtpAuthMethod<S>
where
    S: KvStore<OtpChallenge>
        + AtomicConsume<OtpChallenge>
        + AtomicDecrement<OtpChallenge>
        + AtomicInsert<OtpChallenge>
        + Send
        + Sync
        + 'static,
{
    fn name(&self) -> &str {
        METHOD_NAME_OTP
    }

    /// Verify a code against the subject's live challenge.
    ///
    /// The budget is spent *before* the code is checked. That ordering is
    /// deliberate: a crash or a dropped connection after the check but before
    /// the decrement would hand an attacker a free attempt each time, so the
    /// cost is taken first and the successful path simply discards the
    /// challenge afterwards.
    ///
    /// The comparison is constant-time, and this is the one place where
    /// `magic_link`'s reasoning does **not** carry over. There, a mismatch
    /// burns the secret, so an attacker gets exactly one attempt and a timing
    /// oracle has nothing to accumulate. Here several attempts are allowed by
    /// design, which is precisely the condition that makes an early-exit
    /// comparison exploitable — a learned prefix collapses 10^6 quickly.
    ///
    /// Every failure returns [`AuthError::InvalidCredentials`]: no live
    /// challenge, wrong code, exhausted budget and expired all look alike to
    /// the caller. An exhausted challenge is deleted rather than left to
    /// expire, so "you have used up your attempts" is not an oracle telling
    /// an attacker they had the right subject.
    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError> {
        let AuthInput::Otp { subject, code } = input else {
            tracing::debug!("declining: input is not a one-time code");
            return Err(AuthError::InvalidInput);
        };

        let key = challenge_key(&subject);

        let challenge = self
            .store
            .get(&key)
            .await
            .map_err(|e| AuthError::Internal(format!("otp store read failed: {e}")))?;

        let Some(challenge) = challenge else {
            tracing::warn!("otp rejected: no live challenge for the subject");
            return Err(AuthError::InvalidCredentials);
        };

        let counter_k = counter_key(&key, &challenge.challenge_id);
        let remaining = self
            .store
            .decrement(&counter_k)
            .await
            .map_err(|e| AuthError::Internal(format!("otp counter read failed: {e}")))?;

        // Absent means never set or expired. Treating that as "no attempts
        // left" is the fail-closed reading; treating it as unlimited would
        // invert the guard entirely.
        let Some(remaining) = remaining else {
            tracing::warn!("otp rejected: no attempt budget for a live challenge");
            self.discard(&key, &challenge.challenge_id).await;
            return Err(AuthError::InvalidCredentials);
        };

        let presented = hash_code(&code);
        let matches: bool = presented
            .as_bytes()
            .ct_eq(challenge.code_hash.as_bytes())
            .into();

        if !matches {
            tracing::warn!(remaining, "otp rejected: wrong code");
            if remaining == 0 {
                // Deleted rather than left to expire, so an exhausted
                // challenge is indistinguishable from one that never existed.
                tracing::warn!("otp attempt budget exhausted; discarding the challenge");
                self.discard(&key, &challenge.challenge_id).await;
            }
            return Err(AuthError::InvalidCredentials);
        }

        // Correct — but knowing the code is not the same as being the one who
        // gets to use it. `consume` decides that: it fetches and removes in
        // one operation, so among any number of concurrent submissions of the
        // same correct code exactly one sees `Some` and the rest see `None`.
        //
        // Deleting after accepting would not do. Verification here is a read,
        // a decrement and a compare, none of which excludes a second caller
        // doing the same against the same live record — under a multi-threaded
        // runtime that reliably yields several accepted identities from one
        // code. Single use has to be won, not tidied up afterwards.
        let claimed = self
            .store
            .consume(&key)
            .await
            .map_err(|e| AuthError::Internal(format!("otp claim failed: {e}")))?;

        let Some(consumed) = claimed else {
            tracing::warn!("otp rejected: the challenge was claimed concurrently");
            return Err(AuthError::InvalidCredentials);
        };

        if consumed.challenge_id != challenge.challenge_id {
            tracing::warn!(
                expected_id = %challenge.challenge_id,
                actual_id = %consumed.challenge_id,
                "otp rejected: challenge was replaced by concurrent mint; restoring new challenge"
            );
            let remaining_secs =
                (consumed.expires_at - chrono::Utc::now().timestamp()).max(1) as u64;
            if let Err(e) = self
                .store
                .set(&key, consumed, Duration::from_secs(remaining_secs))
                .await
            {
                tracing::error!(error = %e, "failed to restore replaced challenge into store");
            }
            return Err(AuthError::InvalidCredentials);
        }

        tracing::info!(subject = %subject, channel = ?challenge.channel, "otp accepted");

        let mut attributes = std::collections::HashMap::new();
        // The channel has to survive to `amr` derivation, which happens in
        // `authkestra-op` and never sees the challenge.
        attributes.insert(
            IDENTITY_ATTR_OTP_CHANNEL.to_string(),
            match challenge.channel {
                OtpChannel::Email => OTP_CHANNEL_EMAIL.to_string(),
                OtpChannel::Sms => OTP_CHANNEL_SMS.to_string(),
            },
        );

        Ok(Identity {
            provider_id: METHOD_NAME_OTP.to_string(),
            external_id: subject,
            email: None,
            username: None,
            attributes,
        })
    }

    /// Always `false`, as a statement rather than an inherited default: there
    /// is no enrolment ceremony, so nothing exists to report.
    async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
        Ok(false)
    }

    /// Always `false`, matching TOTP. A delivered code is one factor.
    fn is_mfa_equivalent(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::MemoryStore;

    const TTL: Duration = Duration::from_secs(300);

    fn method() -> OtpAuthMethod<MemoryStore<OtpChallenge>> {
        OtpAuthMethod::new(MemoryStore::new())
    }

    fn submit(subject: &str, code: &str) -> AuthInput {
        AuthInput::Otp {
            subject: subject.to_string(),
            code: code.to_string(),
        }
    }

    #[tokio::test]
    async fn a_correct_code_authenticates_its_subject() {
        let m = method();
        let minted = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();

        let identity = m.authenticate(submit("alice", &minted.code)).await.unwrap();

        assert_eq!(identity.external_id, "alice");
        assert_eq!(identity.provider_id, METHOD_NAME_OTP);
        assert_eq!(
            identity.attributes.get(IDENTITY_ATTR_OTP_CHANNEL),
            Some(&OTP_CHANNEL_EMAIL.to_string())
        );
    }

    #[tokio::test]
    async fn the_channel_survives_onto_the_identity() {
        let m = method();
        let minted = m.mint("alice", TTL, OtpChannel::Sms, 3).await.unwrap();
        let identity = m.authenticate(submit("alice", &minted.code)).await.unwrap();
        assert_eq!(
            identity.attributes.get(IDENTITY_ATTR_OTP_CHANNEL),
            Some(&OTP_CHANNEL_SMS.to_string())
        );
    }

    #[tokio::test]
    async fn a_code_works_exactly_once() {
        let m = method();
        let minted = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();

        assert!(m.authenticate(submit("alice", &minted.code)).await.is_ok());
        assert!(matches!(
            m.authenticate(submit("alice", &minted.code)).await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    /// Does a correct code submitted concurrently produce more than one
    /// identity? (Reproduction for the review finding.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_correct_submissions_yield_one_identity() {
        let store = MemoryStore::<OtpChallenge>::new();
        let m = std::sync::Arc::new(OtpAuthMethod::new(store));
        let minted = m.mint("alice", TTL, OtpChannel::Email, 5).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..5 {
            let m = m.clone();
            let code = minted.code.clone();
            handles.push(tokio::spawn(async move {
                m.authenticate(submit("alice", &code)).await.is_ok()
            }));
        }
        let mut accepted = 0;
        for h in handles {
            if h.await.unwrap() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 1, "a code was accepted {accepted} times");
    }

    #[tokio::test]
    async fn a_subject_with_no_challenge_is_refused() {
        let m = method();
        assert!(matches!(
            m.authenticate(submit("nobody", "000000")).await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    /// The property that makes a six-digit secret defensible at all.
    #[tokio::test]
    async fn the_attempt_budget_is_enforced_and_then_the_challenge_is_gone() {
        let m = method();
        let minted = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();
        let wrong = if minted.code == "000000" {
            "111111"
        } else {
            "000000"
        };

        for _ in 0..3 {
            assert!(matches!(
                m.authenticate(submit("alice", wrong)).await,
                Err(AuthError::InvalidCredentials)
            ));
        }

        // Budget spent, so even the right code is refused — and the challenge
        // has been discarded rather than left to expire.
        assert!(matches!(
            m.authenticate(submit("alice", &minted.code)).await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    /// A wrong guess must not spend somebody else's budget, which is the
    /// cross-account failure that keying by the code rather than the subject
    /// would have produced.
    #[tokio::test]
    async fn one_subjects_wrong_guesses_do_not_touch_another() {
        let m = method();
        let alice = m.mint("alice", TTL, OtpChannel::Email, 2).await.unwrap();
        let bob = m.mint("bob", TTL, OtpChannel::Email, 2).await.unwrap();

        for _ in 0..2 {
            let _ = m.authenticate(submit("alice", "000000")).await;
        }

        assert!(matches!(
            m.authenticate(submit("alice", &alice.code)).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(m.authenticate(submit("bob", &bob.code)).await.is_ok());
    }

    /// A code is only valid for the subject it was minted for. Presenting
    /// Alice's code against Bob's challenge must fail even though the digits
    /// are genuine.
    #[tokio::test]
    async fn a_code_is_not_valid_for_a_different_subject() {
        let m = method();
        let alice = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();
        m.mint("bob", TTL, OtpChannel::Email, 3).await.unwrap();

        assert!(matches!(
            m.authenticate(submit("bob", &alice.code)).await,
            Err(AuthError::InvalidCredentials)
        ));
        // Alice's own code still works: Bob's failure spent Bob's budget.
        assert!(m.authenticate(submit("alice", &alice.code)).await.is_ok());
    }

    /// RFC-011 §4.2: minting replaces, so resend has the obvious meaning.
    #[tokio::test]
    async fn minting_again_replaces_the_live_challenge() {
        let m = method();
        let first = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();
        let second = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();

        assert!(matches!(
            m.authenticate(submit("alice", &first.code)).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(m.authenticate(submit("alice", &second.code)).await.is_ok());
    }

    /// A replaced challenge gets a fresh budget rather than inheriting the
    /// spent one — otherwise a resend would arrive already exhausted.
    #[tokio::test]
    async fn minting_again_restores_the_budget() {
        let m = method();
        m.mint("alice", TTL, OtpChannel::Email, 1).await.unwrap();
        let _ = m.authenticate(submit("alice", "000000")).await;

        let second = m.mint("alice", TTL, OtpChannel::Email, 1).await.unwrap();
        assert!(m.authenticate(submit("alice", &second.code)).await.is_ok());
    }

    #[tokio::test]
    async fn without_a_cooldown_minting_again_is_allowed() {
        let m = method();
        assert!(m.mint("alice", TTL, OtpChannel::Email, 3).await.is_ok());
        assert!(
            m.mint("alice", TTL, OtpChannel::Email, 3).await.is_ok(),
            "the cooldown is opt-in; off by default nothing should refuse"
        );
    }

    #[tokio::test]
    async fn a_cooldown_refuses_an_immediate_resend() {
        let m =
            OtpAuthMethod::new(MemoryStore::new()).with_resend_cooldown(Duration::from_secs(60));

        assert!(m.mint("alice", TTL, OtpChannel::Email, 3).await.is_ok());
        assert!(matches!(
            m.mint("alice", TTL, OtpChannel::Email, 3).await,
            Err(AuthError::Throttled)
        ));
    }

    /// The cooldown is per-subject, which is the dimension the abuse has.
    /// Throttling one account must not throttle everybody.
    #[tokio::test]
    async fn a_cooldown_is_scoped_to_one_subject() {
        let m =
            OtpAuthMethod::new(MemoryStore::new()).with_resend_cooldown(Duration::from_secs(60));

        assert!(m.mint("alice", TTL, OtpChannel::Email, 3).await.is_ok());
        assert!(m.mint("alice", TTL, OtpChannel::Email, 3).await.is_err());
        assert!(
            m.mint("bob", TTL, OtpChannel::Email, 3).await.is_ok(),
            "bob has not asked for anything"
        );
    }

    /// One second, not less: `insert_if_absent` floors its TTL there on
    /// purpose, so a shorter cooldown would silently be rounded up and this
    /// test would be asserting something the API does not promise.
    #[tokio::test]
    async fn a_cooldown_lapses() {
        let m = OtpAuthMethod::new(MemoryStore::new()).with_resend_cooldown(Duration::from_secs(1));

        assert!(m.mint("alice", TTL, OtpChannel::Email, 3).await.is_ok());
        assert!(m.mint("alice", TTL, OtpChannel::Email, 3).await.is_err());

        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(
            m.mint("alice", TTL, OtpChannel::Email, 3).await.is_ok(),
            "the cooldown should expire on its own"
        );
    }

    /// A refused mint must leave the previous challenge intact. Otherwise a
    /// resend an attacker triggers would invalidate the code the real user is
    /// in the middle of typing — turning a throttle into a denial of service.
    #[tokio::test]
    async fn a_refused_resend_does_not_disturb_the_live_challenge() {
        let m =
            OtpAuthMethod::new(MemoryStore::new()).with_resend_cooldown(Duration::from_secs(60));

        let first = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();
        assert!(m.mint("alice", TTL, OtpChannel::Email, 3).await.is_err());

        assert!(
            m.authenticate(submit("alice", &first.code)).await.is_ok(),
            "the original code must still work"
        );
    }

    /// Two simultaneous resends must not both get through. `insert_if_absent`
    /// is what makes that true rather than a check-then-mint that races.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_resends_yield_one_mint() {
        let m = std::sync::Arc::new(
            OtpAuthMethod::new(MemoryStore::new()).with_resend_cooldown(Duration::from_secs(60)),
        );

        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = m.clone();
            handles.push(tokio::spawn(async move {
                m.mint("alice", TTL, OtpChannel::Email, 3).await.is_ok()
            }));
        }
        let mut minted = 0;
        for h in handles {
            if h.await.unwrap() {
                minted += 1;
            }
        }
        assert_eq!(minted, 1, "{minted} codes were sent for one request");
    }

    /// A store whose `set` fails once, to exercise the unwind path.
    #[derive(Clone)]
    struct FailingSetStore {
        inner: MemoryStore<OtpChallenge>,
        fail_next_set: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl FailingSetStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::new(),
                fail_next_set: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            }
        }
    }

    #[async_trait]
    impl KvStore<OtpChallenge> for FailingSetStore {
        async fn get(&self, key: &str) -> Result<Option<OtpChallenge>, crate::store::StoreError> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: OtpChallenge,
            ttl: Duration,
        ) -> Result<(), crate::store::StoreError> {
            if self
                .fail_next_set
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(crate::store::StoreError::Internal("boom".into()));
            }
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), crate::store::StoreError> {
            self.inner.delete(key).await
        }
    }

    #[async_trait]
    impl AtomicConsume<OtpChallenge> for FailingSetStore {
        async fn consume(
            &self,
            key: &str,
        ) -> Result<Option<OtpChallenge>, crate::store::StoreError> {
            self.inner.consume(key).await
        }
    }

    #[async_trait]
    impl AtomicDecrement<OtpChallenge> for FailingSetStore {
        async fn init_counter(
            &self,
            key: &str,
            value: u32,
            ttl: Duration,
        ) -> Result<(), crate::store::StoreError> {
            self.inner.init_counter(key, value, ttl).await
        }
        async fn decrement(&self, key: &str) -> Result<Option<u32>, crate::store::StoreError> {
            self.inner.decrement(key).await
        }
    }

    #[async_trait]
    impl AtomicInsert<OtpChallenge> for FailingSetStore {
        async fn insert_if_absent(
            &self,
            key: &str,
            value: OtpChallenge,
            ttl: Duration,
        ) -> Result<bool, crate::store::StoreError> {
            self.inner.insert_if_absent(key, value, ttl).await
        }
    }

    /// A mint that fails after claiming the cooldown must hand it back.
    ///
    /// Otherwise one transient store error locks the subject out for the
    /// whole interval while no code was ever delivered — a user refused a
    /// code they never received, which is worse than the abuse the cooldown
    /// exists to stop.
    #[tokio::test]
    async fn a_failed_mint_does_not_leave_the_subject_throttled() {
        let m = OtpAuthMethod::new(FailingSetStore::new())
            .with_resend_cooldown(Duration::from_secs(60));

        // First mint fails inside the store, after the cooldown was claimed.
        assert!(matches!(
            m.mint("alice", TTL, OtpChannel::Email, 3).await,
            Err(AuthError::Internal(_))
        ));

        // The retry must not be refused.
        let minted = m
            .mint("alice", TTL, OtpChannel::Email, 3)
            .await
            .expect("a retry after a failed mint must not be throttled");
        assert!(m.authenticate(submit("alice", &minted.code)).await.is_ok());
    }

    #[tokio::test]
    async fn a_zero_budget_is_refused_rather_than_minted_unusable() {
        let m = method();
        assert!(matches!(
            m.mint("alice", TTL, OtpChannel::Email, 0).await,
            Err(AuthError::InvalidInput)
        ));
    }

    #[tokio::test]
    async fn the_store_never_holds_the_code() {
        let store = MemoryStore::<OtpChallenge>::new();
        let m = OtpAuthMethod::new(store.clone());
        let minted = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();

        let challenge = store
            .get(&challenge_key("alice"))
            .await
            .unwrap()
            .expect("the subject key should address the challenge");
        let serialized = serde_json::to_string(&challenge).unwrap();
        assert!(
            !serialized.contains(&minted.code),
            "the stored challenge must not carry the code"
        );
        assert_eq!(challenge.code_hash, hash_code(&minted.code));
    }

    #[tokio::test]
    async fn another_methods_input_is_declined_rather_than_misread() {
        let m = method();
        assert!(matches!(
            m.authenticate(AuthInput::Token("bearer".into())).await,
            Err(AuthError::InvalidInput)
        ));
    }

    #[tokio::test]
    async fn otp_is_not_a_second_factor_and_enrols_nothing() {
        let m = method();
        assert!(!m.is_mfa_equivalent());
        assert!(!m.has_enrolled("alice").await.unwrap());
        assert_eq!(m.name(), "otp");
    }

    #[test]
    fn a_code_is_always_the_advertised_number_of_digits() {
        // Guards the formatting as much as the range: a value below 100000
        // must still render six characters, or a leading zero would silently
        // shrink the keyspace a caller sees.
        for _ in 0..2_000 {
            let code = generate_code();
            assert_eq!(code.len(), CODE_DIGITS as usize, "{code}");
            assert!(code.chars().all(|c| c.is_ascii_digit()), "{code}");
        }
    }

    /// Not a distribution test — 2000 draws cannot prove uniformity. It
    /// catches the coarse failure of a generator stuck in one decade, which
    /// is what a botched range or a reused seed looks like.
    #[test]
    fn generated_codes_span_the_keyspace() {
        let mut first_digits = std::collections::HashSet::new();
        for _ in 0..2_000 {
            first_digits.insert(generate_code().chars().next().unwrap());
        }
        assert!(
            first_digits.len() >= 8,
            "only saw leading digits {first_digits:?}"
        );
    }

    #[tokio::test]
    async fn zero_and_sub_second_ttl_are_rejected() {
        let m = method();
        assert!(matches!(
            m.mint("alice", Duration::ZERO, OtpChannel::Email, 3).await,
            Err(AuthError::InvalidInput)
        ));
        assert!(matches!(
            m.mint("alice", Duration::from_millis(999), OtpChannel::Email, 3)
                .await,
            Err(AuthError::InvalidInput)
        ));
        assert!(m
            .mint("alice", Duration::from_secs(1), OtpChannel::Email, 3)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn new_mint_supersedes_old_and_old_submission_does_not_consume_new() {
        let m = method();
        let first = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();
        let second = m.mint("alice", TTL, OtpChannel::Email, 3).await.unwrap();

        // Submitting old code must fail
        assert!(matches!(
            m.authenticate(submit("alice", &first.code)).await,
            Err(AuthError::InvalidCredentials)
        ));

        // And the second code must STILL work!
        assert!(m.authenticate(submit("alice", &second.code)).await.is_ok());
    }
}
