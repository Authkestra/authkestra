use authkestra_engine::error::AuthError;
use authkestra_engine::strategy::AuthenticationStrategy;
use http::request::Parts;

pub mod jwt;

/// DPoP (RFC 9449) proof replay tracking for [`jwt::JwtStrategy`]. See the
/// module doc for why this is independent of `authkestra-op`'s own replay
/// guard.
pub mod dpop;
pub use authkestra_engine::token::refusal::{
    self, AuthScheme, ResourceRefusal, StepUpRequirement, INSUFFICIENT_USER_AUTHENTICATION,
};
pub use dpop::{DpopJtiRecord, DpopReplayStore, NoDpopReplayStore, DPOP_PROOF_MAX_AGE_SECS};

#[cfg(feature = "policy")]
pub mod policy;
#[cfg(feature = "policy")]
pub use policy::{
    encode_principal_component, format_principal_uid_str, DefaultPrincipalMapper, PolicyGuard,
    PrincipalMapper,
};

/// Policy for controlling the behavior of chained authentication strategies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthPolicy {
    /// Try strategies in order, return the first success.
    /// If a strategy returns an error, the whole chain fails.
    /// If all strategies return `None`, the chain returns `None`.
    #[default]
    FirstSuccess,
    /// All strategies must succeed. If any fails or returns `None`, the whole chain fails.
    /// Returns the identity from the last strategy.
    AllSuccess,
    /// If the first strategy fails or returns `None`, stop immediately.
    FailFast,
}

/// A service that orchestrates multiple authentication strategies.
#[non_exhaustive]
pub struct Guard<I> {
    strategies: Vec<Box<dyn AuthenticationStrategy<I>>>,
    policy: AuthPolicy,
}

impl<I> Guard<I> {
    /// Create a new builder for the Guard.
    pub fn builder() -> GuardBuilder<I> {
        GuardBuilder::default()
    }

    /// Attempt to authenticate the request using the configured strategies and policy.
    pub async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        match self.policy {
            AuthPolicy::FirstSuccess => {
                for strategy in &self.strategies {
                    match strategy.authenticate(parts).await {
                        Ok(Some(identity)) => return Ok(Some(identity)),
                        Ok(None) => continue,
                        Err(e) => return Err(e),
                    }
                }
                Ok(None)
            }
            AuthPolicy::AllSuccess => {
                let mut last_identity = None;
                for strategy in &self.strategies {
                    match strategy.authenticate(parts).await {
                        Ok(Some(identity)) => last_identity = Some(identity),
                        Ok(None) => return Ok(None),
                        Err(e) => return Err(e),
                    }
                }
                Ok(last_identity)
            }
            AuthPolicy::FailFast => {
                if let Some(strategy) = self.strategies.first() {
                    strategy.authenticate(parts).await
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Attempt to authenticate the request, preserving a structured
    /// [`ResourceRefusal`] (`WWW-Authenticate`, `DPoP-Nonce`, RFC 9470 step-up
    /// parameters) when a strategy rejects presented credentials.
    pub async fn authenticate_with_refusal(
        &self,
        parts: &Parts,
    ) -> Result<Option<I>, ResourceRefusal> {
        tracing::debug!(
            policy = ?self.policy,
            strategy_count = self.strategies.len(),
            "dispatching Guard::authenticate_with_refusal"
        );
        match self.policy {
            AuthPolicy::FirstSuccess => {
                let mut last_refusal: Option<ResourceRefusal> = None;
                for (idx, strategy) in self.strategies.iter().enumerate() {
                    match strategy.authenticate_with_refusal(parts).await {
                        Ok(Some(identity)) => {
                            if let Some(prev) = &last_refusal {
                                tracing::debug!(
                                    strategy_index = idx,
                                    discarded_error = %prev.error,
                                    "strategy succeeded under FirstSuccess; discarding earlier refusal"
                                );
                            } else {
                                tracing::debug!(
                                    strategy_index = idx,
                                    "strategy succeeded under FirstSuccess"
                                );
                            }
                            return Ok(Some(identity));
                        }
                        Ok(None) => {
                            tracing::debug!(
                                strategy_index = idx,
                                "strategy abstained under FirstSuccess; trying next strategy"
                            );
                            continue;
                        }
                        Err(refusal) if refusal.status >= 500 => {
                            tracing::warn!(
                                strategy_index = idx,
                                status = refusal.status,
                                error = %refusal.error,
                                "strategy returned server error under FirstSuccess; aborting chain"
                            );
                            return Err(refusal);
                        }
                        Err(refusal) => {
                            tracing::debug!(
                                strategy_index = idx,
                                status = refusal.status,
                                error = %refusal.error,
                                "strategy refused credentials under FirstSuccess; trying remaining strategies"
                            );
                            last_refusal = Some(refusal);
                        }
                    }
                }
                match last_refusal {
                    Some(refusal) => {
                        tracing::debug!(
                            status = refusal.status,
                            error = %refusal.error,
                            "no strategy succeeded under FirstSuccess; returning last refusal"
                        );
                        Err(refusal)
                    }
                    None => {
                        tracing::debug!("all strategies abstained under FirstSuccess");
                        Ok(None)
                    }
                }
            }
            AuthPolicy::AllSuccess => {
                let mut last_identity = None;
                for (idx, strategy) in self.strategies.iter().enumerate() {
                    match strategy.authenticate_with_refusal(parts).await {
                        Ok(Some(identity)) => {
                            tracing::debug!(
                                strategy_index = idx,
                                "strategy succeeded under AllSuccess"
                            );
                            last_identity = Some(identity);
                        }
                        Ok(None) => {
                            tracing::debug!(
                                strategy_index = idx,
                                "strategy abstained under AllSuccess; chain failed"
                            );
                            return Ok(None);
                        }
                        Err(refusal) => {
                            tracing::debug!(
                                strategy_index = idx,
                                status = refusal.status,
                                error = %refusal.error,
                                "strategy refused credentials under AllSuccess; aborting chain"
                            );
                            return Err(refusal);
                        }
                    }
                }
                Ok(last_identity)
            }
            AuthPolicy::FailFast => {
                if let Some(strategy) = self.strategies.first() {
                    let result = strategy.authenticate_with_refusal(parts).await;
                    match &result {
                        Ok(Some(_)) => {
                            tracing::debug!("first strategy succeeded under FailFast");
                        }
                        Ok(None) => {
                            tracing::debug!("first strategy abstained under FailFast");
                        }
                        Err(refusal) => {
                            tracing::debug!(
                                status = refusal.status,
                                error = %refusal.error,
                                "first strategy refused credentials under FailFast"
                            );
                        }
                    }
                    result
                } else {
                    tracing::debug!("no strategies configured for FailFast Guard");
                    Ok(None)
                }
            }
        }
    }
}

/// Builder for the `Guard`.
#[non_exhaustive]
pub struct GuardBuilder<I> {
    strategies: Vec<Box<dyn AuthenticationStrategy<I>>>,
    policy: AuthPolicy,
}

impl<I> Default for GuardBuilder<I> {
    fn default() -> Self {
        Self {
            strategies: Vec::new(),
            policy: AuthPolicy::default(),
        }
    }
}

impl<I> GuardBuilder<I>
where
    I: Send + Sync + 'static,
{
    /// Add an authentication strategy to the chain.
    pub fn strategy<S>(mut self, strategy: S) -> Self
    where
        S: AuthenticationStrategy<I> + 'static,
    {
        self.strategies.push(Box::new(strategy));
        self
    }

    /// Set the authentication policy.
    pub fn policy(mut self, policy: AuthPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Build the `Guard`.
    pub fn build(self) -> Guard<I> {
        Guard {
            strategies: self.strategies,
            policy: self.policy,
        }
    }
}
