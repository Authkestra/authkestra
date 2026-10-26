use authkestra_engine::error::AuthError;
use authkestra_engine::strategy::AuthenticationStrategy;
use http::request::Parts;

pub mod jwt;

/// DPoP (RFC 9449) proof replay tracking for [`jwt::JwtStrategy`]. See the
/// module doc for why this is independent of `authkestra-op`'s own replay
/// guard.
pub mod dpop;
pub use dpop::{DpopJtiRecord, DpopReplayStore, NoDpopReplayStore, DPOP_PROOF_MAX_AGE_SECS};

#[cfg(feature = "policy")]
pub mod policy;
#[cfg(feature = "policy")]
pub use policy::{DefaultPrincipalMapper, PolicyGuard, PrincipalMapper};

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
