use crate::client::ClientStore;
use crate::code::AuthorizationCodeStore;
use crate::device::DeviceCodeStore;
use crate::dpop::{DpopReplayStore, NoDpopReplayStore};
use crate::refresh::RefreshTokenStore;
use authkestra_engine::store::traits::{ClientAssertionStore, NoClientAssertionStore};
use authkestra_engine::token::dpop_nonce::DpopNonces;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// A unified store for all OpenID Provider state.
/// This supertrait aggregates `ClientStore`, `AuthorizationCodeStore`,
/// `RefreshTokenStore`, and `DeviceCodeStore`.
#[async_trait::async_trait]
pub trait OpStore:
    ClientStore + AuthorizationCodeStore + RefreshTokenStore + DeviceCodeStore + Send + Sync
{
    /// Atomically spends the `jti` of a `private_key_jwt` client assertion,
    /// returning `Ok(false)` if it was already spent (RFC 7523 §3 point 7).
    ///
    /// A defaulted method rather than a fifth supertrait, so that adding
    /// replay tracking does not break every existing `OpStore`
    /// implementation — the same reasoning that makes `handle_custom_grant`
    /// a defaulted method here.
    ///
    /// **The default refuses every assertion.** A store that has not
    /// implemented `jti` tracking cannot offer the single-use guarantee, and
    /// a `private_key_jwt` deployment without it would be strictly worse than
    /// one without the method at all: the client would believe it had
    /// proof-of-possession authentication while a captured assertion stayed
    /// replayable for its whole lifetime. Failing closed makes that
    /// impossible to reach by accident. See
    /// `CompositeOpStore::with_client_assertion_store` for how to wire one.
    async fn record_client_assertion_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        NoClientAssertionStore::default()
            .record_jti(jti, expires_at)
            .await
    }

    /// Atomically records the `jti` of a presented DPoP proof, returning
    /// `Ok(false)` if it was already spent (RFC 9449 §11.1).
    ///
    /// A defaulted method, same reasoning as `record_client_assertion_jti`:
    /// adding replay tracking must not break every existing `OpStore`
    /// implementation.
    ///
    /// **The default refuses every proof.** See
    /// `record_client_assertion_jti`'s doc comment for why failing closed
    /// is the only safe default here too. See
    /// `CompositeOpStore::with_dpop_replay_store` for how to wire one.
    async fn check_and_record_dpop_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        NoDpopReplayStore::default()
            .check_and_record_dpop_jti(jti, expires_at)
            .await
    }

    /// The DPoP nonce source the token endpoint requires proofs to carry a nonce from
    /// (RFC 9449 §8), or `None` — the default — for no nonce requirement.
    ///
    /// Defaulted for the same reason as `check_and_record_dpop_jti`: adding it must not break
    /// any existing `OpStore`. Unlike that method the default is *off*, not fail-closed: a
    /// nonce is an extra freshness bound on top of proofs that are already verified and
    /// single-use, so a store without one behaves exactly as before. Opt in with
    /// `CompositeOpStore::with_dpop_nonces`.
    fn dpop_nonces(&self) -> Option<&authkestra_engine::token::dpop_nonce::DpopNonces> {
        None
    }

    /// Handle a custom grant type request during token exchange.
    ///
    /// By default, this returns an `unsupported_grant_type` error.
    async fn handle_custom_grant(
        &mut self,
        _grant_type: &str,
        _req: crate::handlers::token::TokenRequest,
        _client_id: String,
        _client: crate::client::ClientRegistration,
        _config: &crate::config::OpConfig,
        _tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<crate::handlers::token::TokenResponse, crate::handlers::token::TokenErrorResponse>
    {
        Err(crate::handlers::token::TokenErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: "Unsupported grant type".to_string(),
        })
    }

    /// Handle an `authorization_code` grant (RFC 6749 §4.1) request during
    /// token exchange.
    ///
    /// A defaulted method, same reasoning as `handle_refresh_token` and
    /// `handle_token_exchange` below: the built-in dispatch in
    /// `handlers::token::handle_token` used to match the literal string
    /// `"authorization_code"` and call straight into the built-in handler,
    /// with no seam an `OpStore` implementor could intercept. That made it
    /// impossible to stamp custom claims onto, or create session state for,
    /// tokens issued by the authorization-code flow — e.g.
    /// `TokenManager::issue_user_token_with_extra` exists precisely for
    /// this, but the built-in handler had no way to reach it — without
    /// forking the crate.
    ///
    /// The default (see `default_handle_authorization_code`) reproduces the
    /// existing authorization-code exchange logic (code consumption, PKCE
    /// verification, redirect_uri/client_id validation, and token
    /// issuance). Any `OpStore` that does not override this method gets
    /// that behavior automatically; nothing about the trait or dispatch
    /// changes for it.
    async fn handle_authorization_code_grant(
        &mut self,
        req: crate::handlers::token::TokenRequest,
        client_id: String,
        client: crate::client::ClientRegistration,
        config: &crate::config::OpConfig,
        tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<crate::handlers::token::TokenResponse, crate::handlers::token::TokenErrorResponse>
    {
        crate::handlers::token::default_handle_authorization_code(
            req, client_id, client, config, self, tokens,
        )
        .await
    }

    /// Handle a `refresh_token` grant request during token exchange.
    ///
    /// A defaulted method, same reasoning as `handle_custom_grant`: the
    /// built-in dispatch in `handlers::token::handle_token` used to match the
    /// literal string `"refresh_token"` and call straight into the built-in
    /// handler, with no seam an `OpStore` implementor could intercept. That
    /// made it impossible to substitute custom refresh behavior — e.g.
    /// re-minting an `id_token`, or a non-default rotation policy — without
    /// forking the crate.
    ///
    /// The default (see `default_handle_refresh_token`) consumes and
    /// rotates the refresh token, re-mints an access token, and — mirroring
    /// `default_handle_authorization_code` — re-mints an `id_token` too when
    /// the stored scope includes `openid` (OIDC Core §12.2 makes this
    /// optional; this crate now exercises that option instead of always
    /// omitting it).
    /// Any `OpStore` that does not override this method gets that behavior
    /// automatically; nothing about the trait or dispatch changes for it.
    async fn handle_refresh_token(
        &mut self,
        req: crate::handlers::token::TokenRequest,
        client_id: String,
        client: crate::client::ClientRegistration,
        config: &crate::config::OpConfig,
        tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<crate::handlers::token::TokenResponse, crate::handlers::token::TokenErrorResponse>
    {
        crate::handlers::token::default_handle_refresh_token(
            req, client_id, client, config, self, tokens,
        )
        .await
    }

    /// Handle a `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693)
    /// grant request during token exchange.
    ///
    /// A defaulted method, same reasoning as `handle_refresh_token`: the
    /// built-in dispatch in `handlers::token::handle_token` used to call the
    /// built-in handler directly, with no seam an `OpStore` implementor could
    /// intercept. That made it impossible to stamp custom claims onto the
    /// exchanged token — e.g. `TokenManager::issue_user_token_with_extra`
    /// exists precisely for this, but the built-in handler had no way to
    /// reach it — without forking the crate.
    ///
    /// The default (see `default_handle_token_exchange`) reproduces the
    /// existing exchange logic. Any `OpStore` that does not override this
    /// method gets that behavior automatically; nothing about the trait or
    /// dispatch changes for it.
    async fn handle_token_exchange(
        &mut self,
        req: crate::handlers::token::TokenRequest,
        client_id: String,
        client: crate::client::ClientRegistration,
        config: &crate::config::OpConfig,
        tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<crate::handlers::token::TokenResponse, crate::handlers::token::TokenErrorResponse>
    {
        crate::handlers::token::default_handle_token_exchange(
            req, client_id, client, config, tokens,
        )
        .await
    }
}

/// An `OpStore` that can be cloned behind a trait object.
///
/// This is the seam that lets `authkestra-axum`/`authkestra-actix` hand
/// each request its own independent, owned store instance — a plain
/// `Box::new(store.clone())` — instead of holding one shared instance
/// behind a lock for the whole handler. That distinction matters: a
/// pool-backed store (`authkestra-store-sqlx`'s `SqlxOpStore`, or either
/// ORM example crate) is already cheap to clone precisely because cloning
/// it doesn't clone the pool, just a handle to it, so serializing every
/// request behind one `Mutex` would throw away all of the pool's own
/// concurrency for no benefit.
///
/// **`Clone` here must mean "new handle to the same state", never "new,
/// independent copy of the state".** A handler clones the store once per
/// request and drops the clone when the request ends, so if `Clone`
/// duplicates the underlying data instead of sharing it, every write a
/// handler makes vanishes with that request's clone — e.g. an
/// `#[derive(Clone)]` over a plain `HashMap` field would compile, satisfy
/// this trait, and then silently make every `/authorize` write invisible to
/// the following `/token` exchange (always `invalid_grant`), with no
/// compile error, no log, and no failing test to catch it. Share mutable
/// state through an `Arc<Mutex<_>>`/`Arc<RwLock<_>>` field (as
/// `MemoryClientAssertionStore` and `authkestra_engine::store::MemoryStore`
/// do) or a connection-pool handle (`sqlx::Pool`, `deadpool`, etc.) that is
/// already cheap-clone-shares-state by construction, not by `#[derive]`ing
/// `Clone` over the data itself.
///
/// Blanket-implemented for any `OpStore + Clone` — nothing to implement by
/// hand. `CompositeOpStore` and every first-party backend already satisfy
/// it; a custom `OpStore` needs only `#[derive(Clone)]` (or a hand-written
/// impl) to pick it up too, **provided its `Clone` shares state** as
/// described above.
pub trait CloneableOpStore: OpStore {
    /// Returns an owned, independent clone of this store, boxed as a plain
    /// `OpStore` trait object (not `Self` or `CloneableOpStore` again) —
    /// callers use the clone for exactly one request and then drop it, so
    /// there's no need for the clone to itself be re-cloneable.
    fn clone_op_store(&self) -> Box<dyn OpStore>;
}

impl<T> CloneableOpStore for T
where
    T: OpStore + Clone + 'static,
{
    fn clone_op_store(&self) -> Box<dyn OpStore> {
        Box::new(self.clone())
    }
}

/// An [`OpStore`] scoped to a single open database transaction.
///
/// Every `OpStore` method called on one of these runs inside that
/// transaction, so nothing it writes is visible to anyone else — and
/// nothing is durable — until [`commit`](OpStoreTransaction::commit).
/// Dropping it without committing rolls the transaction back, which is what
/// makes `?` in the middle of a composed unit of work safe.
///
/// This is what the `&mut self` receiver on the store traits is *for*: the
/// transaction lives in the store value rather than being threaded through
/// every method as an extra argument. That choice is what keeps the traits
/// dyn-compatible, which the adapters depend on — `authkestra-axum` and
/// `authkestra-actix` hold an [`Arc<dyn CloneableOpStore>`](CloneableOpStore)
/// and clone a `Box<dyn OpStore>` per request. Neither trait object can be
/// named if `OpStore` stops being dyn-compatible, and a generic executor
/// parameter on each method would do exactly that.
///
/// Obtain one from [`TransactionalOpStore::begin`]. To interleave a host
/// application's *own* statements in the same transaction, use the
/// concrete store's inherent `begin_tx` instead, which returns the backend
/// type rather than a trait object — see that type's docs (e.g.
/// `authkestra_store_sqlx::SqlxOpStoreTx`) for the escape hatch that hands
/// you the native connection.
#[async_trait::async_trait]
pub trait OpStoreTransaction: OpStore {
    /// Commit the transaction, making every write durable at once.
    ///
    /// Takes `self: Box<Self>` rather than `self` so the trait stays
    /// dyn-compatible: a by-value `self` on a `?Sized` receiver is not
    /// expressible, and this trait is meant to be usable as
    /// `Box<dyn OpStoreTransaction>`.
    async fn commit(self: Box<Self>) -> Result<(), authkestra_engine::store::StoreError>;

    /// Roll the transaction back, discarding every write.
    ///
    /// Dropping without committing does this too; the explicit form exists
    /// so a caller can observe a rollback failure rather than have it
    /// swallowed by `Drop`.
    async fn rollback(self: Box<Self>) -> Result<(), authkestra_engine::store::StoreError>;
}

/// An [`OpStore`] whose backend can hand out transaction-scoped stores.
///
/// Deliberately a separate, opt-in trait rather than defaulted methods on
/// `OpStore`: a backend with no transactions (the in-memory store, Redis)
/// must not be able to accidentally claim this. There is no useful default
/// — one that committed each write immediately and made `rollback` a no-op
/// would hand callers a unit of work that silently isn't one, which is
/// worse than not offering the capability at all.
///
/// See [`OpStoreTransaction`] for why the transaction lives in the store
/// value instead of in the method signatures.
#[async_trait::async_trait]
pub trait TransactionalOpStore: OpStore {
    /// Begin a transaction and return a store scoped to it.
    ///
    /// Takes `&self`, not `&mut self`: beginning a transaction borrows the
    /// pool, not the store's own state, so a host application can start one
    /// from behind an `Arc` while request handlers keep using the
    /// non-transactional store.
    async fn begin(
        &self,
    ) -> Result<Box<dyn OpStoreTransaction + Send>, authkestra_engine::store::StoreError>;
}

/// A helper struct that implements `OpStore` by delegating to individual stores.
/// Useful if you want to use different backends for different types of data (e.g., config for clients, Redis for codes).
///
/// The client-assertion and DPoP-replay slots default to
/// [`NoClientAssertionStore`] and [`NoDpopReplayStore`] respectively, so
/// `private_key_jwt` and DPoP are both refused until a deployment opts in
/// with [`CompositeOpStore::with_client_assertion_store`] /
/// [`CompositeOpStore::with_dpop_replay_store`]. Both are defaulted type
/// parameters rather than required arguments to [`CompositeOpStore::new`]
/// so that existing four-store call sites keep compiling untouched.
#[derive(Clone)]
#[non_exhaustive]
pub struct CompositeOpStore<C, A, R, D, J = NoClientAssertionStore, P = NoDpopReplayStore> {
    clients: C,
    codes: A,
    refresh: R,
    devices: D,
    assertions: J,
    dpop_replays: P,
    dpop_nonces: Option<Arc<DpopNonces>>,
}

#[async_trait::async_trait]
impl<C, A, R, D, J, P> OpStore for CompositeOpStore<C, A, R, D, J, P>
where
    C: ClientStore,
    A: AuthorizationCodeStore,
    R: RefreshTokenStore,
    D: DeviceCodeStore,
    J: ClientAssertionStore,
    P: DpopReplayStore,
    Self: Send + Sync,
{
    async fn record_client_assertion_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        self.assertions.record_jti(jti, expires_at).await
    }

    async fn check_and_record_dpop_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        self.dpop_replays
            .check_and_record_dpop_jti(jti, expires_at)
            .await
    }

    fn dpop_nonces(&self) -> Option<&DpopNonces> {
        self.dpop_nonces.as_deref()
    }
}

impl<C, A, R, D> CompositeOpStore<C, A, R, D, NoClientAssertionStore, NoDpopReplayStore> {
    /// Create a new `CompositeOpStore` from individual stores.
    pub fn new(clients: C, codes: A, refresh: R, devices: D) -> Self {
        Self {
            clients,
            codes,
            refresh,
            devices,
            assertions: NoClientAssertionStore::default(),
            dpop_replays: NoDpopReplayStore::default(),
            dpop_nonces: None,
        }
    }
}

impl<C, A, R, D, J, P> CompositeOpStore<C, A, R, D, J, P> {
    /// Swaps in the backend that tracks spent `private_key_jwt` assertion
    /// `jti`s — the one thing this store needs before it will accept
    /// asymmetric client authentication at all.
    ///
    /// [`crate::client_assertion::MemoryClientAssertionStore`] is correct for
    /// a single-node deployment; a cluster needs something shared, because an
    /// unshared map means one accepted replay per node. Whichever is chosen,
    /// remember to advertise the method with
    /// [`crate::handlers::discovery::OidcDiscovery::with_private_key_jwt`] —
    /// discovery is deliberately silent about it otherwise.
    pub fn with_client_assertion_store<J2: ClientAssertionStore>(
        self,
        assertions: J2,
    ) -> CompositeOpStore<C, A, R, D, J2, P> {
        CompositeOpStore {
            clients: self.clients,
            codes: self.codes,
            refresh: self.refresh,
            devices: self.devices,
            assertions,
            dpop_replays: self.dpop_replays,
            dpop_nonces: self.dpop_nonces,
        }
    }

    /// Swaps in the backend that tracks spent DPoP proof `jti`s — the one
    /// thing this store needs before it will accept a `DPoP` header at
    /// `/token` at all.
    ///
    /// Any backend `authkestra_engine::store::AtomicInsert` is implemented
    /// for (`MemoryStore`, `RedisStore`, and the SQL backends) already
    /// implements [`crate::dpop::DpopReplayStore`] via its blanket impl — no
    /// DPoP-specific storage code is needed. A single-node deployment can
    /// use `authkestra_engine::store::memory::MemoryStore`; a cluster needs
    /// something shared, for the same reason `with_client_assertion_store`
    /// does.
    pub fn with_dpop_replay_store<P2: DpopReplayStore>(
        self,
        dpop_replays: P2,
    ) -> CompositeOpStore<C, A, R, D, J, P2> {
        CompositeOpStore {
            clients: self.clients,
            codes: self.codes,
            refresh: self.refresh,
            devices: self.devices,
            assertions: self.assertions,
            dpop_replays,
            dpop_nonces: self.dpop_nonces,
        }
    }

    /// Requires every DPoP proof presented at `/token` to carry a nonce from `nonces`
    /// (RFC 9449 §8). Off until called.
    ///
    /// With it, a proof without a valid `nonce` claim is refused `400 {"error":
    /// "use_dpop_nonce"}`, and the axum and actix token handlers put a fresh nonce in a
    /// `DPoP-Nonce` header on every token response — the refusal and the successes alike — so a
    /// client always holds a current one. A token request without a `DPoP` header is
    /// unaffected: the nonce constrains proofs, not bearer clients.
    ///
    /// A browser client on another origin can read the header only if the host's (or the
    /// proxy's) CORS policy lists `DPoP-Nonce` in `Access-Control-Expose-Headers` on token
    /// responses. Without that it never sees the nonce, and every retry is refused again.
    ///
    /// [`DpopNonces`] is stateless; give every node of a cluster the same secret
    /// ([`DpopNonces::new`]), or use [`DpopNonces::random`] on a single node.
    pub fn with_dpop_nonces(mut self, nonces: DpopNonces) -> Self {
        self.dpop_nonces = Some(Arc::new(nonces));
        self
    }
}

#[async_trait::async_trait]
impl<
        C: ClientStore,
        A: Send + Sync,
        R: Send + Sync,
        D: Send + Sync,
        J: Send + Sync,
        P: Send + Sync,
    > ClientStore for CompositeOpStore<C, A, R, D, J, P>
{
    #[tracing::instrument(skip(self))]
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<crate::client::ClientRegistration>, authkestra_engine::store::StoreError>
    {
        tracing::debug!(client_id = %client_id, "CompositeOpStore: finding client");
        self.clients.find_client(client_id).await
    }
}

#[async_trait::async_trait]
impl<
        C: Send + Sync,
        A: AuthorizationCodeStore,
        R: Send + Sync,
        D: Send + Sync,
        J: Send + Sync,
        P: Send + Sync,
    > AuthorizationCodeStore for CompositeOpStore<C, A, R, D, J, P>
{
    #[tracing::instrument(skip(self, code))]
    async fn store_code(
        &mut self,
        code: crate::code::AuthorizationCode,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: storing authorization code");
        self.codes.store_code(code).await
    }

    #[tracing::instrument(skip(self))]
    async fn consume_code(
        &mut self,
        code: &str,
    ) -> Result<Option<crate::code::AuthorizationCode>, authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: consuming authorization code");
        self.codes.consume_code(code).await
    }
}

#[async_trait::async_trait]
impl<
        C: Send + Sync,
        A: Send + Sync,
        R: RefreshTokenStore,
        D: Send + Sync,
        J: Send + Sync,
        P: Send + Sync,
    > RefreshTokenStore for CompositeOpStore<C, A, R, D, J, P>
{
    #[tracing::instrument(skip(self, token))]
    async fn store_token(
        &mut self,
        token: crate::refresh::RefreshToken,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: storing refresh token");
        self.refresh.store_token(token).await
    }

    #[tracing::instrument(skip(self))]
    async fn consume_token(
        &mut self,
        token: &str,
    ) -> Result<Option<crate::refresh::RefreshToken>, authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: consuming refresh token");
        self.refresh.consume_token(token).await
    }

    #[tracing::instrument(skip(self))]
    async fn get_token(
        &mut self,
        token: &str,
    ) -> Result<Option<crate::refresh::RefreshToken>, authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: getting refresh token");
        self.refresh.get_token(token).await
    }

    #[tracing::instrument(skip(self))]
    async fn revoke_token(
        &mut self,
        token: &str,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: revoking refresh token");
        self.refresh.revoke_token(token).await
    }
}

#[async_trait::async_trait]
impl<
        C: Send + Sync,
        A: Send + Sync,
        R: Send + Sync,
        D: DeviceCodeStore,
        J: Send + Sync,
        P: Send + Sync,
    > DeviceCodeStore for CompositeOpStore<C, A, R, D, J, P>
{
    #[tracing::instrument(skip(self, session))]
    async fn store_device_code(
        &mut self,
        session: crate::device::DeviceCodeSession,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: storing device code");
        self.devices.store_device_code(session).await
    }

    #[tracing::instrument(skip(self))]
    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
    {
        tracing::debug!(device_code = %device_code, "CompositeOpStore: getting device code");
        self.devices.get_device_code(device_code).await
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
    {
        tracing::debug!(user_code = %user_code, "CompositeOpStore: getting by user code");
        self.devices.get_by_user_code(user_code).await
    }

    #[tracing::instrument(skip(self, session))]
    async fn update_device_code(
        &mut self,
        session: crate::device::DeviceCodeSession,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: updating device code");
        self.devices.update_device_code(session).await
    }

    #[tracing::instrument(skip(self))]
    async fn delete_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!(device_code = %device_code, "CompositeOpStore: deleting device code");
        self.devices.delete_device_code(device_code).await
    }

    #[tracing::instrument(skip(self))]
    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError>
    {
        tracing::debug!(device_code = %device_code, "CompositeOpStore: consuming device code");
        self.devices.consume_device_code(device_code).await
    }
}
