use crate::models::{ClientRow, CodeRow, DeviceCodeRow, RefreshTokenRow};
use crate::schema::{oauth_clients, oauth_codes, oauth_device_codes, oauth_refresh_tokens};
use async_trait::async_trait;
use authkestra_engine::store::sqlite_url::is_private_memory_url;
use authkestra_engine::store::StoreError;
use authkestra_op::client::{ClientRegistration, ClientStore};
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus, DeviceCodeStore};
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use authkestra_op::store::OpStore;
use diesel::connection::{AnsiTransactionManager, TransactionManager};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::sqlite::SqliteConnection;

type SqlitePool = Pool<ConnectionManager<SqliteConnection>>;

fn pool_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Internal(format!("connection pool error: {e}"))
}

fn diesel_err(e: diesel::result::Error) -> StoreError {
    StoreError::Internal(format!("diesel error: {e}"))
}

/// Sets SQLite's `busy_timeout` on every connection r2d2 hands out.
///
/// Without it, SQLite's default is to fail a write immediately with
/// "database is locked" the instant it can't grab the single writer lock,
/// rather than waiting for the current writer to finish — turning any two
/// genuinely concurrent writers (e.g. two `consume_code` calls racing on
/// separate pooled connections, exactly the case the compare-and-swap in
/// `AuthorizationCodeStore::consume_code` is meant to resolve cleanly into
/// one winner and one `None`) into a hard error on whichever one loses,
/// instead of the loser simply waiting its turn and then correctly
/// observing the row as already consumed.
#[derive(Debug, Clone, Copy)]
struct SetBusyTimeout;

impl diesel::r2d2::CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SetBusyTimeout {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        diesel::sql_query("PRAGMA busy_timeout = 5000;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        // WAL mode lets readers proceed without waiting on the single
        // writer (rollback-journal mode's default), which is what actually
        // lets `busy_timeout` matter under real concurrent load rather than
        // every reader also contending for the same lock. A silent no-op
        // for a `:memory:`/temporary database, which SQLite doesn't support
        // WAL for — harmless there since that path is already capped to a
        // single connection anyway (see `connect`).
        diesel::sql_query("PRAGMA journal_mode = WAL;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
}

/// A real, compiled `OpStore` implementation backed by [`diesel`] —
/// authkestra#289's second proof (alongside `authkestra-example-seaorm`)
/// that the storage traits are implementable by a third-party ORM,
/// including one with a synchronous API.
///
/// Diesel is sync-only, so every trait method here hands its work to
/// [`tokio::task::spawn_blocking`] rather than blocking the async runtime —
/// the standard pattern for embedding a blocking library in async code, and
/// exactly what a real host application using Diesel would need to do too.
/// A connection pool (not a single connection) is required for this: a
/// `SqliteConnection` is `!Sync`, so each blocking task needs to check out
/// its own connection rather than share one across threads.
///
/// Deliberately simpler than `authkestra-store-sqlx` in the same ways
/// `authkestra-example-seaorm` is: no foreign-key constraints between
/// tables, and single-use consume goes through a transaction
/// (find-then-delete-or-mark-used) rather than a single
/// `UPDATE`/`DELETE ... RETURNING` statement.
#[derive(Clone)]
#[non_exhaustive]
pub struct DieselOpStore {
    pool: SqlitePool,
}

impl DieselOpStore {
    /// Builds a connection pool for `database_url` (e.g. `:memory:` or a
    /// file path) and wraps it.
    ///
    /// A private, per-connection in-memory (or temporary) database is
    /// special-cased to a single-connection pool: SQLite gives every such
    /// connection its own independent database, so a pool with r2d2's
    /// default size (10) would silently scatter this store's rows across
    /// ten unrelated in-memory databases — `migrate()` would create tables
    /// in whichever one it happens to check out, and any other checkout
    /// would see "no such table". A real (file-backed) database has no such
    /// problem and keeps the default pool size, since SQLite's own locking
    /// already serializes writers across connections. See
    /// [`authkestra_engine::store::sqlite_url::is_private_memory_url`] for
    /// exactly which URL forms count as private — shared with
    /// `authkestra-example-seaorm`'s identical guard, since both examples
    /// need to recognize the same set of SQLite spellings.
    pub fn connect(database_url: &str) -> Result<Self, diesel::r2d2::PoolError> {
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);
        let mut builder = Pool::builder().connection_customizer(Box::new(SetBusyTimeout));
        if is_private_memory_url(database_url) {
            builder = builder.max_size(1);
        }
        let pool = builder.build(manager)?;
        Ok(Self { pool })
    }

    /// Wraps an already-built connection pool.
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// The underlying connection pool, for host-application code that wants
    /// to run its own queries against the same database (e.g. seeding a
    /// `ClientRegistration` — `ClientStore` has no generic write path).
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run one synchronous query on a pooled connection, off the async
    /// runtime. The pool-backed counterpart to [`DieselOpStoreTx::run`],
    /// which runs the same closure on the connection its transaction owns —
    /// having both means every query in `queries` is written once and driven
    /// two ways.
    async fn run<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut SqliteConnection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            f(&mut conn)
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }

    /// Begin a transaction and return a store scoped to it.
    ///
    /// Diesel is synchronous and has no owned transaction object, so this
    /// holds the checked-out connection with a transaction open on it and
    /// drives it through `spawn_blocking` per call. The connection is moved
    /// into the blocking task and moved back out again, which is what lets a
    /// `!Sync` `SqliteConnection` be held across await points at all.
    ///
    /// Note this takes the connection out of the pool for as long as the
    /// transaction is open — the same cost any synchronous transaction has,
    /// but worth stating, since a pool sized for request concurrency needs
    /// headroom for however many of these a host application holds at once.
    pub async fn begin_tx(&self) -> Result<DieselOpStoreTx, StoreError> {
        let pool = self.pool.clone();
        let conn = tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            // `BEGIN IMMEDIATE`, matching the `immediate_transaction` the
            // consume paths use when they run on the pool: it takes the
            // write lock up front rather than discovering a conflict at the
            // first write and failing with SQLITE_BUSY halfway through a
            // unit of work the caller believes it has already secured.
            AnsiTransactionManager::begin_transaction_sql(&mut *conn, "BEGIN IMMEDIATE")
                .map_err(diesel_err)?;
            Ok::<_, StoreError>(conn)
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))??;

        Ok(DieselOpStoreTx {
            conn: std::sync::Mutex::new(Some(conn)),
        })
    }

    /// Creates the four tables this store needs, if they don't already
    /// exist. Idempotent — safe to call on every startup, same contract as
    /// `authkestra-store-sqlx::SqlxOpStore::migrate`.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(pool_err)?;
            diesel::sql_query(
                "CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_secret_hash TEXT,
                    require_pkce BOOLEAN NOT NULL,
                    redirect_uris TEXT NOT NULL,
                    grant_types TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    allowed_audiences TEXT NOT NULL,
                    token_endpoint_auth_method TEXT,
                    jwks TEXT
                )",
            )
            .execute(&mut conn)
            .map_err(diesel_err)?;
            diesel::sql_query(
                "CREATE TABLE IF NOT EXISTS oauth_codes (
                    code TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    code_challenge TEXT,
                    code_challenge_method TEXT,
                    nonce TEXT,
                    identity TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN NOT NULL
                )",
            )
            .execute(&mut conn)
            .map_err(diesel_err)?;
            diesel::sql_query(
                "CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
                    token TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    jkt TEXT
                )",
            )
            .execute(&mut conn)
            .map_err(diesel_err)?;
            diesel::sql_query(
                "CREATE TABLE IF NOT EXISTS oauth_device_codes (
                    device_code TEXT PRIMARY KEY,
                    user_code TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    last_polled_at TIMESTAMP
                )",
            )
            .execute(&mut conn)
            .map_err(diesel_err)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }
}

/// A [`DieselOpStore`] scoped to one open transaction — the synchronous
/// counterpart to `authkestra-store-sqlx`'s `SqlxOpStoreTx`, and the case
/// that most stresses the design: Diesel has no owned transaction handle and
/// its connections are `!Sync`, so the transaction lives as an open
/// transaction *on a connection this type owns*, moved in and out of
/// `spawn_blocking` for each call.
///
/// That it works at all is the point: because the transaction lives in the
/// store value rather than in the method signatures, a backend whose native
/// API has no transaction object to pass around can still implement the
/// trait unchanged.
///
/// Obtain one from [`DieselOpStore::begin_tx`]. [`run`](Self::run) is the
/// escape hatch for the host application's own Diesel queries — it hands a
/// `&mut SqliteConnection` inside the same transaction.
#[non_exhaustive]
pub struct DieselOpStoreTx {
    /// `Option` so the connection can be moved into a blocking task and
    /// moved back; it is `Some` at every await point except during a call.
    ///
    /// The `Mutex` is not for concurrency — every access below goes through
    /// `get_mut`, and an open transaction is exclusively owned anyway. It is
    /// here purely to satisfy the `Send + Sync` bound the store traits carry:
    /// a `SqliteConnection` is `Send` but `!Sync`, so without the wrapper
    /// this type cannot implement `OpStore` at all. Worth noting as a wart —
    /// `Sync` buys those traits nothing now that every method takes
    /// `&mut self` — but relaxing the bound is a breaking change to every
    /// implementor, so it stays for now.
    conn: std::sync::Mutex<Option<PooledConnection<ConnectionManager<SqliteConnection>>>>,
}

impl DieselOpStoreTx {
    /// Run one synchronous closure on this transaction's connection, off the
    /// async runtime.
    ///
    /// Public because it is also how a host application runs *its own*
    /// Diesel queries inside this transaction — the equivalent of
    /// `SqlxOpStoreTx::as_mut`, shaped as a closure rather than a borrow
    /// because a `!Sync` connection cannot be lent across an await point.
    pub async fn run<T, F>(&mut self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut SqliteConnection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let mut conn = self.take_conn()?;
        let (conn, result) = tokio::task::spawn_blocking(move || {
            let result = f(&mut conn);
            (conn, result)
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?;
        *self
            .conn
            .get_mut()
            .expect("transaction mutex is never poisoned") = Some(conn);
        result
    }

    fn take_conn(
        &mut self,
    ) -> Result<PooledConnection<ConnectionManager<SqliteConnection>>, StoreError> {
        self.conn
            .get_mut()
            .expect("transaction mutex is never poisoned")
            .take()
            .ok_or_else(|| {
                StoreError::Internal("diesel transaction connection is gone".to_string())
            })
    }

    /// Commit, making every write in this transaction durable at once.
    pub async fn commit(mut self) -> Result<(), StoreError> {
        self.finish(true).await
    }

    /// Roll back, discarding every write in this transaction.
    pub async fn rollback(mut self) -> Result<(), StoreError> {
        self.finish(false).await
    }

    async fn finish(&mut self, commit: bool) -> Result<(), StoreError> {
        let mut conn = self.take_conn()?;
        tokio::task::spawn_blocking(move || {
            if commit {
                AnsiTransactionManager::commit_transaction(&mut *conn).map_err(diesel_err)
            } else {
                AnsiTransactionManager::rollback_transaction(&mut *conn).map_err(diesel_err)
            }
        })
        .await
        .map_err(|e| StoreError::Internal(format!("diesel worker task failed: {e}")))?
    }
}

impl Drop for DieselOpStoreTx {
    /// Roll back on drop, so an early `?` in a host application's unit of
    /// work cannot leave the transaction open.
    ///
    /// This has to happen synchronously — `Drop` cannot await — which is
    /// safe enough here (a local `ROLLBACK` on an already-checked-out
    /// connection) but is a real reason to prefer calling
    /// [`commit`](Self::commit) or [`rollback`](Self::rollback) explicitly.
    ///
    /// Doing nothing would not be a silent success: r2d2 asks Diesel whether
    /// a returned connection is broken, and a connection still inside a
    /// transaction answers yes, so the pool would discard it and dial a new
    /// one. The data outcome is the same (nothing was committed), but the
    /// pool pays for a reconnect on every dropped transaction — and against
    /// an in-memory SQLite database, where the connection *is* the database,
    /// the reconnect silently starts from an empty schema.
    fn drop(&mut self) {
        if let Ok(slot) = self.conn.get_mut() {
            if let Some(mut conn) = slot.take() {
                let _ = AnsiTransactionManager::rollback_transaction(&mut *conn);
            }
        }
    }
}

#[async_trait]
impl authkestra_op::store::TransactionalOpStore for DieselOpStore {
    async fn begin(
        &self,
    ) -> Result<Box<dyn authkestra_op::store::OpStoreTransaction + Send>, StoreError> {
        Ok(Box::new(self.begin_tx().await?))
    }
}

#[async_trait]
impl authkestra_op::store::OpStoreTransaction for DieselOpStoreTx {
    async fn commit(self: Box<Self>) -> Result<(), StoreError> {
        DieselOpStoreTx::commit(*self).await
    }

    async fn rollback(self: Box<Self>) -> Result<(), StoreError> {
        DieselOpStoreTx::rollback(*self).await
    }
}

/// Every query this store runs, written once as plain synchronous Diesel
/// against a borrowed connection — no pool checkout, no `spawn_blocking`.
/// Both [`DieselOpStore`] (which checks a connection out per call) and
/// [`DieselOpStoreTx`] (which owns one for the life of its transaction)
/// drive these through their own `run` helper.
mod queries {
    use super::*;

    /// True when `conn` already has a transaction (or savepoint) open.
    fn in_transaction(conn: &mut SqliteConnection) -> bool {
        AnsiTransactionManager::transaction_manager_status_mut(conn)
            .transaction_depth()
            .ok()
            .flatten()
            .is_some()
    }

    /// Run `f` atomically, whether or not a transaction is already open.
    ///
    /// The single-use consume paths need their own atomic scope, and on the
    /// pool that means `BEGIN IMMEDIATE` — taking SQLite's write lock up
    /// front rather than failing with `SQLITE_BUSY` at the first write. But
    /// SQLite has no nested `BEGIN`: called inside a host application's
    /// transaction (`DieselOpStoreTx`), the same statement errors with
    /// "cannot start a transaction within a transaction". Diesel's plain
    /// `transaction` issues a SAVEPOINT once the depth is non-zero, which is
    /// the correct nested form — governed by the outer commit or rollback —
    /// so pick between them by depth.
    ///
    /// The outer transaction was itself opened with `BEGIN IMMEDIATE` (see
    /// [`DieselOpStore::begin_tx`]), so the write lock this would have taken
    /// is already held by the time a savepoint is used instead. Nothing is
    /// given up by the switch.
    fn atomically<T>(
        conn: &mut SqliteConnection,
        f: impl FnOnce(&mut SqliteConnection) -> Result<T, diesel::result::Error>,
    ) -> Result<T, diesel::result::Error> {
        if in_transaction(conn) {
            conn.transaction(f)
        } else {
            conn.immediate_transaction(f)
        }
    }

    pub(crate) fn find_client(
        conn: &mut SqliteConnection,
        client_id: String,
    ) -> Result<Option<ClientRegistration>, StoreError> {
        let row: Option<ClientRow> = oauth_clients::table
            .find(client_id)
            .first(conn)
            .optional()
            .map_err(diesel_err)?;
        row.map(ClientRow::into_domain).transpose()
    }

    pub(crate) fn store_code(conn: &mut SqliteConnection, row: CodeRow) -> Result<(), StoreError> {
        diesel::insert_into(oauth_codes::table)
            .values(&row)
            .execute(conn)
            .map_err(diesel_err)?;
        Ok(())
    }

    pub(crate) fn consume_code(
        conn: &mut SqliteConnection,
        code: String,
    ) -> Result<Option<AuthorizationCode>, StoreError> {
        atomically(conn, |conn| {
            let row: Option<CodeRow> = oauth_codes::table.find(&code).first(conn).optional()?;
            let Some(mut row) = row else {
                return Ok(None);
            };
            // Single-use, atomically: the `UPDATE ... WHERE used =
            // false` below is the actual compare-and-swap — two
            // concurrent consumers can both reach this point having
            // read `used: false` above, but only the one whose UPDATE
            // affects a row (still `used = false` at write time) may
            // treat the code as consumed. Same shape, and the same
            // reasoning, as authkestra-store-sqlx's own consume_code;
            // the `find` above is a read for the fields to return, not
            // the authority on whether this call wins the race.
            let affected = diesel::update(
                oauth_codes::table
                    .filter(oauth_codes::code.eq(&code))
                    .filter(oauth_codes::used.eq(false)),
            )
            .set(oauth_codes::used.eq(true))
            .execute(conn)?;
            if affected != 1 {
                return Ok(None);
            }
            row.used = true;
            Ok::<_, diesel::result::Error>(Some(row))
        })
        .map_err(diesel_err)?
        .map(CodeRow::into_domain)
        .transpose()
    }

    pub(crate) fn store_token(
        conn: &mut SqliteConnection,
        row: RefreshTokenRow,
    ) -> Result<(), StoreError> {
        diesel::insert_into(oauth_refresh_tokens::table)
            .values(&row)
            .execute(conn)
            .map_err(diesel_err)?;
        Ok(())
    }

    pub(crate) fn get_token(
        conn: &mut SqliteConnection,
        token: String,
    ) -> Result<Option<RefreshToken>, StoreError> {
        let row: Option<RefreshTokenRow> = oauth_refresh_tokens::table
            .find(token)
            .first(conn)
            .optional()
            .map_err(diesel_err)?;
        row.map(RefreshTokenRow::into_domain).transpose()
    }

    pub(crate) fn revoke_token(
        conn: &mut SqliteConnection,
        token: String,
    ) -> Result<(), StoreError> {
        diesel::delete(oauth_refresh_tokens::table.find(token))
            .execute(conn)
            .map_err(diesel_err)?;
        Ok(())
    }

    pub(crate) fn consume_token(
        conn: &mut SqliteConnection,
        token: String,
    ) -> Result<Option<RefreshToken>, StoreError> {
        atomically(conn, |conn| {
            let row: Option<RefreshTokenRow> = oauth_refresh_tokens::table
                .find(&token)
                .first(conn)
                .optional()?;
            let Some(row) = row else {
                return Ok(None);
            };
            // The DELETE, not the `find` above, is what's atomic: two
            // concurrent consumers can both read the row present, but
            // only the one whose DELETE actually removes it (checked
            // via the affected-row count) may treat the token as
            // consumed — same compare-and-swap reasoning as
            // `consume_code`.
            let affected =
                diesel::delete(oauth_refresh_tokens::table.find(&token)).execute(conn)?;
            if affected != 1 {
                return Ok(None);
            }
            Ok::<_, diesel::result::Error>(Some(row))
        })
        .map_err(diesel_err)?
        .map(RefreshTokenRow::into_domain)
        .transpose()
    }

    pub(crate) fn store_device_code(
        conn: &mut SqliteConnection,
        row: DeviceCodeRow,
    ) -> Result<(), StoreError> {
        diesel::insert_into(oauth_device_codes::table)
            .values(&row)
            .execute(conn)
            .map_err(diesel_err)?;
        Ok(())
    }

    pub(crate) fn get_device_code(
        conn: &mut SqliteConnection,
        device_code: String,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let row: Option<DeviceCodeRow> = oauth_device_codes::table
            .find(device_code)
            .first(conn)
            .optional()
            .map_err(diesel_err)?;
        row.map(DeviceCodeRow::into_domain).transpose()
    }

    pub(crate) fn get_by_user_code(
        conn: &mut SqliteConnection,
        user_code: String,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let row: Option<DeviceCodeRow> = oauth_device_codes::table
            .filter(oauth_device_codes::user_code.eq(user_code))
            .first(conn)
            .optional()
            .map_err(diesel_err)?;
        row.map(DeviceCodeRow::into_domain).transpose()
    }

    pub(crate) fn update_device_code(
        conn: &mut SqliteConnection,
        row: DeviceCodeRow,
        device_code: String,
    ) -> Result<(), StoreError> {
        let existing = get_device_code(conn, device_code.clone())?;
        match existing {
            Some(e) if matches!(e.status, DeviceCodeStatus::Pending) => {}
            _ => {
                tracing::warn!(
                    device_code = %device_code,
                    "diesel update_device_code rejected: session missing or not in Pending state"
                );
                return Err(StoreError::NotFound);
            }
        }
        let pending_status = serde_json::to_string(&DeviceCodeStatus::Pending)
            .map_err(|_| StoreError::Internal("db".into()))?;
        let affected = diesel::update(
            oauth_device_codes::table
                .filter(oauth_device_codes::device_code.eq(&device_code))
                .filter(oauth_device_codes::status.eq(pending_status)),
        )
        .set(&row)
        .execute(conn)
        .map_err(diesel_err)?;
        if affected != 1 {
            tracing::warn!(
                device_code = %device_code,
                "diesel update_device_code affected 0 rows (record missing or no longer Pending)"
            );
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub(crate) fn delete_device_code(
        conn: &mut SqliteConnection,
        device_code: String,
    ) -> Result<(), StoreError> {
        diesel::delete(oauth_device_codes::table.find(device_code))
            .execute(conn)
            .map_err(diesel_err)?;
        Ok(())
    }

    pub(crate) fn consume_device_code(
        conn: &mut SqliteConnection,
        device_code: String,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        atomically(conn, |conn| {
            let row: Option<DeviceCodeRow> = oauth_device_codes::table
                .find(&device_code)
                .first(conn)
                .optional()?;
            let Some(row) = row else {
                return Ok(None);
            };
            // Same compare-and-swap reasoning as `consume_token`: the
            // DELETE's affected-row count, not the read above, decides
            // whether this call wins the race against a concurrent
            // consumer of the same device code.
            let affected =
                diesel::delete(oauth_device_codes::table.find(&device_code)).execute(conn)?;
            if affected != 1 {
                return Ok(None);
            }
            Ok::<_, diesel::result::Error>(Some(row))
        })
        .map_err(diesel_err)?
        .map(DeviceCodeRow::into_domain)
        .transpose()
    }
}

#[async_trait]
impl ClientStore for DieselOpStore {
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, StoreError> {
        let client_id = client_id.to_string();
        self.run(move |conn| queries::find_client(conn, client_id))
            .await
    }
}

#[async_trait]
impl AuthorizationCodeStore for DieselOpStore {
    async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), StoreError> {
        let row = CodeRow::from_domain(&code)?;
        self.run(move |conn| queries::store_code(conn, row)).await
    }
    async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, StoreError> {
        let code = code.to_string();
        self.run(move |conn| queries::consume_code(conn, code))
            .await
    }
}

#[async_trait]
impl RefreshTokenStore for DieselOpStore {
    async fn store_token(&mut self, token: RefreshToken) -> Result<(), StoreError> {
        let row = RefreshTokenRow::from_domain(&token)?;
        self.run(move |conn| queries::store_token(conn, row)).await
    }
    async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        let token = token.to_string();
        self.run(move |conn| queries::get_token(conn, token)).await
    }
    async fn revoke_token(&mut self, token: &str) -> Result<(), StoreError> {
        let token = token.to_string();
        self.run(move |conn| queries::revoke_token(conn, token))
            .await
    }
    async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        let token = token.to_string();
        self.run(move |conn| queries::consume_token(conn, token))
            .await
    }
}

#[async_trait]
impl DeviceCodeStore for DieselOpStore {
    async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let row = DeviceCodeRow::from_domain(&session)?;
        self.run(move |conn| queries::store_device_code(conn, row))
            .await
    }
    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let device_code = device_code.to_string();
        self.run(move |conn| queries::get_device_code(conn, device_code))
            .await
    }
    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let user_code = user_code.to_string();
        self.run(move |conn| queries::get_by_user_code(conn, user_code))
            .await
    }
    async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let row = DeviceCodeRow::from_domain(&session)?;
        let device_code = session.device_code.clone();
        self.run(move |conn| queries::update_device_code(conn, row, device_code))
            .await
    }
    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), StoreError> {
        let device_code = device_code.to_string();
        self.run(move |conn| queries::delete_device_code(conn, device_code))
            .await
    }
    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let device_code = device_code.to_string();
        self.run(move |conn| queries::consume_device_code(conn, device_code))
            .await
    }
}

impl OpStore for DieselOpStore {}

#[async_trait]
impl ClientStore for DieselOpStoreTx {
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, StoreError> {
        let client_id = client_id.to_string();
        self.run(move |conn| queries::find_client(conn, client_id))
            .await
    }
}

#[async_trait]
impl AuthorizationCodeStore for DieselOpStoreTx {
    async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), StoreError> {
        let row = CodeRow::from_domain(&code)?;
        self.run(move |conn| queries::store_code(conn, row)).await
    }
    async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, StoreError> {
        let code = code.to_string();
        self.run(move |conn| queries::consume_code(conn, code))
            .await
    }
}

#[async_trait]
impl RefreshTokenStore for DieselOpStoreTx {
    async fn store_token(&mut self, token: RefreshToken) -> Result<(), StoreError> {
        let row = RefreshTokenRow::from_domain(&token)?;
        self.run(move |conn| queries::store_token(conn, row)).await
    }
    async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        let token = token.to_string();
        self.run(move |conn| queries::get_token(conn, token)).await
    }
    async fn revoke_token(&mut self, token: &str) -> Result<(), StoreError> {
        let token = token.to_string();
        self.run(move |conn| queries::revoke_token(conn, token))
            .await
    }
    async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        let token = token.to_string();
        self.run(move |conn| queries::consume_token(conn, token))
            .await
    }
}

#[async_trait]
impl DeviceCodeStore for DieselOpStoreTx {
    async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let row = DeviceCodeRow::from_domain(&session)?;
        self.run(move |conn| queries::store_device_code(conn, row))
            .await
    }
    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let device_code = device_code.to_string();
        self.run(move |conn| queries::get_device_code(conn, device_code))
            .await
    }
    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let user_code = user_code.to_string();
        self.run(move |conn| queries::get_by_user_code(conn, user_code))
            .await
    }
    async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let row = DeviceCodeRow::from_domain(&session)?;
        let device_code = session.device_code.clone();
        self.run(move |conn| queries::update_device_code(conn, row, device_code))
            .await
    }
    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), StoreError> {
        let device_code = device_code.to_string();
        self.run(move |conn| queries::delete_device_code(conn, device_code))
            .await
    }
    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        let device_code = device_code.to_string();
        self.run(move |conn| queries::consume_device_code(conn, device_code))
            .await
    }
}

impl OpStore for DieselOpStoreTx {}
