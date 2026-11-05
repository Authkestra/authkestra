//! Native, batteries-included SQL storage for `authkestra-op`'s `OpStore`,
//! via [`sqlx`]. Split out of `authkestra-op` itself (authkestra#289) so
//! that core has zero `sqlx` dependency — anyone wanting SQL-backed storage
//! adds this satellite crate explicitly, selecting one or more of the
//! `postgres`/`mysql`/`sqlite` features for the backend(s) they need.
//!
//! While a generic `KvStore` exists in `authkestra-engine` for JSON blob
//! persistence across the framework, the OpenID Provider's [`SqlxOpStore`]
//! is deliberately opinionated instead: highly normalized SQL tables with
//! proper relational foreign keys, `ON DELETE CASCADE` constraints, and
//! strictly defined columns (`client_id`, `scopes`, `expires_at`, ...).

use async_trait::async_trait;
use authkestra_op::client::{ClientRegistration, ClientStore, TokenEndpointAuthMethod};
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStore};
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};

// Model for database rows, using sqlx::FromRow would require fields to match perfectly.
// Since we are mapping JSON strings back into structs, we will map rows manually.

/// Opinionated, native SQL implementation of OpStore using sqlx.
#[derive(Debug)]
#[non_exhaustive]
pub struct SqlxOpStore<DB: sqlx::Database> {
    pool: sqlx::Pool<DB>,
}

// Written by hand rather than `#[derive(Clone)]`: the derive macro adds a
// `DB: Clone` bound on the generic parameter, but `sqlx::Pool<DB>` is
// already cheaply cloneable (it's a handle around a shared connection pool)
// regardless of whether the `Database` marker type itself implements
// `Clone` — Postgres/MySql/Sqlite don't.
impl<DB: sqlx::Database> SqlxOpStore<DB> {
    /// Check a connection out of the pool for one query.
    ///
    /// Every `OpStore` method on the pool-backed store goes through here,
    /// which is the only thing that distinguishes it from `SqlxOpStoreTx` —
    /// that one already owns a connection with a transaction open on it.
    async fn conn(
        &self,
    ) -> Result<sqlx::pool::PoolConnection<DB>, authkestra_engine::store::StoreError> {
        self.pool.acquire().await.map_err(|e| {
            tracing::error!(error = %e, "sqlx pool acquire error");
            authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
        })
    }
}

impl<DB: sqlx::Database> Clone for SqlxOpStore<DB> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }
}

/// A [`SqlxOpStore`] scoped to one open `sqlx` transaction — every store
/// method called on it runs inside that transaction, and nothing lands until
/// [`commit`](Self::commit).
///
/// Obtain one from [`SqlxOpStore::begin_tx`]. Dropping it without committing
/// rolls back, so an early `?` in the middle of a composed unit of work
/// cannot leave a half-written state behind.
///
/// # Composing with the host application's own writes
///
/// This is the point of the type. [`as_mut`](AsMut::as_mut) hands back the
/// live connection, so the application's own statements and the store's run
/// in the same transaction and commit or roll back together:
///
/// ```ignore
/// let mut tx = store.begin_tx().await?;
///
/// sqlx::query("INSERT INTO app_users (id, email) VALUES (?1, ?2)")
///     .bind(&user_id)
///     .bind(&email)
///     .execute(tx.as_mut())
///     .await?;
///
/// tx.store_token(refresh_token).await?;   // same transaction
///
/// tx.commit().await?;                     // both, or neither
/// ```
///
/// Reaching the native connection is deliberately an inherent method rather
/// than something on the [`OpStoreTransaction`](authkestra_op::store::OpStoreTransaction)
/// trait: the host's own queries are written against a concrete driver, so
/// there is nothing for a backend-agnostic trait to usefully return here.
/// Keeping it off the trait is what lets the trait stay dyn-compatible.
#[derive(Debug)]
#[non_exhaustive]
pub struct SqlxOpStoreTx<DB: sqlx::Database> {
    tx: sqlx::Transaction<'static, DB>,
}

/// The live connection inside this transaction, for the host application's own
/// statements — `tx.as_mut()`, exactly as it reads on a bare
/// [`sqlx::Transaction`], so a caller's queries look the way they would
/// anywhere else in their code.
impl<DB: sqlx::Database> AsMut<DB::Connection> for SqlxOpStoreTx<DB> {
    fn as_mut(&mut self) -> &mut DB::Connection {
        &mut self.tx
    }
}

impl<DB: sqlx::Database> SqlxOpStoreTx<DB> {
    /// Commit, making every write in this transaction durable at once.
    pub async fn commit(self) -> Result<(), authkestra_engine::store::StoreError> {
        self.tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "sqlx commit error");
            authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
        })
    }

    /// Roll back, discarding every write in this transaction.
    ///
    /// Dropping does this too; calling it explicitly is how a caller gets to
    /// see a rollback failure rather than have `Drop` swallow it.
    pub async fn rollback(self) -> Result<(), authkestra_engine::store::StoreError> {
        self.tx.rollback().await.map_err(|e| {
            tracing::error!(error = %e, "sqlx rollback error");
            authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
        })
    }
}

/// Add `column` to `table` (in the `authkestra` schema) if it isn't
/// already there.
///
/// Postgres *does* support `ADD COLUMN IF NOT EXISTS`, but it still takes
/// an ACCESS EXCLUSIVE lock on the relation before discovering there is
/// nothing to do — and because Postgres lock requests are FIFO, an ALTER
/// that queues behind a long-running transaction blocks every subsequent
/// read of that table until the blocker clears. `migrate()` runs at every
/// startup, so probing the catalog first keeps the steady state lock-free.
/// The `IF NOT EXISTS` is retained *inside* the guard so a concurrently
/// starting replica racing the same ALTER is still handled by Postgres
/// itself, under the lock — which is why this backend needs no equivalent
/// of `is_sqlite_duplicate_column`/`is_mysql_duplicate_column`.
///
/// `table_schema` is not optional here: `information_schema.columns` spans
/// every schema the role can see, so an unqualified probe would be
/// satisfied by a host application's own same-named table in `public` and
/// would skip an ALTER that `authkestra`'s table still needs.
#[cfg(feature = "postgres")]
async fn ensure_postgres_column(
    pool: &sqlx::PgPool,
    table: &str,
    column: &str,
    add_column_ddl: &str,
) -> Result<(), sqlx::Error> {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema = 'authkestra' AND table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await?;
    if exists == 0 {
        // `info!`, not `debug!`: this alters the host application's schema.
        // A deployment should be able to see that happen without having to
        // turn debug logging on, and this whole path was silent.
        tracing::info!(
            table,
            column,
            "adding a missing column to the authkestra schema"
        );
        sqlx::query(&format!(
            "ALTER TABLE authkestra.{table} ADD COLUMN IF NOT EXISTS {add_column_ddl}"
        ))
        .execute(pool)
        .await?;
    } else {
        tracing::debug!(table, column, "column already present; no migration needed");
    }
    Ok(())
}

/// True only for "the column is already there" — the exact error the loser
/// of a check-then-ALTER race gets when another process added the column
/// between our `pragma_table_info` probe and our `ALTER`.
///
/// SQLite reports this as plain `SQLITE_ERROR` (1), the same extended
/// result code as a syntax error or a missing table, so `code()` cannot
/// discriminate it. The message is the only reliable signal, and its text
/// is fixed in SQLite's `alter.c` as `duplicate column name: <name>`.
#[cfg(feature = "sqlite")]
fn is_sqlite_duplicate_column(e: &sqlx::Error) -> bool {
    // `message()` resolves through the `dyn DatabaseError` object itself, so
    // no trait import is needed here (nor in the MySQL classifier below).
    e.as_database_error()
        .is_some_and(|db| db.message().starts_with("duplicate column name:"))
}

/// True only for MySQL `ER_DUP_FIELDNAME` (1060, SQLSTATE 42S21) — see the
/// SQLite equivalent above for why this narrow tolerance exists.
///
/// Matched on the error *number*, not the message or SQLSTATE: a missing
/// table (1146) or a bad column type (1064) stays fatal.
#[cfg(feature = "mysql")]
fn is_mysql_duplicate_column(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|db| db.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
        .is_some_and(|db| db.number() == 1060)
}

/// Add `column` to `table` if it isn't already there.
///
/// SQLite has no `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (unlike
/// Postgres 9.6+), so this introspects via `pragma_table_info` first. Used
/// by [`SqlxOpStore::<sqlx::Sqlite>::migrate`] instead of `sqlx::migrate!` —
/// see that function's doc comment for why.
#[cfg(feature = "sqlite")]
async fn ensure_sqlite_column(
    pool: &sqlx::SqlitePool,
    table: &str,
    column: &str,
    add_column_ddl: &str,
) -> Result<(), sqlx::Error> {
    let exists: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?"
    ))
    .bind(column)
    .fetch_one(pool)
    .await?;
    if exists == 0 {
        // A concurrently-starting replica may have added the column between
        // the probe above and here; that is the *intended* end state, so it
        // is success, not a failed migration. Nothing else is tolerated —
        // see `is_sqlite_duplicate_column`.
        tracing::info!(
            table,
            column,
            "adding a missing column to the authkestra schema"
        );
        if let Err(e) = sqlx::query(&format!("ALTER TABLE {table} ADD COLUMN {add_column_ddl}"))
            .execute(pool)
            .await
        {
            if !is_sqlite_duplicate_column(&e) {
                tracing::error!(table, column, error = %e, "column migration failed");
                return Err(e);
            }
            // The intended end state, reached by somebody else. Worth a line
            // during a rolling deploy: it says another replica won the race
            // rather than that this one did nothing.
            tracing::debug!(
                table,
                column,
                "column was added concurrently by another process; treating as done"
            );
        }
    } else {
        tracing::debug!(table, column, "column already present; no migration needed");
    }
    Ok(())
}

/// Add `column` to `table` if it isn't already there.
///
/// MySQL has no universally-available `ADD COLUMN IF NOT EXISTS` across
/// commonly-deployed versions, so this introspects via
/// `information_schema.columns` first. Used by
/// [`SqlxOpStore::<sqlx::MySql>::migrate`] instead of `sqlx::migrate!` —
/// see the Postgres impl's doc comment for why.
#[cfg(feature = "mysql")]
async fn ensure_mysql_column(
    pool: &sqlx::MySqlPool,
    table: &str,
    column: &str,
    add_column_ddl: &str,
) -> Result<(), sqlx::Error> {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await?;
    if exists == 0 {
        // See `ensure_sqlite_column`'s identical comment: only the losing
        // side of a check-then-ALTER race is tolerated here.
        tracing::info!(
            table,
            column,
            "adding a missing column to the authkestra schema"
        );
        if let Err(e) = sqlx::query(&format!("ALTER TABLE {table} ADD COLUMN {add_column_ddl}"))
            .execute(pool)
            .await
        {
            if !is_mysql_duplicate_column(&e) {
                tracing::error!(table, column, error = %e, "column migration failed");
                return Err(e);
            }
            // The intended end state, reached by somebody else. Worth a line
            // during a rolling deploy: it says another replica won the race
            // rather than that this one did nothing.
            tracing::debug!(
                table,
                column,
                "column was added concurrently by another process; treating as done"
            );
        }
    } else {
        tracing::debug!(table, column, "column already present; no migration needed");
    }
    Ok(())
}

macro_rules! impl_opstore_sql {
    (
        $backend:path,
        $feature:literal,
        $queries:ident,
        $placeholder_fmt:expr,
        $schema_prefix:literal,
        $migrate_impl:item,
        $consume_code_fn:item,
        $consume_token_fn:item,
        $consume_device_fn:item,
        $dpop_jti_fn:item
    ) => {
        /// Every query this backend runs, written once against a plain
        /// connection rather than against a pool, so the pool-backed store
        /// and the transaction-scoped store below can share them verbatim
        /// instead of keeping two copies of the same SQL in sync.
        ///
        /// Taking `&mut Conn` (not a generic `sqlx::Executor`) is what makes
        /// the composed case correct: a `Connection` can `begin()`, and sqlx
        /// turns a `begin()` on a connection that is already inside a
        /// transaction into a SAVEPOINT. So the consume paths that need their
        /// own transaction (MySQL's `SELECT ... FOR UPDATE`) get a real one
        /// when called on the pool, and a nested savepoint — governed by the
        /// caller's commit — when called inside a host transaction.
        #[cfg(feature = $feature)]
        pub(crate) mod $queries {
            use super::*;
            #[allow(unused_imports)]
            use sqlx::Connection as _;

            /// The raw connection type this backend's queries run against.
            pub(crate) type Conn = <$backend as sqlx::Database>::Connection;

            #[allow(deprecated)] // `require_pkce` (authkestra#273) — still round-tripped for wire/storage compatibility
            pub(crate) async fn find_client(
                conn: &mut Conn,
                client_id: &str,
            ) -> Result<Option<ClientRegistration>, authkestra_engine::store::StoreError> {
            let query = format!(
                "SELECT
                    client_id,
                    client_secret_hash,
                    require_pkce,
                    redirect_uris,
                    grant_types,
                    scopes,
                    allowed_audiences,
                    token_endpoint_auth_method,
                    jwks
                FROM {schema}oauth_clients
                WHERE client_id = {p1}",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1)
            );

            let row = sqlx::query(&query)
                .bind(client_id)
                .fetch_optional(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx find_client error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;

            if let Some(row) = row {
                use sqlx::Row;
                let client_id: String = row.try_get("client_id").unwrap_or_default();
                let client_secret_hash: Option<String> = row.try_get("client_secret_hash").unwrap_or_default();
                let require_pkce: bool = row.try_get("require_pkce").unwrap_or(true);

                // SQLite might return these as Strings (from TEXT) while Postgres might return JsonValue (from JSONB)
                // The safest way across all drivers is to deserialize from whatever String they provide, or handle types cleanly.
                // For now, we'll assume we can get it as a string or fallback. We will use `try_get` as string.
                // Since sqlx::types::Json is cross-platform, we can use that!

                let redirect_uris: sqlx::types::Json<Vec<String>> = row.try_get("redirect_uris").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
                let grant_types: sqlx::types::Json<Vec<authkestra_op::client::GrantType>> = row.try_get("grant_types").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
                let scopes: sqlx::types::Json<Vec<String>> = row.try_get("scopes").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
                let allowed_audiences: sqlx::types::Json<Vec<String>> = row.try_get("allowed_audiences").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
                // Nullable: a client registered before authkestra#287's
                // migration added these columns simply has no value in
                // them yet, same as any other pre-existing row and a
                // newly-added nullable column. That's a genuine SQL
                // NULL, which `try_get::<Option<Json<T>>, _>` already
                // reports as `Ok(None)` — distinct from a non-NULL value
                // that fails to decode, which it reports as `Err`.
                // Collapsing both cases with `.ok()` would silently turn
                // an operator-written value this enum doesn't model
                // (e.g. `client_secret_jwt`) into `None`, and
                // `authenticate_client` treats `None` as "no auth method
                // configured" — fail-open into an unauthenticated
                // client. Propagate the decode error instead.
                let token_endpoint_auth_method: Option<TokenEndpointAuthMethod> = row
                    .try_get::<Option<sqlx::types::Json<TokenEndpointAuthMethod>>, _>("token_endpoint_auth_method")
                    .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?
                    .map(|j| j.0);
                let jwks: Option<serde_json::Value> = row
                    .try_get::<Option<sqlx::types::Json<serde_json::Value>>, _>("jwks")
                    .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?
                    .map(|j| j.0);

                Ok(Some(ClientRegistration {
                    client_id,
                    client_secret_hash,
                    require_pkce,
                    redirect_uris: redirect_uris.0,
                    grant_types: grant_types.0,
                    scopes: scopes.0,
                    allowed_audiences: allowed_audiences.0,
                    token_endpoint_auth_method,
                    jwks,
                }))
            } else {
                Ok(None)
            }
            }

            pub(crate) async fn store_code(
                conn: &mut Conn,
                code: AuthorizationCode,
            ) -> Result<(), authkestra_engine::store::StoreError> {
            let query = format!(
                "INSERT INTO {schema}oauth_codes 
                (code, client_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, identity, expires_at, used) 
                VALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7}, {p8}, {p9}, {p10})",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1), p2 = $placeholder_fmt(2), p3 = $placeholder_fmt(3),
                p4 = $placeholder_fmt(4), p5 = $placeholder_fmt(5), p6 = $placeholder_fmt(6),
                p7 = $placeholder_fmt(7), p8 = $placeholder_fmt(8), p9 = $placeholder_fmt(9),
                p10 = $placeholder_fmt(10)
            );

            let identity_json = sqlx::types::Json(code.identity);

            sqlx::query(&query)
                .bind(code.code)
                .bind(code.client_id)
                .bind(code.redirect_uri)
                .bind(code.scope)
                .bind(code.code_challenge)
                .bind(code.code_challenge_method)
                .bind(code.nonce)
                .bind(identity_json)
                .bind(code.expires_at)
                .bind(code.used)
                .execute(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx store_code error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;
            Ok(())
            }

            pub(crate) async fn store_token(
                conn: &mut Conn,
                token: RefreshToken,
            ) -> Result<(), authkestra_engine::store::StoreError> {
            let query = format!(
                "INSERT INTO {schema}oauth_refresh_tokens
                (token, client_id, identity, scope, expires_at, jkt)
                VALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6})",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1), p2 = $placeholder_fmt(2), p3 = $placeholder_fmt(3),
                p4 = $placeholder_fmt(4), p5 = $placeholder_fmt(5), p6 = $placeholder_fmt(6)
            );

            let identity_json = sqlx::types::Json(token.identity);

            sqlx::query(&query)
                .bind(token.token)
                .bind(token.client_id)
                .bind(identity_json)
                .bind(token.scope)
                .bind(token.expires_at)
                .bind(token.jkt)
                .execute(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx store_token error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;
            Ok(())
            }

            pub(crate) async fn get_token(
                conn: &mut Conn,
                token: &str,
            ) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
            let query = format!(
                "SELECT token, client_id, identity, scope, expires_at, jkt
                FROM {schema}oauth_refresh_tokens
                WHERE token = {p1} AND revoked_at IS NULL AND expires_at > {p2}",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1),
                p2 = $placeholder_fmt(2)
            );

            let row = sqlx::query(&query)
                .bind(token)
                .bind(chrono::Utc::now())
                .fetch_optional(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx get_token error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;

            if let Some(row) = row {
                use sqlx::Row;
                let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

                // NULL (a pre-authkestra#287 row, or a token never bound
                // to a DPoP proof) is a legitimate `None`; a decode error
                // on a non-NULL value is propagated rather than silently
                // discarded, since that would undo the RFC 9449 §5
                // continuity check this column exists to enforce.
                Ok(Some(RefreshToken::new(
                    row.try_get("token").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("client_id").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    identity.0,
                    row.try_get("scope").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("jkt").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                )))
            } else {
                Ok(None)
            }
            }

            pub(crate) async fn revoke_token(
                conn: &mut Conn,
                token: &str,
            ) -> Result<(), authkestra_engine::store::StoreError> {
            let query = format!(
                "UPDATE {schema}oauth_refresh_tokens SET revoked_at = {p1} WHERE token = {p2}",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1),
                p2 = $placeholder_fmt(2)
            );

            sqlx::query(&query)
                .bind(chrono::Utc::now())
                .bind(token)
                .execute(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx revoke_token error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;
            Ok(())
            }

            pub(crate) async fn store_device_code(
                conn: &mut Conn,
                session: DeviceCodeSession,
            ) -> Result<(), authkestra_engine::store::StoreError> {
            let query = format!(
                "INSERT INTO {schema}oauth_device_codes 
                (device_code, user_code, client_id, scope, expires_at, status, last_polled_at) 
                VALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7})",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1), p2 = $placeholder_fmt(2), p3 = $placeholder_fmt(3),
                p4 = $placeholder_fmt(4), p5 = $placeholder_fmt(5), p6 = $placeholder_fmt(6),
                p7 = $placeholder_fmt(7)
            );

            let status_json = sqlx::types::Json(session.status);

            sqlx::query(&query)
                .bind(session.device_code)
                .bind(session.user_code)
                .bind(session.client_id)
                .bind(session.scope)
                .bind(session.expires_at)
                .bind(status_json)
                .bind(session.last_polled_at)
                .execute(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx store_device_code error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;
            Ok(())
            }

            pub(crate) async fn get_device_code(
                conn: &mut Conn,
                device_code: &str,
            ) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
            let query = format!(
                "SELECT device_code, user_code, client_id, scope, expires_at, status, last_polled_at 
                FROM {schema}oauth_device_codes 
                WHERE device_code = {p1}",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1)
            );

            let row = sqlx::query(&query)
                .bind(device_code)
                .fetch_optional(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx get_device_code error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;

            if let Some(row) = row {
                use sqlx::Row;
                let status: sqlx::types::Json<authkestra_op::device::DeviceCodeStatus> = row.try_get("status").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

                Ok(Some({
                    let mut session = DeviceCodeSession::new(
                    row.try_get("device_code").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("user_code").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("client_id").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("scope").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    status.0,
                );
                    session.last_polled_at = row.try_get("last_polled_at").ok();
                    session
                }))
            } else {
                Ok(None)
            }
            }

            pub(crate) async fn get_by_user_code(
                conn: &mut Conn,
                user_code: &str,
            ) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
            let query = format!(
                "SELECT device_code, user_code, client_id, scope, expires_at, status, last_polled_at 
                FROM {schema}oauth_device_codes 
                WHERE user_code = {p1}",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1)
            );

            let row = sqlx::query(&query)
                .bind(user_code)
                .fetch_optional(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx get_by_user_code error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;

            if let Some(row) = row {
                use sqlx::Row;
                let status: sqlx::types::Json<authkestra_op::device::DeviceCodeStatus> = row.try_get("status").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

                Ok(Some({
                    let mut session = DeviceCodeSession::new(
                    row.try_get("device_code").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("user_code").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("client_id").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("scope").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                    status.0,
                );
                    session.last_polled_at = row.try_get("last_polled_at").ok();
                    session
                }))
            } else {
                Ok(None)
            }
            }

            pub(crate) async fn update_device_code(
                conn: &mut Conn,
                session: DeviceCodeSession,
            ) -> Result<(), authkestra_engine::store::StoreError> {
            let existing = get_device_code(conn, &session.device_code).await?;
            match existing {
                Some(e) if matches!(e.status, authkestra_op::device::DeviceCodeStatus::Pending) => {}
                _ => {
                    tracing::warn!("sqlx update_device_code rejected: session missing or not in Pending state");
                    return Err(authkestra_engine::store::StoreError::NotFound);
                }
            }

            let query = format!(
                "UPDATE {schema}oauth_device_codes 
                SET status = {p1}, last_polled_at = {p2} 
                WHERE device_code = {p3} AND status = {p4}",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1), p2 = $placeholder_fmt(2), p3 = $placeholder_fmt(3), p4 = $placeholder_fmt(4)
            );

            let status_json = sqlx::types::Json(session.status);
            let pending_json = sqlx::types::Json(authkestra_op::device::DeviceCodeStatus::Pending);

            let res = sqlx::query(&query)
                .bind(status_json)
                .bind(session.last_polled_at)
                .bind(session.device_code)
                .bind(pending_json)
                .execute(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx update_device_code error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;

            if res.rows_affected() != 1 {
                tracing::warn!("sqlx update_device_code affected 0 rows (record missing or modified)");
                return Err(authkestra_engine::store::StoreError::NotFound);
            }
            Ok(())
            }

            pub(crate) async fn delete_device_code(
                conn: &mut Conn,
                device_code: &str,
            ) -> Result<(), authkestra_engine::store::StoreError> {
            let query = format!(
                "DELETE FROM {schema}oauth_device_codes WHERE device_code = {p1}",
                schema = $schema_prefix,
                p1 = $placeholder_fmt(1)
            );

            sqlx::query(&query)
                .bind(device_code)
                .execute(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "sqlx delete_device_code error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;
            Ok(())
            }

            $consume_code_fn

            $consume_token_fn

            $consume_device_fn

            $dpop_jti_fn
        }

        #[cfg(feature = $feature)]
        impl SqlxOpStore<$backend> {
            /// Create a new SqlxOpStore from a sqlx connection pool.
            pub fn new(pool: sqlx::Pool<$backend>) -> Self {
                Self { pool }
            }

            $migrate_impl

            /// Begin a transaction and return a store scoped to it.
            ///
            /// The concrete counterpart to
            /// [`TransactionalOpStore::begin`](authkestra_op::store::TransactionalOpStore::begin):
            /// it returns [`SqlxOpStoreTx`] rather than a trait object, which is
            /// what a host application needs — `SqlxOpStoreTx`'s `AsMut` impl hands
            /// back the live `sqlx` connection so the application's own
            /// statements run in the same transaction as the store's.
            pub async fn begin_tx(&self) -> Result<SqlxOpStoreTx<$backend>, authkestra_engine::store::StoreError> {
                let tx = self.pool.begin().await.map_err(|e| {
                    tracing::error!(error = %e, "sqlx begin transaction error");
                    authkestra_engine::store::StoreError::Internal(format!("db error: {e}"))
                })?;
                Ok(SqlxOpStoreTx { tx })
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl authkestra_op::store::TransactionalOpStore for SqlxOpStore<$backend> {
            async fn begin(
                &self,
            ) -> Result<Box<dyn authkestra_op::store::OpStoreTransaction + Send>, authkestra_engine::store::StoreError> {
                Ok(Box::new(self.begin_tx().await?))
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl authkestra_op::store::OpStoreTransaction for SqlxOpStoreTx<$backend> {
            async fn commit(self: Box<Self>) -> Result<(), authkestra_engine::store::StoreError> {
                SqlxOpStoreTx::commit(*self).await
            }

            async fn rollback(self: Box<Self>) -> Result<(), authkestra_engine::store::StoreError> {
                SqlxOpStoreTx::rollback(*self).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl authkestra_op::store::OpStore for SqlxOpStore<$backend> {
            async fn check_and_record_dpop_jti(&mut self, jti: &str, expires_at: chrono::DateTime<chrono::Utc>) -> Result<bool, authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::check_and_record_dpop_jti(conn, jti, expires_at).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl ClientStore for SqlxOpStore<$backend> {
            async fn find_client(&mut self, client_id: &str) -> Result<Option<ClientRegistration>, authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::find_client(conn, client_id).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl AuthorizationCodeStore for SqlxOpStore<$backend> {
            async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::store_code(conn, code).await
            }
            async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::consume_code(conn, code).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl RefreshTokenStore for SqlxOpStore<$backend> {
            async fn store_token(&mut self, token: RefreshToken) -> Result<(), authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::store_token(conn, token).await
            }
            async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::get_token(conn, token).await
            }
            async fn revoke_token(&mut self, token: &str) -> Result<(), authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::revoke_token(conn, token).await
            }
            async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::consume_token(conn, token).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl DeviceCodeStore for SqlxOpStore<$backend> {
            async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::store_device_code(conn, session).await
            }
            async fn get_device_code(&mut self, device_code: &str) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::get_device_code(conn, device_code).await
            }
            async fn get_by_user_code(&mut self, user_code: &str) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::get_by_user_code(conn, user_code).await
            }
            async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::update_device_code(conn, session).await
            }
            async fn delete_device_code(&mut self, device_code: &str) -> Result<(), authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::delete_device_code(conn, device_code).await
            }
            async fn consume_device_code(&mut self, device_code: &str) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
                let mut c = self.conn().await?;
                let conn = &mut *c;
                $queries::consume_device_code(conn, device_code).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl authkestra_op::store::OpStore for SqlxOpStoreTx<$backend> {
            async fn check_and_record_dpop_jti(&mut self, jti: &str, expires_at: chrono::DateTime<chrono::Utc>) -> Result<bool, authkestra_engine::store::StoreError> {
                $queries::check_and_record_dpop_jti(&mut *self.tx, jti, expires_at).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl ClientStore for SqlxOpStoreTx<$backend> {
            async fn find_client(&mut self, client_id: &str) -> Result<Option<ClientRegistration>, authkestra_engine::store::StoreError> {
                $queries::find_client(&mut *self.tx, client_id).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl AuthorizationCodeStore for SqlxOpStoreTx<$backend> {
            async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), authkestra_engine::store::StoreError> {
                $queries::store_code(&mut *self.tx, code).await
            }
            async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError> {
                $queries::consume_code(&mut *self.tx, code).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl RefreshTokenStore for SqlxOpStoreTx<$backend> {
            async fn store_token(&mut self, token: RefreshToken) -> Result<(), authkestra_engine::store::StoreError> {
                $queries::store_token(&mut *self.tx, token).await
            }
            async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                $queries::get_token(&mut *self.tx, token).await
            }
            async fn revoke_token(&mut self, token: &str) -> Result<(), authkestra_engine::store::StoreError> {
                $queries::revoke_token(&mut *self.tx, token).await
            }
            async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
                $queries::consume_token(&mut *self.tx, token).await
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        impl DeviceCodeStore for SqlxOpStoreTx<$backend> {
            async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), authkestra_engine::store::StoreError> {
                $queries::store_device_code(&mut *self.tx, session).await
            }
            async fn get_device_code(&mut self, device_code: &str) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
                $queries::get_device_code(&mut *self.tx, device_code).await
            }
            async fn get_by_user_code(&mut self, user_code: &str) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
                $queries::get_by_user_code(&mut *self.tx, user_code).await
            }
            async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), authkestra_engine::store::StoreError> {
                $queries::update_device_code(&mut *self.tx, session).await
            }
            async fn delete_device_code(&mut self, device_code: &str) -> Result<(), authkestra_engine::store::StoreError> {
                $queries::delete_device_code(&mut *self.tx, device_code).await
            }
            async fn consume_device_code(&mut self, device_code: &str) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
                $queries::consume_device_code(&mut *self.tx, device_code).await
            }
        }

    };
}

// Generate the Postgres implementation
impl_opstore_sql! {
    sqlx::Postgres,
    "postgres",
    pg_queries,
    |i| format!("${}", i),
    "authkestra.",
    /// Run necessary database migrations to set up schema and tables.
    ///
    /// Deliberately **not** `sqlx::migrate!` (tried in authkestra#287,
    /// reverted): its bookkeeping lives in one database-global
    /// `_sqlx_migrations` table with no supported way in sqlx 0.8 to
    /// rename or namespace it. `authkestra-op` is a library embedded into
    /// a host application's own connection pool — a host that also runs
    /// `sqlx::migrate!` for its own schema against that same pool (the
    /// common case) collides on that shared table the moment either side's
    /// migration lands on a version number the other already used, and
    /// `Migrator::run` then refuses to apply *either* set of migrations.
    /// The old `CREATE TABLE IF NOT EXISTS`-only approach never had this
    /// failure mode, because it kept no bookkeeping of its own at all —
    /// this keeps that property while still being able to *add* a column
    /// to an existing deployment's table. Postgres supports `ADD COLUMN IF
    /// NOT EXISTS` directly (9.6+), so no introspection query is needed
    /// here the way SQLite and MySQL's `migrate()` need one.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        use sqlx::Executor;
        self.pool.execute(
            r#"
            CREATE SCHEMA IF NOT EXISTS authkestra;

            CREATE TABLE IF NOT EXISTS authkestra.oauth_clients (
                client_id VARCHAR(255) PRIMARY KEY,
                client_secret_hash VARCHAR(255),
                require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
                redirect_uris JSONB NOT NULL,
                grant_types JSONB NOT NULL,
                scopes JSONB NOT NULL,
                allowed_audiences JSONB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authkestra.oauth_codes (
                code VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL REFERENCES authkestra.oauth_clients(client_id) ON DELETE CASCADE,
                redirect_uri TEXT NOT NULL,
                scope TEXT NOT NULL,
                code_challenge VARCHAR(255),
                code_challenge_method VARCHAR(10),
                nonce VARCHAR(255),
                identity JSONB NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE IF NOT EXISTS authkestra.oauth_refresh_tokens (
                token VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL REFERENCES authkestra.oauth_clients(client_id) ON DELETE CASCADE,
                identity JSONB NOT NULL,
                scope TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked_at TIMESTAMPTZ
            );

            CREATE TABLE IF NOT EXISTS authkestra.oauth_device_codes (
                device_code VARCHAR(255) PRIMARY KEY,
                user_code VARCHAR(255) UNIQUE NOT NULL,
                client_id VARCHAR(255) NOT NULL REFERENCES authkestra.oauth_clients(client_id) ON DELETE CASCADE,
                scope TEXT NOT NULL,
                status JSONB NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                last_polled_at TIMESTAMPTZ
            );
            -- authkestra#291: RFC 9449 §11.1 DPoP proof replay tracking.
            -- No foreign key to oauth_clients: a `jti` is client-generated
            -- and checked before the grant is dispatched, so it is not
            -- owned by a client row and must not be cascade-deleted with
            -- one.
            CREATE TABLE IF NOT EXISTS authkestra.oauth_dpop_jti (
                jti VARCHAR(255) PRIMARY KEY,
                expires_at TIMESTAMPTZ NOT NULL
            );
            "#
        ).await?;

        // authkestra#287: additive columns for RFC 9449 DPoP refresh-token
        // key continuity and RFC 7523 private_key_jwt. Safe to run on every
        // startup, against both a fresh install (just created above) and an
        // existing deployment upgrading from before these columns existed —
        // and catalog-guarded so the steady-state startup takes no ACCESS
        // EXCLUSIVE lock on either table. See `ensure_postgres_column`.
        ensure_postgres_column(&self.pool, "oauth_refresh_tokens", "jkt", "jkt VARCHAR(255)").await?;
        ensure_postgres_column(&self.pool, "oauth_clients", "token_endpoint_auth_method", "token_endpoint_auth_method JSONB").await?;
        ensure_postgres_column(&self.pool, "oauth_clients", "jwks", "jwks JSONB").await?;

        Ok(())
    },
    // consume_code (Postgres specific)
    pub(crate) async fn consume_code(conn: &mut Conn, code: &str) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError> {
        let query = "UPDATE authkestra.oauth_codes SET used = TRUE WHERE code = $1 AND used = FALSE RETURNING *";
        let row = sqlx::query(query)
            .bind(code)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if let Some(row) = row {
            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(Some({
                let mut code = AuthorizationCode::new(
                row.try_get("code").unwrap_or_default(),
                row.try_get("client_id").unwrap_or_default(),
                row.try_get("redirect_uri").unwrap_or_default(),
                row.try_get("scope").unwrap_or_default(),
                identity.0,
                row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                row.try_get("used").unwrap_or(true),
            );
                code.code_challenge = row.try_get("code_challenge").ok();
                code.code_challenge_method = row.try_get("code_challenge_method").ok();
                code.nonce = row.try_get("nonce").ok();
                code
            }))
        } else {
            Ok(None)
        }
    },
    // consume_token (Postgres specific)
    pub(crate) async fn consume_token(conn: &mut Conn, token: &str) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
        let query = "DELETE FROM authkestra.oauth_refresh_tokens WHERE token = $1 AND revoked_at IS NULL RETURNING *";
        let row = sqlx::query(query)
            .bind(token)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if let Some(row) = row {
            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(Some(RefreshToken::new(
                row.try_get("token").unwrap_or_default(),
                row.try_get("client_id").unwrap_or_default(),
                identity.0,
                row.try_get("scope").unwrap_or_default(),
                row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                row.try_get("jkt").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
            )))
        } else {
            Ok(None)
        }
    },
    // consume_device_impl (Postgres specific)
    pub(crate) async fn consume_device_code(conn: &mut Conn, device_code: &str) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
        let query = "DELETE FROM authkestra.oauth_device_codes WHERE device_code = $1 RETURNING *";
        let row = sqlx::query(query)
            .bind(device_code)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if let Some(row) = row {
            use sqlx::Row;
            let status: sqlx::types::Json<authkestra_op::device::DeviceCodeStatus> = row.try_get("status").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(Some({
                let mut session = DeviceCodeSession::new(
                row.try_get("device_code").unwrap_or_default(),
                row.try_get("user_code").unwrap_or_default(),
                row.try_get("client_id").unwrap_or_default(),
                row.try_get("scope").unwrap_or_default(),
                row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                status.0,
            );
                session.last_polled_at = row.try_get("last_polled_at").ok();
                session
            }))
        } else {
            Ok(None)
        }
    },
    /// Atomically claim a DPoP proof's `jti` (RFC 9449 §11.1).
    ///
    /// Without this override `SqlxOpStore` inherited `OpStore`'s
    /// fail-closed default, which refuses *every* proof — so a
    /// SqlxOpStore-backed OP returned `invalid_dpop_proof` for every
    /// DPoP request, and the `jkt` column authkestra#287 added to
    /// `oauth_refresh_tokens` was unreachable through the token endpoint.
    ///
    /// A single statement, not `SELECT`-then-`INSERT`: the TOCTOU window in
    /// a two-call check is exactly the replay this exists to prevent, since
    /// two concurrent presentations of one captured proof would both
    /// observe "not yet seen".
    ///
    /// An already-expired row is *reclaimable*: a `jti` past its window can
    /// no longer be usefully replayed, because `verify_dpop_proof` fails it
    /// on freshness first.
    pub(crate) async fn check_and_record_dpop_jti(
        conn: &mut Conn,
        jti: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        // The qualified `oauth_dpop_jti.expires_at` in the WHERE clause
        // reads the *pre-update* row, so this claims the `jti` only when it
        // is absent (the INSERT wins) or already expired.
        let res = sqlx::query(
            "INSERT INTO authkestra.oauth_dpop_jti (jti, expires_at) VALUES ($1, $2) \
             ON CONFLICT (jti) DO UPDATE SET expires_at = $2 \
             WHERE oauth_dpop_jti.expires_at <= $3",
        )
        .bind(jti)
        .bind(expires_at)
        .bind(chrono::Utc::now())
        .execute(&mut *conn)
        .await
        .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        Ok(res.rows_affected() > 0)
    }
}

// Generate the SQLite implementation
impl_opstore_sql! {
    sqlx::Sqlite,
    "sqlite",
    sqlite_queries,
    |_| "?".to_string(),
    "authkestra_",
    /// Run necessary database migrations to set up schema and tables.
    ///
    /// See the Postgres impl's identical doc comment for why this is
    /// deliberately not `sqlx::migrate!`. SQLite has no native `ADD COLUMN
    /// IF NOT EXISTS`, so the three new columns go through
    /// `ensure_sqlite_column`'s `pragma_table_info` introspection instead.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        use sqlx::Executor;
        self.pool.execute(
            r#"
            CREATE TABLE IF NOT EXISTS authkestra_oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_secret_hash TEXT,
                require_pkce BOOLEAN NOT NULL DEFAULT 1,
                redirect_uris TEXT NOT NULL,
                grant_types TEXT NOT NULL,
                scopes TEXT NOT NULL,
                allowed_audiences TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authkestra_oauth_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE,
                redirect_uri TEXT NOT NULL,
                scope TEXT NOT NULL,
                code_challenge TEXT,
                code_challenge_method TEXT,
                nonce TEXT,
                identity TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS authkestra_oauth_refresh_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE,
                identity TEXT NOT NULL,
                scope TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked_at DATETIME
            );

            CREATE TABLE IF NOT EXISTS authkestra_oauth_device_codes (
                device_code TEXT PRIMARY KEY,
                user_code TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE,
                scope TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                last_polled_at DATETIME
            );

            -- authkestra#291: RFC 9449 §11.1 DPoP proof replay tracking.
            -- See the Postgres migration for why there is no client_id FK.
            CREATE TABLE IF NOT EXISTS authkestra_oauth_dpop_jti (
                jti TEXT PRIMARY KEY,
                expires_at DATETIME NOT NULL
            );
            "#
        ).await?;

        // authkestra#287: additive columns for RFC 9449 DPoP refresh-token
        // key continuity and RFC 7523 private_key_jwt. Safe to run on every
        // startup, against both a fresh install (just created above) and an
        // existing deployment upgrading from before these columns existed.
        ensure_sqlite_column(&self.pool, "authkestra_oauth_refresh_tokens", "jkt", "jkt TEXT").await?;
        ensure_sqlite_column(&self.pool, "authkestra_oauth_clients", "token_endpoint_auth_method", "token_endpoint_auth_method TEXT").await?;
        ensure_sqlite_column(&self.pool, "authkestra_oauth_clients", "jwks", "jwks TEXT").await?;

        Ok(())
    },
    // consume_code (SQLite specific)
    pub(crate) async fn consume_code(conn: &mut Conn, code: &str) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError> {
        let query = "UPDATE authkestra_oauth_codes SET used = TRUE WHERE code = ? AND used = FALSE RETURNING *";
        let row = sqlx::query(query)
            .bind(code)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if let Some(row) = row {
            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(Some({
                let mut code = AuthorizationCode::new(
                row.try_get("code").unwrap_or_default(),
                row.try_get("client_id").unwrap_or_default(),
                row.try_get("redirect_uri").unwrap_or_default(),
                row.try_get("scope").unwrap_or_default(),
                identity.0,
                row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                row.try_get("used").unwrap_or(true),
            );
                code.code_challenge = row.try_get("code_challenge").ok();
                code.code_challenge_method = row.try_get("code_challenge_method").ok();
                code.nonce = row.try_get("nonce").ok();
                code
            }))
        } else {
            Ok(None)
        }
    },
    // consume_token (SQLite specific)
    pub(crate) async fn consume_token(conn: &mut Conn, token: &str) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
        let query = "DELETE FROM authkestra_oauth_refresh_tokens WHERE token = ? AND revoked_at IS NULL RETURNING *";
        let row = sqlx::query(query)
            .bind(token)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if let Some(row) = row {
            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(Some(RefreshToken::new(
                row.try_get("token").unwrap_or_default(),
                row.try_get("client_id").unwrap_or_default(),
                identity.0,
                row.try_get("scope").unwrap_or_default(),
                row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                row.try_get("jkt").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
            )))
        } else {
            Ok(None)
        }
    },
    // consume_device_impl (SQLite specific)
    pub(crate) async fn consume_device_code(conn: &mut Conn, device_code: &str) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
        let query = "DELETE FROM authkestra_oauth_device_codes WHERE device_code = ? RETURNING *";
        let row = sqlx::query(query)
            .bind(device_code)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if let Some(row) = row {
            use sqlx::Row;
            let status: sqlx::types::Json<authkestra_op::device::DeviceCodeStatus> = row.try_get("status").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(Some({
                let mut session = DeviceCodeSession::new(
                row.try_get("device_code").unwrap_or_default(),
                row.try_get("user_code").unwrap_or_default(),
                row.try_get("client_id").unwrap_or_default(),
                row.try_get("scope").unwrap_or_default(),
                row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                status.0,
            );
                session.last_polled_at = row.try_get("last_polled_at").ok();
                session
            }))
        } else {
            Ok(None)
        }
    },
    /// Atomically claim a DPoP proof's `jti` (RFC 9449 §11.1).
    ///
    /// Without this override `SqlxOpStore` inherited `OpStore`'s
    /// fail-closed default, which refuses *every* proof — so a
    /// SqlxOpStore-backed OP returned `invalid_dpop_proof` for every
    /// DPoP request, and the `jkt` column authkestra#287 added to
    /// `oauth_refresh_tokens` was unreachable through the token endpoint.
    ///
    /// A single statement, not `SELECT`-then-`INSERT`: the TOCTOU window in
    /// a two-call check is exactly the replay this exists to prevent, since
    /// two concurrent presentations of one captured proof would both
    /// observe "not yet seen".
    ///
    /// An already-expired row is *reclaimable*: a `jti` past its window can
    /// no longer be usefully replayed, because `verify_dpop_proof` fails it
    /// on freshness first.
    pub(crate) async fn check_and_record_dpop_jti(
        conn: &mut Conn,
        jti: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        // See the Postgres implementation; SQLite's upsert has the same
        // pre-update read semantics for the qualified column.
        let res = sqlx::query(
            "INSERT INTO authkestra_oauth_dpop_jti (jti, expires_at) VALUES (?1, ?2) \
             ON CONFLICT (jti) DO UPDATE SET expires_at = ?2 \
             WHERE authkestra_oauth_dpop_jti.expires_at <= ?3",
        )
        .bind(jti)
        .bind(expires_at)
        .bind(chrono::Utc::now())
        .execute(&mut *conn)
        .await
        .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        Ok(res.rows_affected() > 0)
    }
}

// Generate the MySQL implementation
impl_opstore_sql! {
    sqlx::MySql,
    "mysql",
    mysql_queries,
    |_| "?".to_string(),
    "authkestra_",
    /// Run necessary database migrations to set up schema and tables.
    ///
    /// See the Postgres impl's identical doc comment for why this is
    /// deliberately not `sqlx::migrate!`. MySQL has no `ADD COLUMN IF NOT
    /// EXISTS` across commonly-deployed versions, so the three new columns
    /// go through `ensure_mysql_column`'s `information_schema`
    /// introspection instead.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        use sqlx::Executor;
        self.pool.execute(
            r#"
            CREATE TABLE IF NOT EXISTS authkestra_oauth_clients (
                client_id VARCHAR(255) PRIMARY KEY,
                client_secret_hash VARCHAR(255),
                require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
                redirect_uris JSON NOT NULL,
                grant_types JSON NOT NULL,
                scopes JSON NOT NULL,
                allowed_audiences JSON NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authkestra_oauth_codes (
                code VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT NOT NULL,
                code_challenge VARCHAR(255),
                code_challenge_method VARCHAR(10),
                nonce VARCHAR(255),
                identity JSON NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN NOT NULL DEFAULT FALSE,
                FOREIGN KEY (client_id) REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS authkestra_oauth_refresh_tokens (
                token VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL,
                identity JSON NOT NULL,
                scope TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked_at DATETIME,
                FOREIGN KEY (client_id) REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS authkestra_oauth_device_codes (
                device_code VARCHAR(255) PRIMARY KEY,
                user_code VARCHAR(255) UNIQUE NOT NULL,
                client_id VARCHAR(255) NOT NULL,
                scope TEXT NOT NULL,
                status JSON NOT NULL,
                expires_at DATETIME NOT NULL,
                last_polled_at DATETIME,
                FOREIGN KEY (client_id) REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE
            );

            -- authkestra#291: RFC 9449 §11.1 DPoP proof replay tracking.
            -- See the Postgres migration for why there is no client_id FK.
            -- DATETIME(3) rather than DATETIME: MySQL rounds a DATETIME to
            -- whole seconds, which would let a `jti` stay blocked up to ~1s
            -- past its window and, worse, make the expired-row reclaim
            -- below compare against a rounded value.
            CREATE TABLE IF NOT EXISTS authkestra_oauth_dpop_jti (
                jti VARCHAR(255) PRIMARY KEY,
                expires_at DATETIME(3) NOT NULL
            );
            "#
        ).await?;

        // authkestra#287: additive columns for RFC 9449 DPoP refresh-token
        // key continuity and RFC 7523 private_key_jwt. Safe to run on every
        // startup, against both a fresh install (just created above) and an
        // existing deployment upgrading from before these columns existed.
        ensure_mysql_column(&self.pool, "authkestra_oauth_refresh_tokens", "jkt", "jkt VARCHAR(255)").await?;
        ensure_mysql_column(&self.pool, "authkestra_oauth_clients", "token_endpoint_auth_method", "token_endpoint_auth_method JSON").await?;
        ensure_mysql_column(&self.pool, "authkestra_oauth_clients", "jwks", "jwks JSON").await?;

        Ok(())
    },
    // consume_code (MySQL specific - needs transaction and FOR UPDATE since no RETURNING)
    pub(crate) async fn consume_code(conn: &mut Conn, code: &str) -> Result<Option<AuthorizationCode>, authkestra_engine::store::StoreError> {
        let mut tx = conn.begin().await.map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        let select_query = "SELECT * FROM authkestra_oauth_codes WHERE code = ? AND used = FALSE FOR UPDATE";
        let row = sqlx::query(select_query)
            .bind(code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if let Some(row) = row {
            let update_query = "UPDATE authkestra_oauth_codes SET used = TRUE WHERE code = ?";
            sqlx::query(update_query)
                .bind(code)
                .execute(&mut *tx)
                .await
                .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

            tx.commit().await.map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(Some({
                let mut code = AuthorizationCode::new(
                row.try_get("code").unwrap_or_default(),
                row.try_get("client_id").unwrap_or_default(),
                row.try_get("redirect_uri").unwrap_or_default(),
                row.try_get("scope").unwrap_or_default(),
                identity.0,
                row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                row.try_get("used").unwrap_or(true),
            );
                code.code_challenge = row.try_get("code_challenge").ok();
                code.code_challenge_method = row.try_get("code_challenge_method").ok();
                code.nonce = row.try_get("nonce").ok();
                code
            }))
        } else {
            tx.rollback().await.map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(None)
        }
    },
    // consume_token (MySQL specific)
    pub(crate) async fn consume_token(conn: &mut Conn, token: &str) -> Result<Option<RefreshToken>, authkestra_engine::store::StoreError> {
        let mut tx = conn.begin().await.map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        let select_query = "SELECT * FROM authkestra_oauth_refresh_tokens WHERE token = ? AND revoked_at IS NULL FOR UPDATE";
        let row = sqlx::query(select_query)
            .bind(token)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if let Some(row) = row {
            let delete_query = "DELETE FROM authkestra_oauth_refresh_tokens WHERE token = ?";
            sqlx::query(delete_query)
                .bind(token)
                .execute(&mut *tx)
                .await
                .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

            tx.commit().await.map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

            use sqlx::Row;
            let identity: sqlx::types::Json<authkestra_engine::auth::state::Identity> = row.try_get("identity").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(Some(RefreshToken::new(
                row.try_get("token").unwrap_or_default(),
                row.try_get("client_id").unwrap_or_default(),
                identity.0,
                row.try_get("scope").unwrap_or_default(),
                row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                row.try_get("jkt").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
            )))
        } else {
            tx.rollback().await.map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(None)
        }
    },
    // consume_device_impl (MySQL specific)
    pub(crate) async fn consume_device_code(conn: &mut Conn, device_code: &str) -> Result<Option<DeviceCodeSession>, authkestra_engine::store::StoreError> {
        let mut tx = conn.begin().await.map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        let select_query = "SELECT * FROM authkestra_oauth_device_codes WHERE device_code = ? FOR UPDATE";
        let row = sqlx::query(select_query)
            .bind(device_code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if let Some(row) = row {
            let delete_query = "DELETE FROM authkestra_oauth_device_codes WHERE device_code = ?";
            sqlx::query(delete_query)
                .bind(device_code)
                .execute(&mut *tx)
                .await
                .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

            tx.commit().await.map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

            use sqlx::Row;
            let status: sqlx::types::Json<authkestra_op::device::DeviceCodeStatus> = row.try_get("status").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(Some({
                let mut session = DeviceCodeSession::new(
                row.try_get("device_code").unwrap_or_default(),
                row.try_get("user_code").unwrap_or_default(),
                row.try_get("client_id").unwrap_or_default(),
                row.try_get("scope").unwrap_or_default(),
                row.try_get("expires_at").map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?,
                status.0,
            );
                session.last_polled_at = row.try_get("last_polled_at").ok();
                session
            }))
        } else {
            tx.rollback().await.map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;
            Ok(None)
        }
    },
    /// Atomically claim a DPoP proof's `jti` (RFC 9449 §11.1).
    ///
    /// Without this override `SqlxOpStore` inherited `OpStore`'s
    /// fail-closed default, which refuses *every* proof — so a
    /// SqlxOpStore-backed OP returned `invalid_dpop_proof` for every
    /// DPoP request, and the `jkt` column authkestra#287 added to
    /// `oauth_refresh_tokens` was unreachable through the token endpoint.
    ///
    /// A single statement, not `SELECT`-then-`INSERT`: the TOCTOU window in
    /// a two-call check is exactly the replay this exists to prevent, since
    /// two concurrent presentations of one captured proof would both
    /// observe "not yet seen".
    ///
    /// An already-expired row is *reclaimable*: a `jti` past its window can
    /// no longer be usefully replayed, because `verify_dpop_proof` fails it
    /// on freshness first.
    ///
    /// Two statements rather than one, and deliberately **not** wrapped in a
    /// transaction with `SELECT ... FOR UPDATE`: on a row that does not yet
    /// exist that pattern takes a gap lock, and two concurrent claims of the
    /// same `jti` then deadlock under MySQL's default REPEATABLE READ
    /// (authkestra#277 hit exactly this). Each statement below is
    /// individually atomic, so no transaction is needed.
    pub(crate) async fn check_and_record_dpop_jti(
        conn: &mut Conn,
        jti: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        let inserted = sqlx::query(
            "INSERT IGNORE INTO authkestra_oauth_dpop_jti (jti, expires_at) VALUES (?, ?)",
        )
        .bind(jti)
        .bind(expires_at)
        .execute(&mut *conn)
        .await
        .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        if inserted.rows_affected() == 1 {
            return Ok(true);
        }

        // The `jti` is present. Reclaim it only if its window has passed.
        // `rows_affected` counts *changed* rows on MySQL (sqlx does not set
        // CLIENT_FOUND_ROWS), which is safe here only because the new
        // `expires_at` is always later than the expired one it replaces —
        // so a matching row always changes.
        let reclaimed = sqlx::query(
            "UPDATE authkestra_oauth_dpop_jti SET expires_at = ? \
             WHERE jti = ? AND expires_at <= ?",
        )
        .bind(expires_at)
        .bind(jti)
        .bind(chrono::Utc::now())
        .execute(&mut *conn)
        .await
        .map_err(|e| authkestra_engine::store::StoreError::Internal(format!("db error: {e}")))?;

        Ok(reclaimed.rows_affected() > 0)
    }
}

#[cfg(all(test, feature = "postgres"))]
mod postgres_tests {
    use super::*;
    use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
    use chrono::{Duration, Utc};
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    async fn setup_db() -> (SqlxOpStore<sqlx::Postgres>, ContainerAsync<Postgres>) {
        let container = Postgres::default()
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_DB", "postgres")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();

        let store = SqlxOpStore::<sqlx::Postgres>::new(pool);
        store.migrate().await.unwrap();

        (store, container)
    }

    #[tokio::test]
    async fn test_postgres_authorization_code_cascading_delete() {
        let (mut store, _c) = setup_db().await;

        // Manually insert a client
        sqlx::query(
            "INSERT INTO authkestra.oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind("test_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode::new(
            "test_code_123".to_string(),
            "test_client".to_string(),
            "http://localhost/cb".to_string(),
            "openid".to_string(),
            authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            Utc::now() + Duration::try_minutes(10).unwrap(),
            false,
        );

        store.store_code(code.clone()).await.unwrap();

        // Consume it to verify it exists
        let consumed = store.consume_code("test_code_123").await.unwrap();
        assert!(consumed.is_some());
        assert_eq!(consumed.unwrap().client_id, "test_client");

        // Test cascade delete
        // Re-insert the code
        let mut code2 = code;
        code2.code = "test_code_456".to_string();
        store.store_code(code2.clone()).await.unwrap();

        // Delete the client
        sqlx::query("DELETE FROM authkestra.oauth_clients WHERE client_id = 'test_client'")
            .execute(&store.pool)
            .await
            .unwrap();

        // Ensure the code is also deleted due to CASCADE
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM authkestra.oauth_codes WHERE code = 'test_code_456'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();

        assert_eq!(count.0, 0);
    }

    #[tokio::test]
    async fn test_postgres_concurrency() {
        let (mut store, _c) = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra.oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind("concurrency_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode::new(
            "concurrent_code".to_string(),
            "concurrency_client".to_string(),
            "http://localhost/cb".to_string(),
            "openid".to_string(),
            authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            Utc::now() + Duration::try_minutes(10).unwrap(),
            false,
        );
        store.store_code(code.clone()).await.unwrap();

        let mut handles = vec![];
        let store_arc = store.clone();

        // Spawn 10 simultaneous consumers
        for _ in 0..10 {
            let mut s = store_arc.clone();
            handles.push(tokio::spawn(async move {
                s.consume_code("concurrent_code").await.unwrap()
            }));
        }

        let mut successes = 0;
        let mut failures = 0;
        for h in handles {
            let res = h.await.unwrap();
            if res.is_some() {
                successes += 1;
            } else {
                failures += 1;
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(failures, 9);
    }

    fn test_identity() -> authkestra_engine::auth::state::Identity {
        authkestra_engine::auth::state::Identity {
            provider_id: "local".to_string(),
            external_id: "user_1".to_string(),
            email: None,
            username: None,
            attributes: std::collections::HashMap::new(),
        }
    }

    /// authkestra#287: `jkt` (RFC 9449 DPoP refresh-token continuity) and
    /// `token_endpoint_auth_method`/`jwks` (RFC 7523 private_key_jwt) must
    /// actually round-trip through a fresh install, not just exist as
    /// columns nothing reads or writes.
    #[tokio::test]
    async fn test_postgres_fresh_install_persists_jkt_and_client_auth_fields() {
        let (mut store, _c) = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra.oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences, token_endpoint_auth_method, jwks)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind("auth287_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .bind(sqlx::types::Json(TokenEndpointAuthMethod::PrivateKeyJwt))
        .bind(sqlx::types::Json(serde_json::json!({"keys": []})))
        .execute(&store.pool)
        .await
        .unwrap();

        let client = store
            .find_client("auth287_client")
            .await
            .unwrap()
            .expect("client must be found");
        assert_eq!(
            client.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::PrivateKeyJwt)
        );
        assert_eq!(client.jwks, Some(serde_json::json!({"keys": []})));

        let rt = RefreshToken::new(
            "rt-287".to_string(),
            "auth287_client".to_string(),
            test_identity(),
            "openid".to_string(),
            Utc::now() + Duration::try_days(1).unwrap(),
            Some("expected-jkt-thumbprint".to_string()),
        );
        store.store_token(rt).await.unwrap();

        let fetched = store
            .get_token("rt-287")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("expected-jkt-thumbprint".to_string()));

        let consumed = store
            .consume_token("rt-287")
            .await
            .unwrap()
            .expect("token must be consumable");
        assert_eq!(consumed.jkt, Some("expected-jkt-thumbprint".to_string()));
    }

    /// The actual point of authkestra#287: a deployment that already ran
    /// the *old* `migrate()` (before `jkt`/`token_endpoint_auth_method`/
    /// `jwks` existed) must upgrade safely when it starts running the new
    /// code — no "table already exists" failure, no data loss for
    /// pre-existing rows, and the new columns must actually work
    /// afterwards. This is the scenario `CREATE TABLE IF NOT EXISTS`
    /// alone could never handle.
    #[tokio::test]
    async fn test_postgres_migration_upgrades_a_pre_existing_deployment_without_the_new_columns() {
        let container = Postgres::default()
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_DB", "postgres")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();

        // The pre-#287 schema, created directly — bypassing
        // `store.migrate()` entirely, exactly like an existing deployment
        // that ran the old code would already have. Uses the raw simple
        // query protocol (`Executor::execute`, same as the old `migrate()`
        // this replaces used), since multiple `;`-separated statements
        // aren't accepted by `sqlx::query(...).execute(...)`'s prepared-
        // statement protocol.
        use sqlx::Executor;
        pool.execute(
            "CREATE SCHEMA IF NOT EXISTS authkestra;
             CREATE TABLE authkestra.oauth_clients (
                client_id VARCHAR(255) PRIMARY KEY,
                client_secret_hash VARCHAR(255),
                require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
                redirect_uris JSONB NOT NULL,
                grant_types JSONB NOT NULL,
                scopes JSONB NOT NULL,
                allowed_audiences JSONB NOT NULL
            );
            CREATE TABLE authkestra.oauth_refresh_tokens (
                token VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL REFERENCES authkestra.oauth_clients(client_id) ON DELETE CASCADE,
                identity JSONB NOT NULL,
                scope TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked_at TIMESTAMPTZ
            );",
        )
        .await
        .unwrap();

        // A client registered under the old schema, before this
        // deployment ever knew about these fields.
        sqlx::query(
            "INSERT INTO authkestra.oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind("pre_existing_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&pool)
        .await
        .unwrap();

        let mut store = SqlxOpStore::<sqlx::Postgres>::new(pool);

        store
            .migrate()
            .await
            .expect("migrating an existing pre-authkestra#287 database must succeed");

        let client = store
            .find_client("pre_existing_client")
            .await
            .unwrap()
            .expect("the pre-existing client must survive the migration");
        assert_eq!(client.token_endpoint_auth_method, None);
        assert_eq!(client.jwks, None);

        let rt = RefreshToken::new(
            "rt-upgrade".to_string(),
            "pre_existing_client".to_string(),
            test_identity(),
            "openid".to_string(),
            Utc::now() + Duration::try_days(1).unwrap(),
            Some("post-upgrade-jkt".to_string()),
        );
        store
            .store_token(rt)
            .await
            .expect("storing a DPoP-bound refresh token must work after the upgrade");
        let fetched = store
            .get_token("rt-upgrade")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("post-upgrade-jkt".to_string()));
    }

    /// authkestra#291: `SqlxOpStore` used to inherit the fail-closed
    /// `NoDpopReplayStore` default, refusing every DPoP proof.
    #[tokio::test]
    async fn test_postgres_dpop_jti_is_claimed_once_and_replay_is_refused() {
        use authkestra_op::store::OpStore;
        let (mut store, _c) = setup_db().await;
        let expires_at = Utc::now() + Duration::seconds(60);

        assert!(store
            .check_and_record_dpop_jti("jti-291", expires_at)
            .await
            .unwrap());
        assert!(
            !store
                .check_and_record_dpop_jti("jti-291", expires_at)
                .await
                .unwrap(),
            "replaying a still-fresh jti must be refused"
        );
    }

    #[tokio::test]
    async fn test_postgres_dpop_jti_is_reclaimable_once_expired() {
        use authkestra_op::store::OpStore;
        let (mut store, _c) = setup_db().await;

        assert!(store
            .check_and_record_dpop_jti("jti-expired", Utc::now() - Duration::seconds(5))
            .await
            .unwrap());
        assert!(
            store
                .check_and_record_dpop_jti("jti-expired", Utc::now() + Duration::seconds(60))
                .await
                .unwrap(),
            "an expired jti must be reclaimable"
        );
    }

    /// Guards both the TOCTOU window and, on MySQL, the gap-lock deadlock
    /// that a `SELECT ... FOR UPDATE` transaction would hit on a
    /// not-yet-existing row under the default REPEATABLE READ.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_postgres_dpop_jti_claim_is_atomic_under_concurrency() {
        use authkestra_op::store::OpStore;
        let (store, _c) = setup_db().await;
        let expires_at = Utc::now() + Duration::seconds(60);

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let mut store = store.clone();
            set.spawn(async move {
                store
                    .check_and_record_dpop_jti("jti-race", expires_at)
                    .await
                    .expect("a concurrent claim must not error — a deadlock here would")
            });
        }

        let mut winners = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one concurrent claim may win");
    }

    /// authkestra#290 (PR review, finding #4): `ensure_postgres_column`
    /// probes `information_schema.columns`, which spans every schema the
    /// role can see. Without the `table_schema = 'authkestra'` predicate a
    /// host application's own `public.oauth_clients` satisfies the probe
    /// and the ALTER that `authkestra.oauth_clients` still needs is
    /// skipped — silently, with the breakage surfacing later as a storage
    /// error on every `find_client`.
    ///
    /// Drop the qualifier from the probe and this test fails on
    /// `find_client`, not on `migrate()`, which is exactly what makes the
    /// unqualified version dangerous.
    #[tokio::test]
    async fn test_postgres_migration_is_not_confused_by_a_same_named_table_in_public() {
        let container = Postgres::default()
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_DB", "postgres")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();

        // The pre-#287 authkestra schema (no new columns), plus an
        // unrelated host-app table of the same name in `public` that
        // *does* already have a `jwks` column.
        use sqlx::Executor;
        pool.execute(
            "CREATE SCHEMA IF NOT EXISTS authkestra;
             CREATE TABLE authkestra.oauth_clients (
                client_id VARCHAR(255) PRIMARY KEY,
                client_secret_hash VARCHAR(255),
                require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
                redirect_uris JSONB NOT NULL,
                grant_types JSONB NOT NULL,
                scopes JSONB NOT NULL,
                allowed_audiences JSONB NOT NULL
            );
            CREATE TABLE authkestra.oauth_refresh_tokens (
                token VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL REFERENCES authkestra.oauth_clients(client_id) ON DELETE CASCADE,
                identity JSONB NOT NULL,
                scope TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked_at TIMESTAMPTZ
            );
            CREATE TABLE public.oauth_clients (
                client_id VARCHAR(255) PRIMARY KEY,
                jwks JSONB
            );",
        )
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO authkestra.oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind("shadowed_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&pool)
        .await
        .unwrap();

        let mut store = SqlxOpStore::<sqlx::Postgres>::new(pool);
        store.migrate().await.expect("migrate must succeed");

        let client = store
            .find_client("shadowed_client")
            .await
            .expect("find_client must not fail: the ALTER must have been applied to authkestra.oauth_clients, not skipped because public.oauth_clients happened to have a jwks column")
            .expect("the client must be found");
        assert_eq!(client.jwks, None);
        assert_eq!(client.token_endpoint_auth_method, None);
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_tests {
    use super::*;
    use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
    use chrono::{Duration, Utc};
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_db() -> SqlxOpStore<sqlx::Sqlite> {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let store = SqlxOpStore::<sqlx::Sqlite>::new(pool);
        store.migrate().await.unwrap();

        // Enable foreign keys in SQLite for this connection
        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(&store.pool)
            .await
            .unwrap();

        store
    }

    #[tokio::test]
    async fn test_sqlite_cascading_delete() {
        let mut store = setup_db().await;

        // Manually insert a client
        sqlx::query(
            "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("test_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode::new(
            "test_code_123".to_string(),
            "test_client".to_string(),
            "http://localhost/cb".to_string(),
            "openid".to_string(),
            authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            Utc::now() + Duration::try_minutes(10).unwrap(),
            false,
        );

        store.store_code(code.clone()).await.unwrap();

        // Consume it to verify it exists
        let consumed = store.consume_code("test_code_123").await.unwrap();
        assert!(consumed.is_some());
        assert_eq!(consumed.unwrap().client_id, "test_client");

        // Test cascade delete
        let mut code2 = code;
        code2.code = "test_code_456".to_string();
        store.store_code(code2.clone()).await.unwrap();

        // Delete the client
        sqlx::query("DELETE FROM authkestra_oauth_clients WHERE client_id = 'test_client'")
            .execute(&store.pool)
            .await
            .unwrap();

        // Ensure the code is also deleted due to CASCADE
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM authkestra_oauth_codes WHERE code = 'test_code_456'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();

        assert_eq!(count.0, 0);
    }

    #[tokio::test]
    async fn test_sqlite_concurrency() {
        let mut store = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("concurrency_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode::new(
            "concurrent_code".to_string(),
            "concurrency_client".to_string(),
            "http://localhost/cb".to_string(),
            "openid".to_string(),
            authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            Utc::now() + Duration::try_minutes(10).unwrap(),
            false,
        );
        store.store_code(code.clone()).await.unwrap();

        let mut handles = vec![];
        let store_arc = store.clone();

        // Spawn 10 simultaneous consumers
        for _ in 0..10 {
            let mut s = store_arc.clone();
            handles.push(tokio::spawn(async move {
                s.consume_code("concurrent_code").await.unwrap()
            }));
        }

        let mut successes = 0;
        let mut failures = 0;
        for h in handles {
            let res = h.await.unwrap();
            if res.is_some() {
                successes += 1;
            } else {
                failures += 1;
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(failures, 9);
    }

    fn test_identity() -> authkestra_engine::auth::state::Identity {
        authkestra_engine::auth::state::Identity {
            provider_id: "local".to_string(),
            external_id: "user_1".to_string(),
            email: None,
            username: None,
            attributes: std::collections::HashMap::new(),
        }
    }

    /// authkestra#287: `jkt` (RFC 9449 DPoP refresh-token continuity) and
    /// `token_endpoint_auth_method`/`jwks` (RFC 7523 private_key_jwt) must
    /// actually round-trip through a fresh install, not just exist as
    /// columns nothing reads or writes.
    #[tokio::test]
    async fn test_sqlite_fresh_install_persists_jkt_and_client_auth_fields() {
        let mut store = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences, token_endpoint_auth_method, jwks)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("auth287_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .bind(sqlx::types::Json(TokenEndpointAuthMethod::PrivateKeyJwt))
        .bind(sqlx::types::Json(serde_json::json!({"keys": []})))
        .execute(&store.pool)
        .await
        .unwrap();

        let client = store
            .find_client("auth287_client")
            .await
            .unwrap()
            .expect("client must be found");
        assert_eq!(
            client.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::PrivateKeyJwt)
        );
        assert_eq!(client.jwks, Some(serde_json::json!({"keys": []})));

        let rt = RefreshToken::new(
            "rt-287".to_string(),
            "auth287_client".to_string(),
            test_identity(),
            "openid".to_string(),
            Utc::now() + Duration::try_days(1).unwrap(),
            Some("expected-jkt-thumbprint".to_string()),
        );
        store.store_token(rt).await.unwrap();

        let fetched = store
            .get_token("rt-287")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("expected-jkt-thumbprint".to_string()));

        let consumed = store
            .consume_token("rt-287")
            .await
            .unwrap()
            .expect("token must be consumable");
        assert_eq!(consumed.jkt, Some("expected-jkt-thumbprint".to_string()));
    }

    /// The actual point of authkestra#287: a deployment that already ran
    /// the *old* `migrate()` (before `jkt`/`token_endpoint_auth_method`/
    /// `jwks` existed) must upgrade safely when it starts running the new
    /// code — no "table already exists" failure, no data loss for
    /// pre-existing rows, and the new columns must actually work
    /// afterwards. This is the scenario `CREATE TABLE IF NOT EXISTS`
    /// alone could never handle.
    #[tokio::test]
    async fn test_sqlite_migration_upgrades_a_pre_existing_deployment_without_the_new_columns() {
        // The pre-#287 schema, created directly — bypassing
        // `store.migrate()` entirely, exactly like an existing deployment
        // that ran the old code would already have.
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE authkestra_oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_secret_hash TEXT,
                require_pkce BOOLEAN NOT NULL DEFAULT 1,
                redirect_uris TEXT NOT NULL,
                grant_types TEXT NOT NULL,
                scopes TEXT NOT NULL,
                allowed_audiences TEXT NOT NULL
            );",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE authkestra_oauth_refresh_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE,
                identity TEXT NOT NULL,
                scope TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked_at DATETIME
            );",
        )
        .execute(&pool)
        .await
        .unwrap();

        // A client registered under the old schema, before this
        // deployment ever knew about these fields.
        sqlx::query(
            "INSERT INTO authkestra_oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("pre_existing_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&pool)
        .await
        .unwrap();

        let mut store = SqlxOpStore::<sqlx::Sqlite>::new(pool);

        store
            .migrate()
            .await
            .expect("migrating an existing pre-authkestra#287 database must succeed");

        // The pre-existing client survives untouched — the new fields are
        // simply absent, not an error.
        let client = store
            .find_client("pre_existing_client")
            .await
            .unwrap()
            .expect("the pre-existing client must survive the migration");
        assert_eq!(client.token_endpoint_auth_method, None);
        assert_eq!(client.jwks, None);

        // And the new columns are now genuinely usable.
        let rt = RefreshToken::new(
            "rt-upgrade".to_string(),
            "pre_existing_client".to_string(),
            test_identity(),
            "openid".to_string(),
            Utc::now() + Duration::try_days(1).unwrap(),
            Some("post-upgrade-jkt".to_string()),
        );
        store
            .store_token(rt)
            .await
            .expect("storing a DPoP-bound refresh token must work after the upgrade");
        let fetched = store
            .get_token("rt-upgrade")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("post-upgrade-jkt".to_string()));
    }

    /// authkestra#290 (PR review, HIGH #1): `sqlx::migrate!`'s bookkeeping
    /// lives in one database-global, unqualified `_sqlx_migrations` table
    /// that sqlx 0.8 provides no way to rename or namespace. `SqlxOpStore`
    /// is embedded into a *host application's own* connection pool, and a
    /// host that also runs `sqlx::migrate!` for its own schema against that
    /// same pool -- a completely ordinary setup -- collided with it the
    /// moment either side's migration version number matched the other's,
    /// with `Migrate::run` then refusing to apply *either* migration set.
    /// `SqlxOpStore::migrate` no longer uses `sqlx::migrate!` at all (see
    /// its doc comment), so it keeps no bookkeeping of its own and cannot
    /// collide -- verified here directly against a real `sqlx::migrate!`
    /// call, in both orderings, sharing one pool.
    #[tokio::test]
    async fn test_sqlite_migrate_does_not_collide_with_a_host_apps_own_sqlx_migrate() {
        // Order A: the host app's own sqlx::migrate! runs first.
        {
            let pool = SqlitePoolOptions::new()
                .connect("sqlite::memory:")
                .await
                .unwrap();

            sqlx::migrate!("./tests/fixture_migrations/host_app")
                .run(&pool)
                .await
                .expect("the host app's own migrator must succeed");

            let store = SqlxOpStore::<sqlx::Sqlite>::new(pool.clone());
            store
                .migrate()
                .await
                .expect("authkestra-op's migrate() must not be blocked by a host app's prior sqlx::migrate! run on the same pool");

            sqlx::query("SELECT id FROM app_widgets")
                .fetch_optional(&pool)
                .await
                .expect("the host app's own table must still exist and be queryable");
            let client_count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM authkestra_oauth_clients")
                    .fetch_one(&pool)
                    .await
                    .expect("authkestra-op's own tables must exist and be queryable");
            assert_eq!(client_count, 0);
        }

        // Order B: authkestra-op's migrate() runs first, the host app's
        // own sqlx::migrate! runs second. The reviewer's reproduction
        // showed the reverse order broke the *other* side, so both
        // orderings must be exercised.
        {
            let pool = SqlitePoolOptions::new()
                .connect("sqlite::memory:")
                .await
                .unwrap();

            let store = SqlxOpStore::<sqlx::Sqlite>::new(pool.clone());
            store.migrate().await.unwrap();

            sqlx::migrate!("./tests/fixture_migrations/host_app")
                .run(&pool)
                .await
                .expect("the host app's own migrator must not be blocked by authkestra-op's prior migrate() run on the same pool");

            sqlx::query("SELECT id FROM app_widgets")
                .fetch_optional(&pool)
                .await
                .expect("the host app's own table must exist and be queryable");
        }
    }

    /// authkestra#290 (PR review, HIGH #2): a `token_endpoint_auth_method`
    /// value the enum can't decode (e.g. an operator-written
    /// `client_secret_jwt`, which this enum has no variant for) must
    /// surface as a storage error, not silently become `None` -- `None`
    /// means "no auth method configured" to `authenticate_client`, which
    /// combined with a NULL `client_secret_hash` (a legitimate shape for a
    /// private_key_jwt-only client) authenticates the client with zero
    /// credentials.
    #[tokio::test]
    async fn test_sqlite_find_client_rejects_an_undecodable_token_endpoint_auth_method() {
        let mut store = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences, token_endpoint_auth_method)
             VALUES (?, NULL, ?, ?, ?, ?, ?, ?)"
        )
        .bind("malformed_client")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .bind(r#""client_secret_jwt""#)
        .execute(&store.pool)
        .await
        .unwrap();

        let result = store.find_client("malformed_client").await;
        assert!(
            matches!(result, Err(authkestra_engine::store::StoreError::Internal(_))),
            "an undecodable token_endpoint_auth_method must fail closed as a storage error, not silently decode to None: got {result:?}"
        );
    }

    /// The point of authkestra#291: before this, `SqlxOpStore` carried an
    /// empty `impl OpStore`, so it inherited the fail-closed
    /// `NoDpopReplayStore` default and refused *every* DPoP proof. A first
    /// claim must now succeed and an immediate replay must be refused.
    #[tokio::test]
    async fn test_sqlite_dpop_jti_is_claimed_once_and_replay_is_refused() {
        use authkestra_op::store::OpStore;
        let mut store = setup_db().await;
        let expires_at = Utc::now() + Duration::seconds(60);

        assert!(
            store
                .check_and_record_dpop_jti("jti-291", expires_at)
                .await
                .unwrap(),
            "a fresh jti must be claimable — a false here is the fail-closed \
             default this override exists to replace"
        );
        assert!(
            !store
                .check_and_record_dpop_jti("jti-291", expires_at)
                .await
                .unwrap(),
            "replaying a still-fresh jti must be refused"
        );
    }

    /// A `jti` past its window is reclaimable: `verify_dpop_proof` rejects
    /// such a proof on freshness first, so keeping the row would only grow
    /// the table forever.
    #[tokio::test]
    async fn test_sqlite_dpop_jti_is_reclaimable_once_expired() {
        use authkestra_op::store::OpStore;
        let mut store = setup_db().await;

        assert!(store
            .check_and_record_dpop_jti("jti-expired", Utc::now() - Duration::seconds(1))
            .await
            .unwrap());
        assert!(
            store
                .check_and_record_dpop_jti("jti-expired", Utc::now() + Duration::seconds(60))
                .await
                .unwrap(),
            "an expired jti must be reclaimable"
        );
    }

    /// The guarantee the single-statement upsert exists for. A
    /// `SELECT`-then-`INSERT` implementation passes both tests above and
    /// fails this one, because its TOCTOU window is the replay itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_sqlite_dpop_jti_claim_is_atomic_under_concurrency() {
        use authkestra_op::store::OpStore;
        let store = setup_db().await;
        let expires_at = Utc::now() + Duration::seconds(60);

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let mut store = store.clone();
            set.spawn(async move {
                store
                    .check_and_record_dpop_jti("jti-race", expires_at)
                    .await
                    .unwrap()
            });
        }

        let mut winners = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "exactly one concurrent claim of the same jti may win"
        );
    }

    /// authkestra#290 (PR review, finding #1): `ensure_sqlite_column`'s
    /// probe-then-ALTER is not atomic. Two replicas calling `migrate()` at
    /// the same time both see the column as absent and both issue the
    /// `ALTER`; the loser must treat "it's already there" as the intended
    /// end state, not as a failed migration that aborts startup.
    ///
    /// Driven deterministically rather than by racing two tasks: the probe
    /// is asked about a name that genuinely doesn't exist while the DDL
    /// names one that does, which produces byte-for-byte the error the
    /// losing replica receives.
    #[tokio::test]
    async fn test_sqlite_ensure_column_tolerates_a_concurrent_duplicate_add() {
        let store = setup_db().await;

        ensure_sqlite_column(
            &store.pool,
            "authkestra_oauth_clients",
            "not_a_real_column",
            "client_id TEXT",
        )
        .await
        .expect("a duplicate-column ALTER must be treated as already-migrated");
    }

    /// The other half of the finding #1 fix, and the reason it can't be a
    /// blanket `.ok()`: everything that is *not* a duplicate column must
    /// still abort the migration.
    #[tokio::test]
    async fn test_sqlite_ensure_column_still_propagates_unrelated_alter_failures() {
        let store = setup_db().await;

        let err = ensure_sqlite_column(&store.pool, "no_such_table", "c", "c TEXT")
            .await
            .expect_err("a missing table must stay fatal");
        assert!(
            !is_sqlite_duplicate_column(&err),
            "a missing table must not be classified as a duplicate column: {err:?}"
        );
    }
}

#[cfg(all(test, feature = "mysql"))]
mod mysql_tests {
    use super::*;
    use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
    use chrono::{Duration, Utc};
    use sqlx::mysql::MySqlPoolOptions;
    use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
    use testcontainers_modules::mysql::Mysql;

    async fn setup_db() -> (SqlxOpStore<sqlx::MySql>, ContainerAsync<Mysql>) {
        let container = Mysql::default()
            .with_env_var("MYSQL_ROOT_PASSWORD", "mysql")
            .with_env_var("MYSQL_DATABASE", "mysql")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(3306).await.unwrap();
        let url = format!("mysql://root:mysql@127.0.0.1:{port}/mysql");

        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();

        let store = SqlxOpStore::<sqlx::MySql>::new(pool);
        store.migrate().await.unwrap();

        (store, container)
    }

    #[tokio::test]
    async fn test_mysql_cascading_delete() {
        let (mut store, _c) = setup_db().await;

        // Manually insert a client
        sqlx::query(
            "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("test_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode::new(
            "test_code_123".to_string(),
            "test_client".to_string(),
            "http://localhost/cb".to_string(),
            "openid".to_string(),
            authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            Utc::now() + Duration::try_minutes(10).unwrap(),
            false,
        );

        store.store_code(code.clone()).await.unwrap();

        // Consume it to verify it exists
        let consumed = store.consume_code("test_code_123").await.unwrap();
        assert!(consumed.is_some());
        assert_eq!(consumed.unwrap().client_id, "test_client");

        // Test cascade delete
        let mut code2 = code;
        code2.code = "test_code_456".to_string();
        store.store_code(code2.clone()).await.unwrap();

        // Delete the client
        sqlx::query("DELETE FROM authkestra_oauth_clients WHERE client_id = 'test_client'")
            .execute(&store.pool)
            .await
            .unwrap();

        // Ensure the code is also deleted due to CASCADE
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM authkestra_oauth_codes WHERE code = 'test_code_456'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();

        assert_eq!(count.0, 0);
    }

    /// MySQL is the one backend whose `consume_code` opens a transaction of
    /// its own (no `UPDATE ... RETURNING`, so it needs
    /// `SELECT ... FOR UPDATE`). Called inside a caller's transaction that
    /// has to degrade to a nested savepoint governed by the outer rollback —
    /// otherwise the consume commits independently and the caller's unit of
    /// work silently isn't one. authkestra#336.
    #[tokio::test]
    async fn test_mysql_consume_inside_a_caller_transaction_rolls_back_with_it() {
        let (mut store, _c) = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("tx_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode::new(
            "tx_code_1".to_string(),
            "tx_client".to_string(),
            "http://localhost/cb".to_string(),
            "openid".to_string(),
            authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            Utc::now() + Duration::try_minutes(10).unwrap(),
            false,
        );

        let mut tx = store.begin_tx().await.unwrap();
        tx.store_code(code.clone()).await.unwrap();
        let consumed = tx.consume_code(&code.code).await.unwrap();
        assert!(
            consumed.is_some(),
            "the FOR UPDATE consume must work inside a caller's transaction, as a savepoint"
        );
        tx.rollback().await.unwrap();

        assert!(
            store.consume_code(&code.code).await.unwrap().is_none(),
            "store-then-consume rolled back as a unit must leave nothing behind"
        );
    }

    #[tokio::test]
    async fn test_mysql_concurrency() {
        let (mut store, _c) = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("concurrency_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&store.pool)
        .await
        .unwrap();

        let code = AuthorizationCode::new(
            "concurrent_code".to_string(),
            "concurrency_client".to_string(),
            "http://localhost/cb".to_string(),
            "openid".to_string(),
            authkestra_engine::auth::state::Identity {
                provider_id: "local".to_string(),
                external_id: "user_1".to_string(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            },
            Utc::now() + Duration::try_minutes(10).unwrap(),
            false,
        );
        store.store_code(code.clone()).await.unwrap();

        let mut handles = vec![];
        let store_arc = store.clone();

        // Spawn 10 simultaneous consumers
        for _ in 0..10 {
            let mut s = store_arc.clone();
            handles.push(tokio::spawn(async move {
                s.consume_code("concurrent_code").await.unwrap()
            }));
        }

        let mut successes = 0;
        let mut failures = 0;
        for h in handles {
            let res = h.await.unwrap();
            if res.is_some() {
                successes += 1;
            } else {
                failures += 1;
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(failures, 9);
    }

    fn test_identity() -> authkestra_engine::auth::state::Identity {
        authkestra_engine::auth::state::Identity {
            provider_id: "local".to_string(),
            external_id: "user_1".to_string(),
            email: None,
            username: None,
            attributes: std::collections::HashMap::new(),
        }
    }

    /// authkestra#287: `jkt` (RFC 9449 DPoP refresh-token continuity) and
    /// `token_endpoint_auth_method`/`jwks` (RFC 7523 private_key_jwt) must
    /// actually round-trip through a fresh install, not just exist as
    /// columns nothing reads or writes.
    #[tokio::test]
    async fn test_mysql_fresh_install_persists_jkt_and_client_auth_fields() {
        let (mut store, _c) = setup_db().await;

        sqlx::query(
            "INSERT INTO authkestra_oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences, token_endpoint_auth_method, jwks)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("auth287_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .bind(sqlx::types::Json(TokenEndpointAuthMethod::PrivateKeyJwt))
        .bind(sqlx::types::Json(serde_json::json!({"keys": []})))
        .execute(&store.pool)
        .await
        .unwrap();

        let client = store
            .find_client("auth287_client")
            .await
            .unwrap()
            .expect("client must be found");
        assert_eq!(
            client.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::PrivateKeyJwt)
        );
        assert_eq!(client.jwks, Some(serde_json::json!({"keys": []})));

        let rt = RefreshToken::new(
            "rt-287".to_string(),
            "auth287_client".to_string(),
            test_identity(),
            "openid".to_string(),
            Utc::now() + Duration::try_days(1).unwrap(),
            Some("expected-jkt-thumbprint".to_string()),
        );
        store.store_token(rt).await.unwrap();

        let fetched = store
            .get_token("rt-287")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("expected-jkt-thumbprint".to_string()));

        let consumed = store
            .consume_token("rt-287")
            .await
            .unwrap()
            .expect("token must be consumable");
        assert_eq!(consumed.jkt, Some("expected-jkt-thumbprint".to_string()));
    }

    /// The actual point of authkestra#287: a deployment that already ran
    /// the *old* `migrate()` (before `jkt`/`token_endpoint_auth_method`/
    /// `jwks` existed) must upgrade safely when it starts running the new
    /// code — no "table already exists" failure, no data loss for
    /// pre-existing rows, and the new columns must actually work
    /// afterwards. This is the scenario `CREATE TABLE IF NOT EXISTS`
    /// alone could never handle.
    #[tokio::test]
    async fn test_mysql_migration_upgrades_a_pre_existing_deployment_without_the_new_columns() {
        let container = Mysql::default()
            .with_env_var("MYSQL_ROOT_PASSWORD", "mysql")
            .with_env_var("MYSQL_DATABASE", "mysql")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(3306).await.unwrap();
        let url = format!("mysql://root:mysql@127.0.0.1:{port}/mysql");
        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();

        // The pre-#287 schema, created directly — bypassing
        // `store.migrate()` entirely, exactly like an existing deployment
        // that ran the old code would already have. Each statement is its
        // own `sqlx::query` call: MySQL's protocol (like Postgres's)
        // doesn't accept multiple `;`-separated statements through a
        // single prepared-statement execution.
        sqlx::query(
            "CREATE TABLE authkestra_oauth_clients (
                client_id VARCHAR(255) PRIMARY KEY,
                client_secret_hash VARCHAR(255),
                require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
                redirect_uris JSON NOT NULL,
                grant_types JSON NOT NULL,
                scopes JSON NOT NULL,
                allowed_audiences JSON NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE authkestra_oauth_refresh_tokens (
                token VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL,
                identity JSON NOT NULL,
                scope TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked_at DATETIME,
                FOREIGN KEY (client_id) REFERENCES authkestra_oauth_clients(client_id) ON DELETE CASCADE
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        // A client registered under the old schema, before this
        // deployment ever knew about these fields.
        sqlx::query(
            "INSERT INTO authkestra_oauth_clients
             (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("pre_existing_client")
        .bind("hash")
        .bind(true)
        .bind(sqlx::types::Json(vec!["http://localhost/cb"]))
        .bind(sqlx::types::Json(vec!["authorization_code"]))
        .bind(sqlx::types::Json(vec!["openid"]))
        .bind(sqlx::types::Json(vec!["aud"]))
        .execute(&pool)
        .await
        .unwrap();

        let mut store = SqlxOpStore::<sqlx::MySql>::new(pool);

        store
            .migrate()
            .await
            .expect("migrating an existing pre-authkestra#287 database must succeed");

        let client = store
            .find_client("pre_existing_client")
            .await
            .unwrap()
            .expect("the pre-existing client must survive the migration");
        assert_eq!(client.token_endpoint_auth_method, None);
        assert_eq!(client.jwks, None);

        let rt = RefreshToken::new(
            "rt-upgrade".to_string(),
            "pre_existing_client".to_string(),
            test_identity(),
            "openid".to_string(),
            Utc::now() + Duration::try_days(1).unwrap(),
            Some("post-upgrade-jkt".to_string()),
        );
        store
            .store_token(rt)
            .await
            .expect("storing a DPoP-bound refresh token must work after the upgrade");
        let fetched = store
            .get_token("rt-upgrade")
            .await
            .unwrap()
            .expect("token must be found");
        assert_eq!(fetched.jkt, Some("post-upgrade-jkt".to_string()));
    }

    /// authkestra#291: `SqlxOpStore` used to inherit the fail-closed
    /// `NoDpopReplayStore` default, refusing every DPoP proof.
    #[tokio::test]
    async fn test_mysql_dpop_jti_is_claimed_once_and_replay_is_refused() {
        use authkestra_op::store::OpStore;
        let (mut store, _c) = setup_db().await;
        let expires_at = Utc::now() + Duration::seconds(60);

        assert!(store
            .check_and_record_dpop_jti("jti-291", expires_at)
            .await
            .unwrap());
        assert!(
            !store
                .check_and_record_dpop_jti("jti-291", expires_at)
                .await
                .unwrap(),
            "replaying a still-fresh jti must be refused"
        );
    }

    #[tokio::test]
    async fn test_mysql_dpop_jti_is_reclaimable_once_expired() {
        use authkestra_op::store::OpStore;
        let (mut store, _c) = setup_db().await;

        assert!(store
            .check_and_record_dpop_jti("jti-expired", Utc::now() - Duration::seconds(5))
            .await
            .unwrap());
        assert!(
            store
                .check_and_record_dpop_jti("jti-expired", Utc::now() + Duration::seconds(60))
                .await
                .unwrap(),
            "an expired jti must be reclaimable"
        );
    }

    /// Guards both the TOCTOU window and, on MySQL, the gap-lock deadlock
    /// that a `SELECT ... FOR UPDATE` transaction would hit on a
    /// not-yet-existing row under the default REPEATABLE READ.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_mysql_dpop_jti_claim_is_atomic_under_concurrency() {
        use authkestra_op::store::OpStore;
        let (store, _c) = setup_db().await;
        let expires_at = Utc::now() + Duration::seconds(60);

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let mut store = store.clone();
            set.spawn(async move {
                store
                    .check_and_record_dpop_jti("jti-race", expires_at)
                    .await
                    .expect("a concurrent claim must not error — a deadlock here would")
            });
        }

        let mut winners = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one concurrent claim may win");
    }

    /// authkestra#290 (PR review, finding #1) — the MySQL half. See
    /// `sqlite_tests`'s identically named test for the reasoning and for
    /// why the race is driven deterministically instead of with two tasks.
    /// MySQL reports this as `ER_DUP_FIELDNAME` (1060, SQLSTATE 42S21).
    #[tokio::test]
    async fn test_mysql_ensure_column_tolerates_a_concurrent_duplicate_add() {
        let (store, _c) = setup_db().await;

        ensure_mysql_column(
            &store.pool,
            "authkestra_oauth_clients",
            "not_a_real_column",
            "client_id VARCHAR(255)",
        )
        .await
        .expect("a duplicate-column ALTER must be treated as already-migrated");
    }

    /// The other half of the finding #1 fix: a missing table is MySQL 1146,
    /// not 1060, and must still abort the migration.
    #[tokio::test]
    async fn test_mysql_ensure_column_still_propagates_unrelated_alter_failures() {
        let (store, _c) = setup_db().await;

        let err = ensure_mysql_column(&store.pool, "no_such_table", "c", "c VARCHAR(255)")
            .await
            .expect_err("a missing table must stay fatal");
        assert!(
            !is_mysql_duplicate_column(&err),
            "a missing table must not be classified as a duplicate column: {err:?}"
        );
    }
}
