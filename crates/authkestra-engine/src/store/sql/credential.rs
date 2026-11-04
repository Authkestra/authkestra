#[cfg(all(
    any(
        feature = "sql-postgres",
        feature = "sql-sqlite",
        feature = "sql-mysql"
    ),
    any(feature = "webauthn", feature = "totp")
))]
use async_trait::async_trait;
use serde_json::Value;
use sqlx::Database;

use crate::auth::error::AuthError;
use crate::auth::store::CredentialStore;

/// SQLx implementation of the `CredentialStore` trait.
#[derive(Debug)]
#[non_exhaustive]
pub struct SqlxCredentialStore<DB: Database> {
    pub pool: sqlx::Pool<DB>,
    pub table_name: String,
}

/// Cloned by hand rather than derived.
///
/// `#[derive(Clone)]` would add a `DB: Clone` bound, and `DB` here is a
/// backend marker — `sqlx::Sqlite`, `sqlx::Postgres`, `sqlx::MySql` — none of
/// which is `Clone`. The derive therefore produced an impl that applied to no
/// real backend, making the store uncloneable in practice while looking as
/// though it were not. `sqlx::Pool<DB>` is itself `Clone` for any
/// `DB: Database` (it is an `Arc` inside), so nothing about the type actually
/// required the bound.
impl<DB: Database> Clone for SqlxCredentialStore<DB> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            table_name: self.table_name.clone(),
        }
    }
}

impl<DB: Database> SqlxCredentialStore<DB> {
    /// Create a new `SqlxCredentialStore` with the default table name `ak_credentials`.
    pub fn new(pool: sqlx::Pool<DB>) -> Self {
        Self {
            pool,
            table_name: "ak_credentials".to_string(),
        }
    }

    /// Create a new `SqlxCredentialStore` with a custom table name.
    pub fn with_table_name(pool: sqlx::Pool<DB>, table_name: String) -> Self {
        Self { pool, table_name }
    }
}

/// Helper model for deserializing database rows using normalized columns.
#[derive(sqlx::FromRow)]
struct SqlCredentialModel {
    #[allow(dead_code)]
    pub credential_id: String,
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub cred_type: String,
    pub secret_key: Option<String>,
    pub extra_data: Option<String>,
}

macro_rules! impl_credential_store {
    (
        $backend:path,
        $feature:literal,
        $dialect_name:literal,
        $save_query:expr,
        $get_query:expr,
        $update_query:expr,
        $delete_credential_query:expr,
        $delete_credentials_query:expr,
        $claim_totp_step_query:expr,
        $migrate_q1:expr,
        $migrate_q2:expr
    ) => {
        #[cfg(feature = $feature)]
        #[async_trait]
        impl CredentialStore for SqlxCredentialStore<$backend> {
            #[tracing::instrument(skip(self, data))]
            async fn save_credential(
                &self,
                user_id: &str,
                cred_type: &str,
                data: Value,
            ) -> Result<(), AuthError> {
                tracing::debug!(concat!("saving credential to ", $dialect_name, " store"));
                let query = format!($save_query, self.table_name);

                let credential_id = data
                    .get("credential_id")
                    .or_else(|| data.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

                let mut secret_key: Option<String> = None;
                let mut extra_data: Option<String> = None;

                if cred_type == "totp" {
                    if let Some(s) = data.as_str() {
                        secret_key = Some(s.to_string());
                    } else if let Some(s) = data.get("secret").and_then(|v| v.as_str()) {
                        secret_key = Some(s.to_string());
                    }
                    if data.is_object() {
                        extra_data = Some(serde_json::to_string(&data).unwrap_or_default());
                    }
                } else if cred_type == "password" {
                    if let Some(s) = data.as_str() {
                        secret_key = Some(s.to_string());
                    }
                } else {
                    extra_data = Some(serde_json::to_string(&data).unwrap_or_default());
                }

                let result = sqlx::query(&query)
                    .bind(&credential_id)
                    .bind(user_id)
                    .bind(cred_type)
                    .bind(secret_key)
                    .bind(extra_data)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " save_credential error"));
                        AuthError::Internal(format!("{} save_credential error: {}", $dialect_name, e))
                    })?;

                if result.rows_affected() == 0 {
                    tracing::error!(
                        credential_id = %credential_id,
                        user_id = %user_id,
                        cred_type = %cred_type,
                        "credential_id conflict: credential belongs to another user or credential type"
                    );
                    return Err(AuthError::Credentials(
                        "Credential ID collision or ownership mismatch".into(),
                    ));
                }

                Ok(())
            }

            #[tracing::instrument(skip(self))]
            async fn get_credentials(
                &self,
                user_id: &str,
                cred_type: &str,
            ) -> Result<Vec<Value>, AuthError> {
                tracing::debug!(user_id = %user_id, cred_type = %cred_type, concat!("loading credentials from ", $dialect_name, " store"));
                let query = format!($get_query, self.table_name);

                let rows: Vec<SqlCredentialModel> = sqlx::query_as(&query)
                    .bind(user_id)
                    .bind(cred_type)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " get_credentials error"));
                        AuthError::Internal(format!("{} get_credentials error: {}", $dialect_name, e))
                    })?;

                let mut list = Vec::new();
                for row in rows {
                    if cred_type == "totp" {
                        let mut obj = serde_json::json!({ "credential_id": row.credential_id });
                        if let Some(secret) = row.secret_key {
                            obj["secret"] = Value::String(secret);
                        }
                        if let Some(extra) = row.extra_data {
                            if let Ok(extra_val) = serde_json::from_str::<Value>(&extra) {
                                if let Some(step) = extra_val.get("last_used_step") {
                                    obj["last_used_step"] = step.clone();
                                }
                            }
                        }
                        list.push(obj);
                    } else if cred_type == "password" {
                        if let Some(secret) = row.secret_key {
                            list.push(Value::String(secret));
                        }
                    } else if let Some(extra) = row.extra_data {
                        let val: Value = serde_json::from_str(&extra).map_err(|e| {
                            tracing::error!(error = %e, "Deserialization error");
                            AuthError::Internal(format!("Deserialization error: {e}"))
                        })?;
                        list.push(val);
                    }
                }

                Ok(list)
            }

            #[tracing::instrument(skip(self, data))]
            async fn update_credential(
                &self,
                credential_id: &str,
                data: Value,
            ) -> Result<(), AuthError> {
                tracing::debug!(credential_id = %credential_id, concat!("updating credential in ", $dialect_name, " store"));
                let query = format!($update_query, self.table_name);

                let extra_data = serde_json::to_string(&data)
                    .map_err(|e| AuthError::Internal(format!("Serialization error: {e}")))?;

                sqlx::query(&query)
                    .bind(extra_data)
                    .bind(credential_id)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " update_credential error"));
                        AuthError::Internal(format!("{} update_credential error: {}", $dialect_name, e))
                    })?;

                Ok(())
            }

            #[tracing::instrument(skip(self))]
            async fn delete_credential(
                &self,
                user_id: &str,
                cred_type: &str,
                credential_id: &str,
            ) -> Result<bool, AuthError> {
                tracing::debug!(user_id = %user_id, cred_type = %cred_type, credential_id = %credential_id, concat!("deleting credential from ", $dialect_name, " store"));
                let query = format!($delete_credential_query, self.table_name);

                let result = sqlx::query(&query)
                    .bind(credential_id)
                    .bind(user_id)
                    .bind(cred_type)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " delete_credential error"));
                        AuthError::Internal(format!("{} delete_credential error: {}", $dialect_name, e))
                    })?;

                Ok(result.rows_affected() > 0)
            }

            #[tracing::instrument(skip(self))]
            async fn delete_credentials(
                &self,
                user_id: &str,
                cred_type: &str,
            ) -> Result<u64, AuthError> {
                tracing::debug!(user_id = %user_id, cred_type = %cred_type, concat!("deleting all credentials from ", $dialect_name, " store"));
                let query = format!($delete_credentials_query, self.table_name);

                let result = sqlx::query(&query)
                    .bind(user_id)
                    .bind(cred_type)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " delete_credentials error"));
                        AuthError::Internal(format!("{} delete_credentials error: {}", $dialect_name, e))
                    })?;

                Ok(result.rows_affected())
            }

            #[tracing::instrument(skip(self))]
            async fn claim_totp_step(
                &self,
                user_id: &str,
                credential_id: &str,
                matched_step: u64,
            ) -> Result<bool, AuthError> {
                tracing::debug!(
                    user_id = %user_id,
                    credential_id = %credential_id,
                    matched_step = matched_step,
                    concat!("claiming TOTP step in ", $dialect_name, " store")
                );
                let query = format!($claim_totp_step_query, self.table_name);

                let result = sqlx::query(&query)
                    .bind(matched_step as i64)
                    .bind(credential_id)
                    .bind(user_id)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " claim_totp_step error"));
                        AuthError::Internal(format!("{} claim_totp_step error: {}", $dialect_name, e))
                    })?;

                Ok(result.rows_affected() > 0)
            }
        }

        #[cfg(feature = $feature)]
        impl SqlxCredentialStore<$backend> {
            /// Creates the necessary credentials table and index if they do not exist.
            pub async fn migrate(&self) -> Result<(), AuthError> {
                let query1 = format!($migrate_q1, table = self.table_name);
                let query2 = format!($migrate_q2, table = self.table_name);
                sqlx::query(&query1)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| AuthError::Internal(format!("{} credential migration error: {}", $dialect_name, e)))?;
                sqlx::query(&query2)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| AuthError::Internal(format!("{} credential migration index error: {}", $dialect_name, e)))?;
                Ok(())
            }
        }
    };
}

impl_credential_store! {
    sqlx::Postgres,
    "sql-postgres",
    "Postgres",
    "INSERT INTO {0} (credential_id, user_id, cred_type, secret_key, extra_data) VALUES ($1, $2, $3, $4, $5) ON CONFLICT(credential_id) DO UPDATE SET secret_key = EXCLUDED.secret_key, extra_data = EXCLUDED.extra_data WHERE {0}.user_id = EXCLUDED.user_id AND {0}.cred_type = EXCLUDED.cred_type",
    "SELECT credential_id, user_id, cred_type, secret_key, extra_data FROM {} WHERE user_id = $1 AND cred_type = $2 ORDER BY created_at DESC",
    "UPDATE {} SET extra_data = $1 WHERE credential_id = $2",
    "DELETE FROM {} WHERE credential_id = $1 AND user_id = $2 AND cred_type = $3",
    "DELETE FROM {} WHERE user_id = $1 AND cred_type = $2",
    "UPDATE {0} SET extra_data = (coalesce(nullif(extra_data, ''), '{{}}')::jsonb || jsonb_build_object('last_used_step', $1::bigint))::text WHERE credential_id = $2 AND user_id = $3 AND cred_type = 'totp' AND (extra_data IS NULL OR (coalesce(nullif(extra_data, ''), '{{}}')::jsonb->>'last_used_step') IS NULL OR ((coalesce(nullif(extra_data, ''), '{{}}')::jsonb->>'last_used_step')::bigint < $1))",
    "CREATE TABLE IF NOT EXISTS {table} (credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, cred_type TEXT NOT NULL, secret_key TEXT, extra_data TEXT, created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    "CREATE INDEX IF NOT EXISTS {table}_user_idx ON {table}(user_id, cred_type)"
}

impl_credential_store! {
    sqlx::Sqlite,
    "sql-sqlite",
    "Sqlite",
    "INSERT INTO {0} (credential_id, user_id, cred_type, secret_key, extra_data) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(credential_id) DO UPDATE SET secret_key = excluded.secret_key, extra_data = excluded.extra_data WHERE {0}.user_id = excluded.user_id AND {0}.cred_type = excluded.cred_type",
    "SELECT credential_id, user_id, cred_type, secret_key, extra_data FROM {} WHERE user_id = ?1 AND cred_type = ?2 ORDER BY created_at DESC",
    "UPDATE {} SET extra_data = ?1 WHERE credential_id = ?2",
    "DELETE FROM {} WHERE credential_id = ?1 AND user_id = ?2 AND cred_type = ?3",
    "DELETE FROM {} WHERE user_id = ?1 AND cred_type = ?2",
    "UPDATE {} SET extra_data = json_set(coalesce(extra_data, '{{}}'), '$.last_used_step', ?1) WHERE credential_id = ?2 AND user_id = ?3 AND cred_type = 'totp' AND (extra_data IS NULL OR json_extract(extra_data, '$.last_used_step') IS NULL OR json_extract(extra_data, '$.last_used_step') < ?1)",
    "CREATE TABLE IF NOT EXISTS {table} (credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, cred_type TEXT NOT NULL, secret_key TEXT, extra_data TEXT, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    "CREATE INDEX IF NOT EXISTS {table}_user_idx ON {table}(user_id, cred_type)"
}

impl_credential_store! {
    sqlx::MySql,
    "sql-mysql",
    "MySql",
    "INSERT INTO {} (credential_id, user_id, cred_type, secret_key, extra_data) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE secret_key = IF(user_id = VALUES(user_id) AND cred_type = VALUES(cred_type), VALUES(secret_key), secret_key), extra_data = IF(user_id = VALUES(user_id) AND cred_type = VALUES(cred_type), VALUES(extra_data), extra_data), credential_id = IF(user_id = VALUES(user_id) AND cred_type = VALUES(cred_type), credential_id, NULL)",
    "SELECT credential_id, user_id, cred_type, secret_key, extra_data FROM {} WHERE user_id = ? AND cred_type = ? ORDER BY created_at DESC",
    "UPDATE {} SET extra_data = ? WHERE credential_id = ?",
    "DELETE FROM {} WHERE credential_id = ? AND user_id = ? AND cred_type = ?",
    "DELETE FROM {} WHERE user_id = ? AND cred_type = ?",
    "UPDATE {} SET extra_data = JSON_SET(COALESCE(NULLIF(extra_data, ''), '{{}}'), '$.last_used_step', ?) WHERE credential_id = ? AND user_id = ? AND cred_type = 'totp' AND (extra_data IS NULL OR extra_data = '' OR JSON_EXTRACT(extra_data, '$.last_used_step') IS NULL OR JSON_EXTRACT(extra_data, '$.last_used_step') < ?)",
    "CREATE TABLE IF NOT EXISTS {table} (credential_id VARCHAR(255) PRIMARY KEY, user_id VARCHAR(255) NOT NULL, cred_type VARCHAR(255) NOT NULL, secret_key TEXT, extra_data TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    "CREATE INDEX {table}_user_idx ON {table}(user_id, cred_type)"
}

#[cfg(test)]
#[cfg(feature = "sql-sqlite")]
mod tests {
    use super::*;
    use crate::auth::CredentialStore;
    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn test_sqlite_credential_store() {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = SqlxCredentialStore::new(pool);
        store.migrate().await.unwrap();

        // 1. Password
        store
            .save_credential("user1", "password", json!("hashed_pwd"))
            .await
            .unwrap();
        let creds = store.get_credentials("user1", "password").await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].as_str().unwrap(), "hashed_pwd");

        // 2. TOTP
        store
            .save_credential(
                "user2",
                "totp",
                json!({"credential_id": "totp_cred", "secret": "ABC"}),
            )
            .await
            .unwrap();
        let totps = store.get_credentials("user2", "totp").await.unwrap();
        assert_eq!(totps.len(), 1);
        assert_eq!(totps[0]["secret"].as_str().unwrap(), "ABC");

        // 3. Webauthn
        let webauthn_data = json!({"id": "passkey1", "foo": "bar"});
        store
            .save_credential("user3", "webauthn", webauthn_data.clone())
            .await
            .unwrap();
        let passkeys = store.get_credentials("user3", "webauthn").await.unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0]["id"].as_str().unwrap(), "passkey1");

        // 4. Delete Webauthn
        let deleted = store
            .delete_credential("user3", "webauthn", "passkey1")
            .await
            .unwrap();
        assert!(deleted);
    }

    #[tokio::test]
    async fn test_sqlite_claim_totp_step_and_collision_rejection() {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = SqlxCredentialStore::new(pool);
        store.migrate().await.unwrap();

        // Save a TOTP credential with explicit ID
        store
            .save_credential(
                "alice",
                "totp",
                json!({"credential_id": "alice_totp", "secret": "JBSWY3DPEHPK3PXP"}),
            )
            .await
            .unwrap();

        // 1. claim_totp_step should succeed for first attempt
        let claimed = store
            .claim_totp_step("alice", "alice_totp", 100)
            .await
            .unwrap();
        assert!(claimed, "initial step claim should succeed");

        // 2. Replaying the exact same step should return false
        let replay = store
            .claim_totp_step("alice", "alice_totp", 100)
            .await
            .unwrap();
        assert!(!replay, "replaying step 100 must return false");

        // 3. An older step should return false
        let older = store
            .claim_totp_step("alice", "alice_totp", 99)
            .await
            .unwrap();
        assert!(!older, "older step 99 must return false");

        // 4. A newer step should succeed
        let newer = store
            .claim_totp_step("alice", "alice_totp", 101)
            .await
            .unwrap();
        assert!(newer, "newer step 101 must succeed");

        // 5. Wrong user should return false
        let wrong_user = store
            .claim_totp_step("bob", "alice_totp", 102)
            .await
            .unwrap();
        assert!(
            !wrong_user,
            "claiming step for wrong user must return false"
        );

        // 6. Cross-user collision: bob tries to hijack or overwrite alice's credential_id
        let collision_result = store
            .save_credential(
                "bob",
                "totp",
                json!({"credential_id": "alice_totp", "secret": "ATTACKER_SECRET"}),
            )
            .await;
        assert!(
            collision_result.is_err(),
            "saving credential with existing credential_id under another user must be rejected"
        );

        // 7. Legitimate update by alice under alice_totp succeeds
        let update_result = store
            .save_credential(
                "alice",
                "totp",
                json!({"credential_id": "alice_totp", "secret": "NEW_SECRET"}),
            )
            .await;
        assert!(
            update_result.is_ok(),
            "legitimate owner update must succeed"
        );
    }
}
