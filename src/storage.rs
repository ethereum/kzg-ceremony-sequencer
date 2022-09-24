use axum::{
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use clap::Parser;
use eyre::{eyre, WrapErr};
use http::StatusCode;
use serde_json::json;
use sqlx::{
    any::AnyKind,
    migrate::{Migrate, MigrateDatabase, Migrator},
    pool::PoolOptions,
    Any, Executor, Pool, Row,
};
use thiserror::Error;
use tracing::{error, info, warn};

// Statically link in migration files
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct Options {
    /// Database server connection string.
    ///
    /// Example: `postgres://user:password@localhost:5432/database`
    /// Sqlite file: `sqlite://storage.db`
    /// In memory DB: `sqlite::memory:`
    ///
    /// By default, it is a file named `storage.db` in the current directory.
    /// You can use `sqlite::memory:` to use an in-memory database.
    #[clap(long, env, default_value = "sqlite://storage.db")]
    database_url: String,

    /// Allow creation or migration of the database schema.
    /// When set to false the process will terminate if the database is not
    /// up to date.
    #[clap(long, env, default_value = "true")]
    pub database_migrate: bool,

    /// Maximum number of connections in the database connection pool
    #[clap(long, env, default_value = "10")]
    pub database_max_connections: u32,
}

#[derive(Clone, Debug)]
pub struct PersistentStorage(Pool<Any>);

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::error::Error),
}

pub async fn storage_client(options: &Options) -> eyre::Result<PersistentStorage> {
    info!(url = %&options.database_url, "Connecting to database");

    // Create database if requested and does not exist
    if options.database_migrate && !Any::database_exists(options.database_url.as_str()).await? {
        warn!(url = %&options.database_url, "Database does not exist, creating database");
        Any::create_database(options.database_url.as_str()).await?;
    }

    // Create a connection pool
    let pool = PoolOptions::<Any>::new()
        .max_connections(options.database_max_connections)
        .connect(options.database_url.as_str())
        .await
        .wrap_err("error connecting to database")?;

    // Log DB version to test connection.
    let sql = match pool.any_kind() {
        #[cfg(feature = "sqlite")]
        AnyKind::Sqlite => "sqlite_version() || ' ' || sqlite_source_id()",

        #[cfg(feature = "postgres")]
        AnyKind::Postgres => "version()",

        // Depending on compilation flags there may be more patterns.
        #[allow(unreachable_patterns)]
        _ => "'unknown'",
    };
    let version = pool
        .fetch_one(format!("SELECT {sql};", sql = sql).as_str())
        .await
        .wrap_err("error getting database version")?
        .get::<String, _>(0);
    info!(url = %&options.database_url, kind = ?pool.any_kind(), ?version, "Connected to database");

    // Run migrations if requested.
    let latest = MIGRATOR.migrations.last().unwrap().version;
    if options.database_migrate {
        info!(url = %&options.database_url, "Running database migrations if necessary");
        MIGRATOR.run(&pool).await?;
    }

    // Validate database schema version
    #[allow(deprecated)] // HACK: No good alternative to `version()`?
    if let Some((version, dirty)) = pool.acquire().await?.version().await? {
        if dirty {
            error!(
                url = %&options.database_url,
                version,
                expected = latest,
                "Database is in incomplete migration state.",
            );
            return Err(eyre!("Database is in incomplete migration state."));
        } else if version < latest {
            error!(
                url = %&options.database_url,
                version,
                expected = latest,
                "Database is not up to date, try rerunning with --database-migrate",
            );
            return Err(eyre!(
                "Database is not up to date, try rerunning with --database-migrate"
            ));
        } else if version > latest {
            error!(
                url = %&options.database_url,
                version,
                latest,
                "Database version is newer than this version of the software, please update.",
            );
            return Err(eyre!(
                "Database version is newer than this version of the software, please update."
            ));
        }
        info!(
            url = %&options.database_url,
            version,
            latest,
            "Database version is up to date.",
        );
    } else {
        error!(url = %&options.database_url, "Could not get database version");
        return Err(eyre!("Could not get database version."));
    }

    Ok(PersistentStorage(pool))
}

impl IntoResponse for StorageError {
    fn into_response(self) -> Response {
        let message = match self {
            Self::DatabaseError(error) => error.to_string(),
        };
        let body = Json(json!({ "error": message }));
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

impl PersistentStorage {
    pub async fn has_contributed(&self, uid: &str) -> Result<bool, StorageError> {
        let sql = "SELECT EXISTS(SELECT 1 FROM contributors WHERE uid = ?1)";
        let result = self
            .0
            .fetch_one(sqlx::query(sql).bind(uid))
            .await
            .map(|row| row.get(0))?;
        Ok(result)
    }

    pub async fn insert_contributor(&self, uid: &str) -> Result<(), StorageError> {
        let sql = "INSERT INTO contributors (uid, started_at) VALUES (?1, ?2)";
        self.0
            .execute(sqlx::query(sql).bind(uid).bind(Utc::now()))
            .await?;
        Ok(())
    }

    pub async fn finish_contribution(&self, uid: &str) -> Result<(), StorageError> {
        let sql = "UPDATE contributors SET finished_at = ?1 WHERE uid = ?2";
        self.0
            .execute(sqlx::query(sql).bind(Utc::now()).bind(uid))
            .await?;
        Ok(())
    }

    pub async fn expire_contribution(&self, uid: &str) -> Result<(), StorageError> {
        let sql = "UPDATE contributors SET expired_at = ?1 WHERE uid = ?2";
        self.0
            .execute(sqlx::query(sql).bind(Utc::now()).bind(uid))
            .await?;
        Ok(())
    }
}
