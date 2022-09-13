use std::env;

use axum::{response::{IntoResponse, Response}, Json};
use chrono::Utc;
use http::StatusCode;
use serde_json::json;
use sqlx::{Sqlite, Pool, sqlite::SqlitePoolOptions, Executor, Row};

#[derive(Debug)]
pub enum StorageError {
    DatabaseError(sqlx::error::Error)
}

impl IntoResponse for StorageError {
    fn into_response(self) -> Response {
        let message = match self {
            StorageError::DatabaseError(error) => error.to_string()
        };
        let body = Json(json!({ "error": message}));
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

#[derive(Clone)]
pub struct PersistentStorage(Pool<Sqlite>);

impl PersistentStorage {
    pub async fn has_contributed(&self, uid: &str) -> Result<bool, StorageError> {
        let sql = "SELECT EXISTS(SELECT 1 FROM contributors WHERE uid = ?1";
        let result = self.0
            .fetch_one(sqlx::query(sql).bind(uid))
            .await
            .map(|row| row.get(0))
            .map_err(|e| StorageError::DatabaseError(e));

        result
    }

    pub async fn insert_contributor(&self, uid: &str) {
        let sql = "INSERT INTO contributors (uid, started_at) VALUES (?1, ?2)";
        self.0
            .execute(sqlx::query(sql).bind(uid).bind(Utc::now()))
            .await
            .ok();
    }

    pub async fn finish_contribution(&self, uid: &str) {
        let sql = "UPDATE contributors SET finished_at = ?1 WHERE uid = ?2";
        self.0
            .execute(sqlx::query(sql).bind(Utc::now()).bind(uid))
            .await
            .ok();
    }

    pub async fn expire_contribution(&self, uid: &str) {
        let sql = "UPDATE contributors SET expired_at = ?1 WHERE uid = ?2";
        self.0
            .execute(sqlx::query(sql).bind(Utc::now()).bind(uid))
            .await
            .ok();
    }
}

pub async fn persistent_storage_client() -> PersistentStorage {
    let url = env::var("DATABASE_URL").expect("Missing DATABASE_URL!");
    let db_pool = SqlitePoolOptions::new()
        .connect(&url)
        .await
        .expect("Unable to connect to DATABASE_URL");

    sqlx::migrate!().run(&db_pool).await.unwrap();

    PersistentStorage(db_pool)
}

#[cfg(test)]
pub async fn test_storage_client() -> PersistentStorage {
    let db_pool = SqlitePoolOptions::new()
        .connect("sqlite://:memory:")
        .await
        .expect("Unable to connect to memory database");

    sqlx::migrate!().run(&db_pool).await.unwrap();

    PersistentStorage(db_pool)
}