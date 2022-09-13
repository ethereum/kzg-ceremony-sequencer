use std::env;

use sqlx::{Sqlite, Pool, sqlite::SqlitePoolOptions, Executor, Row};

pub enum StorageError {
    DatabaseError(sqlx::error::Error)
}

#[derive(Clone)]
pub struct PersistentStorage(Pool<Sqlite>);

impl PersistentStorage {
    pub async fn has_contributed(&self, uid: &str) -> Result<bool, StorageError> {
        let sql = "SELECT EXISTS(SELECT 1 FROM finished_contributors WHERE uid = ?1";
        let result = self.0
            .fetch_one(sqlx::query(sql).bind(uid))
            .await
            .map(|row| row.get(0))
            .map_err(|e| StorageError::DatabaseError(e));

        result
    }

    pub async fn insert_contributor(&self, uid: &str) {
        let sql = "INSERT INTO finished_contributors (uid, successful) VALUES (?1, ?2)";
        self.0
            .execute(sqlx::query(sql).bind(uid).bind(true))
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