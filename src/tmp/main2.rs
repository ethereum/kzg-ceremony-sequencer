mod main_mvp;

use axum::{
    body::Bytes,
    error_handling::HandleErrorLayer,
    extract::{ContentLengthLimit, Extension, Path},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    BoxError, Json, Router,
};
use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;
use std::{
    borrow::Cow,
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    // time::{Duration, Instant},
};
use tokio::time::{Duration, Instant};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "example_key_value_store=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let shared_state = SharedState::default();

    // Build our application by composing routes
    let app = Router::new()
        // .route(
        //     "/:key",
        //     // Add compression to `kv_get`
        //     get(kv_get)
        //         // But don't compress `kv_set`
        //         .post(kv_set),
        // )
        .route("/register", get(register))
        .route("/ping/:id", get(ping))
        // .route("/insert/:name", get(kv_set2))
        .route("/keys", get(list_keys))
        .layer(Extension(shared_state))
        // Nest our admin routes under `/admin`
        // .nest("/admin", admin_routes(shared_state))
        // Add middleware to all routes
        .layer(
            ServiceBuilder::new()
                // Handle errors from middleware
                .layer(HandleErrorLayer::new(handle_error))
                .load_shed()
                .concurrency_limit(1024)
                .timeout(Duration::from_secs(10))
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        );

    // Run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

type SharedState = Arc<RwLock<AppState>>;

#[derive(Default)]
struct AppState {
    db: HashMap<String, Instant>,
}

async fn kv_get(
    Path(key): Path<String>,
    Extension(state): Extension<SharedState>,
) -> Result<String, StatusCode> {
    let db = &state.read().unwrap().db;

    if let Some(value) = db.get(&key) {
        Ok(value.clone().elapsed().as_secs().to_string())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// async fn kv_set(
//     Path(key): Path<String>,
//     ContentLengthLimit(bytes): ContentLengthLimit<Bytes, { 1024 * 5_000 }>, // ~5mb
//     Extension(state): Extension<SharedState>,
// ) {
//     state.write().unwrap().db.insert(key, bytes);
// }
// async fn kv_set2(Path(name): Path<String>, Extension(state): Extension<SharedState>) {
//     let greeting = name;

//     state
//         .write()
//         .unwrap()
//         .db
//         .insert(greeting.to_owned(), greeting.into());
// }

// Pings the server to state that you are still alive
async fn ping(Path(id): Path<String>, Extension(state): Extension<SharedState>) -> String {
    let now = Instant::now();
    let app_state = state.read().unwrap();
    let last_pinged_time = app_state.db.get(&id).cloned();
    match last_pinged_time {
        Some(last_date_time) => {
            let time_elapsed = last_date_time.elapsed();
            // TODO: for some reason, the time elapsed is not correct
            // TODO: 3 seconds is being picked up as 6 or 8 seconds
            // TODO: check this later
            if time_elapsed > std::time::Duration::from_secs(10) {
                return format!(
                    "Too late to ping! You took {} seconds ",
                    time_elapsed.as_secs()
                );
            } else {
                // state.write().unwrap().db.insert(id.to_owned(), now);
                return format!("Ping successful!");
            }
        }

        None => return format!("{} is not in the queue", id),
    }
}

// Registers a user to go into the queue
async fn register(Extension(state): Extension<SharedState>) -> Html<String> {
    let id = uuid::Uuid::new_v4();
    let now = Instant::now();

    state
        .write()
        .unwrap()
        .db
        .insert(id.to_string().to_owned(), now);
    let num_entries = state.read().unwrap().db.len();

    Html(format!(
        "<h1>ID: {} <br>You are number {} in the queue</h1>",
        id.to_string(),
        num_entries
    ))
}

async fn list_keys(Extension(state): Extension<SharedState>) -> String {
    let db = &state.read().unwrap().db;

    db.keys()
        .map(|key| key.to_string())
        .collect::<Vec<String>>()
        .join("\n")
}

// fn admin_routes(state: SharedState) -> Router<SharedState> {
//     async fn delete_all_keys(State(state): State<SharedState>) {
//         state.write().unwrap().db.clear();
//     }

//     async fn remove_key(Path(key): Path<String>, State(state): State<SharedState>) {
//         state.write().unwrap().db.remove(&key);
//     }

//     Router::with_state(state)
//         .route("/keys", delete(delete_all_keys))
//         .route("/key/:key", delete(remove_key))
//         // Require bearer auth for all admin routes
//         .layer(RequireAuthorizationLayer::bearer("secret-token"))
// }

async fn handle_error(error: BoxError) -> impl IntoResponse {
    if error.is::<tower::timeout::error::Elapsed>() {
        return (StatusCode::REQUEST_TIMEOUT, Cow::from("request timed out"));
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Cow::from("service is overloaded, try again later"),
        );
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Cow::from(format!("Unhandled internal error: {}", error)),
    )
}
