use axum::{
    extract::{Extension, Path},
    response::Html,
    routing::get,
    Router,
};

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
// use tokio::time::{Duration, Instant};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

mod auth;

#[tokio::main]
async fn main() {
    // tracing_subscriber::registry()
    //     .with(tracing_subscriber::EnvFilter::new(
    //         std::env::var("RUST_LOG")
    //             .unwrap_or_else(|_| "example_key_value_store=debug,tower_http=debug".into()),
    //     ))
    //     .with(tracing_subscriber::fmt::layer())
    //     .init();

    let shared_state = SharedState::default();

    // Build our application by composing routes
    let app = Router::new()
        .route("/register", get(register))
        .route("/ping/:id", get(ping))
        .layer(Extension(shared_state));

    // Run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    // tracing::debug!("listening on {}", addr);
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

// Pings the server to state that you are still alive
async fn ping(Path(id): Path<String>, Extension(state): Extension<SharedState>) -> String {
    let now = Instant::now();

    let mut app_state = state.write().unwrap();
    let last_pinged_time = match app_state.db.get(&id) {
        Some(last_date_time) => *last_date_time,
        None => return format!("{} is not registered", id),
    };
    let time_elapsed = now - last_pinged_time;

    if time_elapsed > Duration::from_secs(10) {
        return format!(
            "Too late to ping! You took {} seconds \n{:?}\n {:?}",
            time_elapsed.as_secs(),
            last_pinged_time,
            now,
        );
    }
    app_state.db.insert(id, now);
    return format!("Ping successful! {} seconds", time_elapsed.as_secs());
}

// Registers a user who can now ping
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
        "<h1>ID: {} <br>You are number {} in the queue</h1><br> Put this in url:<br>
        http://localhost:3000/ping/{id} <br> {:?}
        ",
        id.to_string(),
        num_entries,
        now,
    ))
}
