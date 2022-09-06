use axum::{
    extract::Query,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use rand::{thread_rng, Rng};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(handler))
        .route("/hello/:name", get(json_hello));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

use axum::extract::Path;

async fn json_hello(Path(name): Path<String>) -> impl IntoResponse {
    let greeting = name.as_str();
    let hello = String::from("Hello ");

    (StatusCode::OK, Json(json!({ "message": hello + greeting })))
}

// `Deserialize` need be implemented to use with `Query` extractor.
#[derive(Deserialize)]
struct RangeParameters {
    start: usize,
    end: usize,
}

async fn handler(Query(range): Query<RangeParameters>) -> Html<String> {
    // Generate a random number in range parsed from query.

    if range.start > range.end {
        return Html(format!(
            "<h1>Start {} is more than End {}</h1>",
            range.start, range.end
        ));
    }
    let random_number = thread_rng().gen_range(range.start..range.end);

    // Send response in html format.
    Html(format!("<h1>Random Number: {}</h1>", random_number))
}
