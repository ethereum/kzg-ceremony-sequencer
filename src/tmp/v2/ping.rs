use crate::SharedState;

use super::auth::tokens::{AccessToken, RefreshToken};
use axum::{response::IntoResponse, Extension, Json};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PingPayload {
    access_token: String,
}

// User pings to tell us that he is still online
// they only need to do this once, they are at position <= 100
pub(crate) async fn online_ping(
    // TODO: can we pass both refresh token and access token in as parameters?
    // TODO: only one of them can be in the Auth header
    refresh_token: RefreshToken,
    Json(payload): Json<PingPayload>,
    Extension(store): Extension<SharedState>,
) -> impl IntoResponse {
    let app_state = store.write().await;
    // 1. First check if this refresh token has been revoked
    //
    let unique_id = match app_state.refresh_token_store.get(&refresh_token.id) {
        Some(id) => id,
        None => {
            // This refresh token was recently revoked
            // It has not expired just yet though
            let body = Json(json!({"error" : "invalid refresh token"}));
            return (StatusCode::BAD_REQUEST, body).into_response();
        }
    };

    //2. Now we can refresh the access token
    //
    let access_token = match AccessToken::refresh(&payload.access_token) {
        Ok(access_token) => access_token,
        Err(auth_err) => return auth_err.into_response(),
    };

    //2a. Check that refresh token is linked to access token
    if &access_token.sub != unique_id {
        let body = Json(json!({"error" : "access token and refresh token do not match"}));
        return (StatusCode::BAD_REQUEST, body).into_response();
    }

    let access_token_encoded = match access_token.encode() {
        Ok(access_token_encoded) => access_token_encoded,
        Err(err) => return err.into_response(),
    };

    let body = Json(json!({ "access_token": access_token_encoded }));
    return (StatusCode::OK, body).into_response();
}
