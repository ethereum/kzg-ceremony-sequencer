use axum::{response::IntoResponse, Extension, Json};
use http::StatusCode;
use serde_json::json;

use crate::SharedState;

use super::auth::tokens::IdToken;

// Check the status of the ceremony.
// If the user passes in their token, then we also get their position
pub(crate) async fn status(
    user: Option<IdToken>,
    Extension(store): Extension<SharedState>,
) -> impl IntoResponse {
    let app_state = store.read().await;

    // This will be the SRS, for now we are updating numbers
    let current_program_state = app_state.program_state;

    let num_participants = app_state.db.len();

    let status_code = StatusCode::OK;

    let json_values = json!({ "state": current_program_state , "queue_size" : num_participants});
    // TODO: check if the user is available and get their cue position
    match user {
        Some(u) => (status_code, Json(json_values)),
        None => return (status_code, Json(json_values)),
    }
}
