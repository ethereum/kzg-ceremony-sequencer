use crate::{constants::COMPUTE_DEADLINE, SessionId, SharedState};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use serde_json::json;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum SlotJoinResponse {
    UnknownSessionId,
    SlotIsFull,
    Success,
}

impl IntoResponse for SlotJoinResponse {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            SlotJoinResponse::UnknownSessionId => {
                let body = Json(json!({
                    "error": "unknown session id",
                }));
                (StatusCode::BAD_REQUEST, body)
            }

            SlotJoinResponse::SlotIsFull => {
                let body = Json(json!({
                    "error": "slot is full",
                }));
                (StatusCode::SERVICE_UNAVAILABLE, body)
            }
            SlotJoinResponse::Success => {
                let body = Json(json!({
                    "success": "successfully reserved the contribution spot",
                }));
                (StatusCode::OK, body)
            }
        };

        (status, body).into_response()
    }
}

pub(crate) async fn slot_join(
    session_id: SessionId,
    Extension(store): Extension<SharedState>,
) -> SlotJoinResponse {
    let store_clone = store.clone();
    let app_state = &mut store.write().await;

    // 1. Check if this is a valid session. If so, we log the ping time
    {
        let info = match app_state.lobby.get_mut(&session_id) {
            Some(info) => info,
            None => {
                return SlotJoinResponse::UnknownSessionId;
            }
        };
        info.last_ping_time = Instant::now();
    }

    // Check if the contribution slot is taken is full
    if app_state.participant.is_some() {
        return SlotJoinResponse::SlotIsFull;
    }

    {
        // This user now reserves this spot. This also removes them from the lobby
        app_state.reserve_contribution_spot(session_id.clone());
        // Start a timer to remove this user if they go over the `COMPUTE_DEADLINE`
        tokio::spawn(async move {
            clear_spot_on_interval(store_clone, session_id).await;
        });
    }
    return SlotJoinResponse::Success;
}

// Clears the contribution spot on `COMPUTE_DEADLINE` interval
// We use the session_id to avoid needing a channel to check if
pub(crate) async fn clear_spot_on_interval(state: SharedState, session_id: SessionId) {
    // let mut interval = tokio::time::interval(Duration::from_secs(COMPUTE_DEADLINE as u64));
    // interval.tick().await;
    tokio::time::sleep(Duration::from_secs(COMPUTE_DEADLINE as u64)).await;
    // tokio::thread::sleep(Duration::from_secs(COMPUTE_DEADLINE as u64));
    {
        // Check if the contributor has already left the position
        if let Some((participant_session_id, _)) = &state.read().await.participant {
            //
            if participant_session_id != &session_id {
                // Abort, this means that the participant has already contributed and
                // the /contribute endpoint has removed them from the contribution spot
                return;
            }
        } else {
            return;
        }
    }
    println!(
        "User with session id {} took too long to contribute",
        &session_id.to_string()
    );
    state.write().await.clear_contribution_spot();
}
