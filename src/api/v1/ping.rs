use crate::{constants::ACTIVE_ZONE_CHECKIN_DEADLINE, SessionId, SharedState};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use serde_json::json;
use std::time::Instant;

pub enum PingResponse {
    InvalidSessionId,
    Success { deadline: usize },
}

impl IntoResponse for PingResponse {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            PingResponse::InvalidSessionId => {
                let body = Json(json!({"error" : "invalid session id"}));
                (StatusCode::BAD_REQUEST, body)
            }
            PingResponse::Success { deadline } => {
                let body = Json(json!({ "deadline": deadline }));
                (StatusCode::OK, body)
            }
        };
        (status, body).into_response()
    }
}

pub(crate) async fn online_ping(
    session_id: SessionId,
    Extension(store): Extension<SharedState>,
) -> impl IntoResponse {
    let mut app_state = store.write().await;
    // We could have users also say why they are pinging
    match app_state.sessions.get_mut(&session_id) {
        Some(session_info) => {
            session_info.last_ping_time = Instant::now();
            println!(
                "session_id : {:?} \n last_ping : {:?}",
                session_id, session_info.last_ping_time
            );
            session_info
        }
        None => {
            return PingResponse::InvalidSessionId;
        }
    };

    return PingResponse::Success {
        deadline: ACTIVE_ZONE_CHECKIN_DEADLINE,
    };
}
