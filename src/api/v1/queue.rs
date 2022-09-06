use crate::{constants::MAX_QUEUE_SIZE, SessionId, SharedState};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use serde_json::json;
use std::time::Instant;
#[derive(Debug)]
pub enum QueueJoinResponse {
    UnknownSessionId,
    UserAlreadyContributed,
    UserAlreadyInQueue,
    QueueIsFull,
    Position(usize),
}

impl IntoResponse for QueueJoinResponse {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            QueueJoinResponse::UnknownSessionId => {
                let body = Json(json!({
                    "error": "unknown session id",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            QueueJoinResponse::UserAlreadyContributed => {
                let body = Json(json!({ "error": format!("user has already contributed") }));
                (StatusCode::INTERNAL_SERVER_ERROR, body)
            }
            QueueJoinResponse::UserAlreadyInQueue => {
                let body = Json(json!({
                    "error": "user is already in queue",
                }));
                (StatusCode::CONFLICT, body)
            }
            QueueJoinResponse::Position(position) => {
                let body = Json(json!({
                    "position": position,
                }));
                (StatusCode::OK, body)
            }
            QueueJoinResponse::QueueIsFull => {
                let body = Json(json!({
                    "error": "queue is full",
                }));
                (StatusCode::SERVICE_UNAVAILABLE, body)
            }
        };

        (status, body).into_response()
    }
}

// Join the queue
// A user should already have a session_id from going through the auth
// process
pub(crate) async fn queue_join(
    session_id: SessionId,
    Extension(store): Extension<SharedState>,
) -> QueueJoinResponse {
    let app_state = &mut store.write().await;

    // 1. Check if this is a valid session
    let info = match app_state.sessions.get_mut(&session_id) {
        Some(info) => info,
        None => {
            return QueueJoinResponse::UnknownSessionId;
        }
    };
    info.last_ping_time = Instant::now();
    let sub = info.token.sub.clone();

    // Check if the queue is full
    if app_state.queue.num_participants() >= MAX_QUEUE_SIZE {
        return QueueJoinResponse::QueueIsFull;
    }
    // Check if they've already contributed
    if let Some(_) = app_state.finished_contribution.get(&sub) {
        return QueueJoinResponse::UserAlreadyContributed;
    }

    // Check if this user is already in the queue
    if app_state.queue.is_already_in_queue(&session_id) {
        return QueueJoinResponse::UserAlreadyInQueue;
    };

    let position = app_state
        .queue
        .add_participant(session_id)
        .expect("error: session id already added");

    // TODO: we could allow a user with the same id and different session id to
    // TODO replace their session id with a different one

    QueueJoinResponse::Position(position)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use axum::Extension;

    use super::{queue_join, QueueJoinResponse};
    use crate::{
        constants::MAX_QUEUE_SIZE,
        jwt::IdToken,
        sessions::{SessionId, SessionInfo},
        SharedState,
    };

    #[tokio::test]
    async fn queue_join_mock_full() {
        let state = SharedState::default();

        let session_ids: Vec<_> = (0..MAX_QUEUE_SIZE)
            .into_iter()
            .map(|_| SessionId::new())
            .collect();

        let dummy_session_info = SessionInfo {
            token: IdToken {
                sub: String::default(),
                nickname: String::default(),
                provider: String::default(),
                exp: 0,
            },
            last_ping_time: Instant::now(),
        };

        // Add all sessions into the state, as if users were successfully authorised
        {
            let mut state = state.write().await;

            for id in &session_ids {
                state
                    .sessions
                    .insert(id.clone(), dummy_session_info.clone());
            }
        }

        // Add users to queue -- Note, we add up to the max queue size
        {
            for id in &session_ids {
                match queue_join(id.clone(), Extension(state.clone())).await {
                    QueueJoinResponse::UnknownSessionId
                    | QueueJoinResponse::UserAlreadyContributed
                    | QueueJoinResponse::UserAlreadyInQueue
                    | QueueJoinResponse::QueueIsFull => unreachable!("unexpected variant"),
                    QueueJoinResponse::Position(_) => {}
                };
            }
        }

        // Adding one more user when we are at max
        {
            let cloned_state = state.clone();
            let mut cloned_state = cloned_state.write().await;
            let session_id = SessionId::new();
            cloned_state
                .sessions
                .insert(session_id.clone(), dummy_session_info.clone());
            drop(cloned_state);

            assert!(matches!(
                queue_join(session_id, Extension(state)).await,
                QueueJoinResponse::QueueIsFull
            ));
        }
    }
    #[tokio::test]
    async fn queue_join_mock_unknown() {
        let state = SharedState::default();

        let dummy_session_info = SessionInfo {
            token: IdToken {
                sub: String::default(),
                nickname: String::default(),
                provider: String::default(),
                exp: 0,
            },
            last_ping_time: Instant::now(),
        };

        // Add a participant whose session id is unknown

        let session_id = SessionId::new();
        let response = queue_join(session_id, Extension(state.clone())).await;
        assert!(matches!(response, QueueJoinResponse::UnknownSessionId));
    }
}
