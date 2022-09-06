use crate::{
    constants::{ACTIVE_ZONE_CHECKIN_DEADLINE, HISTORY_RECEIPTS_COUNT},
    SessionId, SharedState, SharedTranscript,
};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum_extra::response::ErasedJson;
use http::StatusCode;
use serde::Serialize;
use small_powers_of_tau::sdk::TranscriptJSON;
use std::time::Instant;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct StatusResponse {
    state: String,
    queue_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    position: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadline: Option<usize>,
}

impl StatusResponse {
    pub fn new(state: String, queue_size: usize) -> Self {
        Self {
            state,
            queue_size,
            position: None,
            deadline: None,
        }
    }
}

impl IntoResponse for StatusResponse {
    fn into_response(self) -> axum::response::Response {
        let status = StatusCode::OK;
        (status, Json(self)).into_response()
    }
}

pub(crate) async fn status(
    session_id: Option<SessionId>,
    Extension(store): Extension<SharedState>,
    Extension(shared_transcript): Extension<SharedTranscript>,
) -> StatusResponse {
    let transcript = shared_transcript.read().await;

    let mut status_response = {
        let app_state = store.read().await;
        let summary = transcript.sub_ceremonies[0].summary();

        let num_participants = app_state.queue.num_participants();

        StatusResponse::new(summary, num_participants)
    };

    let id = match session_id {
        Some(id) => id,
        None => return status_response,
    };
    let mut app_state = store.write().await;

    match app_state.queue.find_participant(&id) {
        Some(position) => {
            let session_info = app_state.sessions.get_mut(&id).unwrap();

            session_info.last_ping_time = Instant::now();
            // We require everyone in the queue to checkin
            // because we limit the queue size to be manageable.
            status_response.position = Some(position + 1);
            status_response.deadline = Some(ACTIVE_ZONE_CHECKIN_DEADLINE);
        }
        None => {
            // This is for when a user logs in, but wants to check the status without
            // joining the queue
        }
    }

    return status_response;
}

pub struct HistoryResponse {
    // Receipts are returned in encoded format
    receipts: Vec<String>,
}

impl IntoResponse for HistoryResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self.receipts)).into_response()
    }
}

pub(crate) async fn history(Extension(store): Extension<SharedState>) -> HistoryResponse {
    // Returns the last `HISTORY_RECEIPTS_COUNT` contributions
    let app_state = store.read().await;

    let receipts: Vec<_> = app_state
        .receipts
        .iter()
        .rev()
        .take(HISTORY_RECEIPTS_COUNT)
        .map(|receipt| receipt.encode().unwrap())
        .collect();

    HistoryResponse { receipts }
}

pub struct CurrentTranscriptResponse {
    transcript: TranscriptJSON,
}

impl IntoResponse for CurrentTranscriptResponse {
    fn into_response(self) -> axum::response::Response {
        // We use ErasedJson for the case that one wants to view the
        // transcript in the browser and it needs to be prettified
        (StatusCode::OK, ErasedJson::pretty(self.transcript)).into_response()
    }
}

pub(crate) async fn current_transcript(
    Extension(transcript): Extension<SharedTranscript>,
) -> CurrentTranscriptResponse {
    let app_state = transcript.read().await;
    let transcript_json = TranscriptJSON::from(&*app_state);
    CurrentTranscriptResponse {
        transcript: transcript_json,
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use small_powers_of_tau::sdk::Transcript;
    use std::env;

    use crate::{
        api::v1::queue::queue_join,
        jwt::{IdToken, Receipt},
        sessions::SessionInfo,
        SharedTranscript,
    };

    #[tokio::test]
    async fn current_transcript_mock() {
        let expected_transcript = SharedTranscript::default();

        let response = current_transcript(Extension(expected_transcript.clone())).await;
        //
        let expected_transcript = expected_transcript.read().await;

        let got_transcript_json = &response.transcript;
        let expected_transcript_json = TranscriptJSON::from(&*expected_transcript);

        assert_eq!(
            serde_json::to_string(got_transcript_json).unwrap(),
            serde_json::to_string(&expected_transcript_json).unwrap()
        )
    }
    #[tokio::test]
    async fn history_mock() {
        env::set_var("JWT_SECRET", "password");

        let state = SharedState::default();
        // Should be empty
        let response = history(Extension(state.clone())).await;
        assert!(response.receipts.is_empty());

        let to_add = HISTORY_RECEIPTS_COUNT * 2;

        {
            let mut state = state.write().await;

            for i in 0..to_add {
                let receipt = Receipt {
                    id_token: crate::jwt::IdToken {
                        sub: i.to_string(),
                        nickname: i.to_string(),
                        provider: i.to_string(),
                        exp: i as u64,
                    },
                    witness: Default::default(),
                };

                state.receipts.push(receipt);
            }
        }

        // Make another request
        let response = history(Extension(state.clone())).await;

        let state = state.read().await;

        assert_eq!(response.receipts.len(), HISTORY_RECEIPTS_COUNT);
        assert_eq!(state.receipts.len(), to_add);

        for (receipt_response, receipt_state) in response
            .receipts
            .into_iter()
            .zip(state.receipts.iter().rev())
        {
            assert_eq!(receipt_response, receipt_state.encode().unwrap())
        }
    }

    #[tokio::test]
    async fn status_mock_empty_queue() {
        let state = SharedState::default();
        let transcript = SharedTranscript::default();

        // TODO: We can put a summary method on `Transcript`
        let summary = transcript.clone().read().await.sub_ceremonies[0].summary();

        let response = status(None, Extension(state), Extension(transcript)).await;
        // Since no session id was given, deadline and position will be None
        let position = None;
        let deadline = None;
        // No-one has been added to the queue yet
        let queue_size = 0;

        let expected_response = StatusResponse {
            state: summary,
            queue_size,
            position,
            deadline,
        };
        assert_eq!(expected_response, response);
    }
    #[tokio::test]
    async fn status_mock_session_id() {
        let state = SharedState::default();
        let transcript = SharedTranscript::default();
        let summary = transcript.clone().read().await.sub_ceremonies[0].summary();

        let session_id = SessionId::new();

        {
            // When a user is successful authorised
            // they are given a session Id. Here we emulate that
            state.clone().write().await.sessions.insert(
                session_id.clone(),
                SessionInfo {
                    token: IdToken {
                        sub: String::default(),
                        nickname: String::default(),
                        provider: String::default(),
                        exp: 0,
                    },
                    last_ping_time: Instant::now(),
                },
            );
            // Add user to the queue
            queue_join(session_id.clone(), Extension(state.clone())).await;
        }

        let response = status(Some(session_id), Extension(state), Extension(transcript)).await;

        let position = Some(1);
        let deadline = Some(ACTIVE_ZONE_CHECKIN_DEADLINE);
        let queue_size = 1;

        let expected_response = StatusResponse {
            state: summary,
            queue_size,
            position,
            deadline,
        };
        assert_eq!(expected_response, response);
    }
}
