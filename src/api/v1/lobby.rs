use crate::{constants::{COMPUTE_DEADLINE, LOBBY_CHECKIN_FREQUENCY_SEC, LOBBY_CHECKIN_TOLERANCE_SEC}, SessionId, SharedState, SharedTranscript};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use serde_json::json;
use tokio::time::{Duration, Instant};
use small_powers_of_tau::sdk::TranscriptJSON;

#[derive(Debug)]
pub enum TryContributeResponse {
    UnknownSessionId,
    RateLimited,
    AnotherContributionInProgress,
    Success(TranscriptJSON),
}

impl IntoResponse for TryContributeResponse {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            TryContributeResponse::UnknownSessionId => {
                let body = Json(json!({
                    "error": "unknown session id",
                }));
                (StatusCode::BAD_REQUEST, body)
            }

            TryContributeResponse::RateLimited => {
                let body = Json(json!({
                    "error": "call came too early. rate limited",
                }));
                (StatusCode::BAD_REQUEST, body)
            }

            TryContributeResponse::AnotherContributionInProgress => {
                let body = Json(json!({
                    "message": "another contribution in progress",
                }));
                (StatusCode::OK, body)
            }

            TryContributeResponse::Success(transcript) => {
                let body = Json(json!({
                    "state": transcript,
                }));
                (StatusCode::OK, body)
            }
        };

        (status, body).into_response()
    }
}

pub(crate) async fn try_contribute(
    session_id: SessionId,
    Extension(store): Extension<SharedState>,
    Extension(transcript): Extension<SharedTranscript>,
) -> TryContributeResponse {
    let store_clone = store.clone();
    let app_state = &mut store.write().await;

    // 1. Check if this is a valid session. If so, we log the ping time
    {
        let info = match app_state.lobby.get_mut(&session_id) {
            Some(info) => info,
            None => {
                return TryContributeResponse::UnknownSessionId;
            }
        };

        let min_diff = Duration::from_secs(
            (LOBBY_CHECKIN_FREQUENCY_SEC - LOBBY_CHECKIN_TOLERANCE_SEC) as u64
        );


        let now = Instant::now();
        if !info.is_first_ping_attempt && now < info.last_ping_time + min_diff {
            return TryContributeResponse::RateLimited;
        }

        info.is_first_ping_attempt = false;
        info.last_ping_time = now;
    }

    // Check if there is an existing contribution in progress
    if app_state.participant.is_some() {
        return TryContributeResponse::AnotherContributionInProgress;
    }

    {
        // This user now reserves this spot. This also removes them from the lobby
        app_state.set_current_contributor(session_id.clone());
        // Start a timer to remove this user if they go over the `COMPUTE_DEADLINE`
        tokio::spawn(async move {
            remove_participant_on_deadline(store_clone, session_id).await;
        });
    }

    let transcript = transcript.read().await;
    let transcript_json = TranscriptJSON::from(&*transcript);

    return TryContributeResponse::Success(transcript_json);
}

// Clears the contribution spot on `COMPUTE_DEADLINE` interval
// We use the session_id to avoid needing a channel to check if
pub(crate) async fn remove_participant_on_deadline(state: SharedState, session_id: SessionId) {
    tokio::time::sleep(Duration::from_secs(COMPUTE_DEADLINE as u64)).await;

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
    state.write().await.clear_current_contributor();
}

#[tokio::test]
async fn lobby_try_contribute_test() {
    use crate::test_util::create_test_session_info;

    // manually control time in tests
    tokio::time::pause();

    let shared_state = SharedState::default();
    let transcript = SharedTranscript::default();

    let session_id = SessionId::new();
    let other_session_id = SessionId::new();

    // no users in lobby
    let unknown_session_response = try_contribute(session_id.clone(), Extension(shared_state.clone()), Extension(transcript.clone())).await;
    assert!(matches!(unknown_session_response, TryContributeResponse::UnknownSessionId));

    // add two participants to lobby
    {
        let mut state = shared_state.write().await;
        state.lobby.insert(session_id.clone(), create_test_session_info(100));
        state.lobby.insert(other_session_id.clone(), create_test_session_info(100));
    }

    // "other participant" is contributing
    try_contribute(other_session_id.clone(), Extension(shared_state.clone()), Extension(transcript.clone())).await;
    let contribution_in_progress_response = try_contribute(session_id.clone(), Extension(shared_state.clone()), Extension(transcript.clone())).await;
    assert!(matches!(contribution_in_progress_response, TryContributeResponse::AnotherContributionInProgress));

    // call the endpoint too soon - rate limited, other participant computing
    tokio::time::advance(Duration::from_secs(5)).await;
    let too_soon_response = try_contribute(session_id.clone(), Extension(shared_state.clone()), Extension(transcript.clone())).await;
    assert!(matches!(too_soon_response, TryContributeResponse::RateLimited));

    // "other participant" finished contributing
    {
        let mut state = shared_state.write().await;
        state.participant = None;
    }

    // call the endpoint too soon - rate limited, no one computing
    tokio::time::advance(Duration::from_secs(5)).await;
    let too_soon_response = try_contribute(session_id.clone(), Extension(shared_state.clone()), Extension(transcript.clone())).await;
    assert!(matches!(too_soon_response, TryContributeResponse::RateLimited));
    
    // wait enough time to be able to contribute
    tokio::time::advance(Duration::from_secs(19)).await;
    let success_response = try_contribute(session_id.clone(), Extension(shared_state.clone()), Extension(transcript.clone())).await;
    assert!(matches!(success_response, TryContributeResponse::Success(_)));
}
