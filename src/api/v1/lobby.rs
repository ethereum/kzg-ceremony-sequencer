use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use kzg_ceremony_crypto::interface::Transcript;
use serde::Serialize;
use serde_json::json;
use tokio::time::Instant;

use crate::{
    lobby,
    lobby::{
        clear_current_contributor, set_current_contributor, SharedContributorState,
        SharedLobbyState,
    },
    storage::PersistentStorage,
    SessionId, SharedTranscript,
};

#[derive(Debug)]
pub enum TryContributeError {
    UnknownSessionId,
    RateLimited,
    AnotherContributionInProgress,
}

impl IntoResponse for TryContributeError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::UnknownSessionId => {
                let body = Json(json!({
                    "error": "unknown session id",
                }));
                (StatusCode::BAD_REQUEST, body)
            }

            Self::RateLimited => {
                let body = Json(json!({
                    "error": "call came too early. rate limited",
                }));
                (StatusCode::BAD_REQUEST, body)
            }

            Self::AnotherContributionInProgress => {
                let body = Json(json!({
                    "message": "another contribution in progress",
                }));
                (StatusCode::OK, body)
            }
        };

        (status, body).into_response()
    }
}

#[derive(Debug)]
pub struct TryContributeResponse<C> {
    contribution: C,
}

impl<C: Serialize> IntoResponse for TryContributeResponse<C> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self.contribution)).into_response()
    }
}

pub async fn try_contribute<T: Transcript + Send + Sync>(
    session_id: SessionId,
    Extension(contributor_state): Extension<SharedContributorState>,
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(storage): Extension<PersistentStorage>,
    Extension(transcript): Extension<SharedTranscript<T>>,
    Extension(options): Extension<crate::Options>,
) -> Result<TryContributeResponse<T::ContributionType>, TryContributeError> {
    let uid: String;

    // 1. Check if this is a valid session. If so, we log the ping time
    {
        let mut lobby = lobby_state.write().await;
        let info = lobby
            .participants
            .get_mut(&session_id)
            .ok_or(TryContributeError::UnknownSessionId)?;

        let min_diff =
            options.lobby.lobby_checkin_frequency - options.lobby.lobby_checkin_tolerance;

        let now = Instant::now();
        if !info.is_first_ping_attempt && now < info.last_ping_time + min_diff {
            return Err(TryContributeError::RateLimited);
        }

        info.is_first_ping_attempt = false;
        info.last_ping_time = now;

        uid = info.token.unique_identifier().to_owned();
    }

    {
        // Check if there is an existing contribution in progress
        let contributor = contributor_state.read().await;
        if contributor.is_some() {
            return Err(TryContributeError::AnotherContributionInProgress);
        }
    }

    // If this insertion fails, worst case we allow multiple contributions from the
    // same participant
    storage.insert_contributor(&uid).await;
    set_current_contributor(contributor_state.clone(), lobby_state, session_id.clone()).await;

    // Start a timer to remove this user if they go over the `COMPUTE_DEADLINE`
    tokio::spawn(async move {
        remove_participant_on_deadline(
            contributor_state,
            storage.clone(),
            session_id,
            uid,
            options.lobby,
        )
        .await;
    });

    let transcript = transcript.read().await;

    Ok(TryContributeResponse {
        contribution: transcript.get_contribution(),
    })
}

// Clears the contribution spot on `COMPUTE_DEADLINE` interval
// We use the session_id to avoid needing a channel to check if
pub async fn remove_participant_on_deadline(
    contributor_state: SharedContributorState,
    storage: PersistentStorage,
    session_id: SessionId,
    uid: String,
    options: lobby::Options,
) {
    tokio::time::sleep(options.compute_deadline).await;

    {
        // Check if the contributor has already left the position
        let contributor = contributor_state.read().await;
        if let Some((participant_session_id, _)) = contributor.as_ref() {
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

    storage.expire_contribution(&uid).await;
    clear_current_contributor(contributor_state).await;
}

#[cfg(test)]
use crate::test_util::test_options;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn lobby_try_contribute_test() {
    use crate::{
        storage::test_storage_client,
        test_transcript::{TestContribution, TestTranscript},
        test_util::create_test_session_info,
    };
    use std::time::Duration;

    let contributor_state = SharedContributorState::default();
    let lobby_state = SharedLobbyState::default();
    let transcript = SharedTranscript::<TestTranscript>::default();
    let db = test_storage_client().await;

    let session_id = SessionId::new();
    let other_session_id = SessionId::new();

    // manually control time in tests
    tokio::time::pause();

    // no users in lobby
    let unknown_session_response = try_contribute(
        session_id.clone(),
        Extension(contributor_state.clone()),
        Extension(lobby_state.clone()),
        Extension(db.clone()),
        Extension(transcript.clone()),
        Extension(test_options()),
    )
    .await;
    assert!(matches!(
        unknown_session_response,
        Err(TryContributeError::UnknownSessionId)
    ));

    // add two participants to lobby
    {
        let mut state = lobby_state.write().await;
        state
            .participants
            .insert(session_id.clone(), create_test_session_info(100));
        state
            .participants
            .insert(other_session_id.clone(), create_test_session_info(100));
    }

    // "other participant" is contributing
    try_contribute(
        other_session_id.clone(),
        Extension(contributor_state.clone()),
        Extension(lobby_state.clone()),
        Extension(db.clone()),
        Extension(transcript.clone()),
        Extension(test_options()),
    )
    .await
    .ok();
    let contribution_in_progress_response = try_contribute(
        session_id.clone(),
        Extension(contributor_state.clone()),
        Extension(lobby_state.clone()),
        Extension(db.clone()),
        Extension(transcript.clone()),
        Extension(test_options()),
    )
    .await;
    assert!(matches!(
        contribution_in_progress_response,
        Err(TryContributeError::AnotherContributionInProgress)
    ));

    // call the endpoint too soon - rate limited, other participant computing
    tokio::time::advance(Duration::from_secs(5)).await;
    let too_soon_response = try_contribute(
        session_id.clone(),
        Extension(contributor_state.clone()),
        Extension(lobby_state.clone()),
        Extension(db.clone()),
        Extension(transcript.clone()),
        Extension(test_options()),
    )
    .await;
    assert!(matches!(
        too_soon_response,
        Err(TryContributeError::RateLimited)
    ));

    // "other participant" finished contributing
    {
        let mut state = contributor_state.write().await;
        *state = None;
    }

    // call the endpoint too soon - rate limited, no one computing
    tokio::time::advance(Duration::from_secs(5)).await;
    let too_soon_response = try_contribute(
        session_id.clone(),
        Extension(contributor_state.clone()),
        Extension(lobby_state.clone()),
        Extension(db.clone()),
        Extension(transcript.clone()),
        Extension(test_options()),
    )
    .await;
    assert!(matches!(
        too_soon_response,
        Err(TryContributeError::RateLimited)
    ));

    // wait enough time to be able to contribute
    tokio::time::advance(Duration::from_secs(19)).await;
    let success_response = try_contribute(
        session_id.clone(),
        Extension(contributor_state.clone()),
        Extension(lobby_state.clone()),
        Extension(db.clone()),
        Extension(transcript.clone()),
        Extension(test_options()),
    )
    .await;
    assert!(matches!(
        success_response,
        Ok(TryContributeResponse {
            contribution: TestContribution::ValidContribution(0),
        })
    ));
}
