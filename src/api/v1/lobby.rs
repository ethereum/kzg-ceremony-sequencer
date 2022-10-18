use crate::{
    lobby::{ActiveContributorError, SharedLobbyState},
    storage::{PersistentStorage, StorageError},
    SessionId, SharedTranscript,
};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use kzg_ceremony_crypto::BatchContribution;
use serde::Serialize;
use serde_json::json;
use thiserror::Error;
use tokio::time::Instant;
use tracing::{info, info_span, warn};

#[derive(Debug, Error)]
pub enum TryContributeError {
    #[error("unknown session id")]
    UnknownSessionId,
    #[error("call came too early. rate limited")]
    RateLimited,
    #[error("another contribution in progress")]
    AnotherContributionInProgress,
    #[error("error in storage layer: {0}")]
    StorageError(#[from] StorageError),
}

impl From<ActiveContributorError> for TryContributeError {
    fn from(err: ActiveContributorError) -> Self {
        match err {
            ActiveContributorError::AnotherContributionInProgress
            | ActiveContributorError::NotUsersTurn => Self::AnotherContributionInProgress,
            ActiveContributorError::UserNotInLobby => Self::UnknownSessionId,
        }
    }
}

impl IntoResponse for TryContributeError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::UnknownSessionId => {
                let body = Json(json!({
                    "error": "unknown session id",
                }));
                (StatusCode::UNAUTHORIZED, body)
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
            Self::StorageError(err) => return err.into_response(),
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

pub async fn try_contribute(
    session_id: SessionId,
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(storage): Extension<PersistentStorage>,
    Extension(transcript): Extension<SharedTranscript>,
    Extension(options): Extension<crate::Options>,
) -> Result<TryContributeResponse<BatchContribution>, TryContributeError> {
    let uid = lobby_state
        .modify_participant(&session_id, |mut info| {
            let now = Instant::now();
            let min_diff =
                options.lobby.lobby_checkin_frequency - options.lobby.lobby_checkin_tolerance;
            if !info.is_first_ping_attempt && now < info.last_ping_time + min_diff {
                return Err(TryContributeError::RateLimited);
            }
            info.is_first_ping_attempt = false;
            info.last_ping_time = now;
            Ok(info.token.unique_identifier().to_owned())
        })
        .await
        .unwrap_or_else(|| {
            warn!("user session not found");
            Err(TryContributeError::UnknownSessionId)
        })?;
    let span = info_span!("authenticated user", uid);
    let _s = span.enter();

    lobby_state
        .set_current_contributor(&session_id, options.lobby.compute_deadline, storage.clone())
        .await
        .map_err(|err| {
            warn!(err = %err, "couldn't set current contributor");
            TryContributeError::from(err)
        })?;

    info!("current contributor set");

    storage.insert_contributor(&uid).await?;
    let transcript = transcript.read().await;

    Ok(TryContributeResponse {
        contribution: transcript.contribution(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::v1::lobby::TryContributeError,
        storage::storage_client,
        test_util::{create_test_session_info, test_options},
        tests::test_transcript,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::sync::RwLock;

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn lobby_try_contribute_test() {
        let opts = test_options();
        let lobby_state = SharedLobbyState::default();
        let transcript = Arc::new(RwLock::new(test_transcript()));
        let db = storage_client(&opts.storage).await.unwrap();

        let session_id = SessionId::new();
        let other_session_id = SessionId::new();

        // no users in lobby
        let unknown_session_response = try_contribute(
            session_id.clone(),
            Extension(lobby_state.clone()),
            Extension(db.clone()),
            Extension(transcript.clone()),
            Extension(opts),
        )
        .await;
        assert!(matches!(
            unknown_session_response,
            Err(TryContributeError::UnknownSessionId)
        ));
        lobby_state
            .insert_participant(session_id.clone(), create_test_session_info(100))
            .await;
        lobby_state
            .insert_participant(other_session_id.clone(), create_test_session_info(100))
            .await;

        // "other participant" is contributing
        try_contribute(
            other_session_id.clone(),
            Extension(lobby_state.clone()),
            Extension(db.clone()),
            Extension(transcript.clone()),
            Extension(test_options()),
        )
        .await
        .unwrap();
        let contribution_in_progress_response = try_contribute(
            session_id.clone(),
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

        tokio::time::pause();

        // call the endpoint too soon - rate limited, other participant computing
        tokio::time::advance(Duration::from_secs(5)).await;
        let too_soon_response = try_contribute(
            session_id.clone(),
            Extension(lobby_state.clone()),
            Extension(db.clone()),
            Extension(transcript.clone()),
            Extension(test_options()),
        )
        .await;

        assert!(
            matches!(too_soon_response, Err(TryContributeError::RateLimited),),
            "response expected: Err(TryContributeError::RateLimited) actual: {:?}",
            too_soon_response
        );

        // "other participant" finished contributing
        lobby_state.clear_current_contributor().await;

        // call the endpoint too soon - rate limited, no one computing
        tokio::time::advance(Duration::from_secs(5)).await;
        let too_soon_response = try_contribute(
            session_id.clone(),
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
            Extension(lobby_state.clone()),
            Extension(db.clone()),
            Extension(transcript.clone()),
            Extension(test_options()),
        )
        .await;
        assert!(matches!(
            success_response,
            Ok(TryContributeResponse {
                contribution: BatchContribution { .. },
            })
        ));
    }
}
