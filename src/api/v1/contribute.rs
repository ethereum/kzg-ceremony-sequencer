use crate::{
    io::write_json_file,
    keys::{SharedKeys, Signature, SignatureError},
    lobby::SharedLobbyState,
    receipt::Receipt,
    storage::{PersistentStorage, StorageError},
    Engine, Options, SessionId, SharedCeremonyStatus, SharedTranscript,
};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum_extra::response::ErasedJson;
use http::StatusCode;
use kzg_ceremony_crypto::{BatchContribution, CeremoniesError, ErrorCode};
use serde::Serialize;
use std::sync::atomic::Ordering;
use strum::IntoStaticStr;
use thiserror::Error;
use tokio::task::JoinError;
use tracing::error;

#[derive(Serialize)]
pub struct ContributeReceipt {
    receipt: String,
    signature: Signature,
}

impl IntoResponse for ContributeReceipt {
    fn into_response(self) -> Response {
        (StatusCode::OK, ErasedJson::pretty(self)).into_response()
    }
}

#[derive(Debug, Error, IntoStaticStr)]
pub enum ContributeError {
    #[error("not your turn to participate")]
    NotUsersTurn,
    #[error("contribution invalid: {0}")]
    InvalidContribution(#[from] CeremoniesError),
    #[error("receipt signing error: {0}")]
    ReceiptSigning(SignatureError),
    #[error("storage error: {0}")]
    StorageError(#[from] StorageError),
    #[error("background task error: {0}")]
    TaskError(#[from] JoinError),
}

impl ErrorCode for ContributeError {
    fn to_error_code(&self) -> String {
        format!("ContributeError::{}", <&str>::from(self))
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn contribute(
    session_id: SessionId,
    Json(contribution): Json<BatchContribution>,
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(options): Extension<Options>,
    Extension(shared_transcript): Extension<SharedTranscript>,
    Extension(storage): Extension<PersistentStorage>,
    Extension(num_contributions): Extension<SharedCeremonyStatus>,
    Extension(keys): Extension<SharedKeys>,
) -> Result<ContributeReceipt, ContributeError> {
    // Handle the contribution in the background, so that request cancelation doesn't interrupt it.
    let res = tokio::spawn(async move {
        let id_token = lobby_state
            .begin_contributing(&session_id)
            .await
            .map_err(|_| ContributeError::NotUsersTurn)?
            .token;

        let result = {
            let mut transcript = shared_transcript.write().await;
            transcript
                .verify_add::<Engine>(contribution.clone(), id_token.identity.clone())
                .map_err(ContributeError::InvalidContribution)
        };

        if let Err(e) = result {
            lobby_state.clear_current_contributor().await;
            storage
                .expire_contribution(&id_token.unique_identifier())
                .await?;
            return Err(e);
        }

        let receipt = Receipt {
            identity: id_token.identity,
            witness: contribution.receipt(),
        };

        let (signed_msg, signature) = receipt
            .sign(&keys)
            .await
            .map_err(ContributeError::ReceiptSigning)?;

        write_json_file(
            options.transcript_file,
            options.transcript_in_progress_file,
            shared_transcript,
        )
        .await;

        lobby_state.clear_current_contributor().await;
        storage.finish_contribution(&session_id.0).await?;

        num_contributions.fetch_add(1, Ordering::Relaxed);

        Ok(ContributeReceipt {
            receipt: signed_msg,
            signature,
        })
    })
    .await
    .unwrap_or_else(|e| Err(ContributeError::TaskError(e)));
    if let Err(err) = &res {
        if matches!(
            err,
            ContributeError::ReceiptSigning(_)
                | ContributeError::StorageError(_)
                | ContributeError::TaskError(_)
        ) {
            error!(?err, "unexpected error recording contribution");
        }
    }
    res
}

pub async fn contribute_abort(
    session_id: SessionId,
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(storage): Extension<PersistentStorage>,
) -> Result<(), ContributeError> {
    tokio::spawn(async move {
        lobby_state
            .abort_contribution(&session_id)
            .await
            .map_err(|_| ContributeError::NotUsersTurn)?;
        storage.expire_contribution(&session_id.0).await?;
        Ok(())
    })
    .await
    .unwrap_or_else(|e| Err(ContributeError::TaskError(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::v1::{
            contribute::ContributeError,
            lobby::{try_contribute, TryContributeError, TryContributeResponse},
        },
        contribute,
        io::read_json_file,
        keys,
        keys::SharedKeys,
        lobby::SharedLobbyState,
        storage::storage_client,
        test_util::{create_test_session_info, test_options},
        tests::{invalid_contribution, test_transcript, valid_contribution},
        Keys, SessionId,
    };
    use axum::{Extension, Json};
    use clap::Parser;
    use kzg_ceremony_crypto::{signature::identity::Identity, BatchTranscript};
    use std::{
        sync::{atomic::AtomicUsize, Arc},
        time::Duration,
    };
    use tokio::sync::RwLock;

    fn shared_keys() -> SharedKeys {
        let options = keys::Options::parse_from(Vec::<&str>::new());
        Arc::new(Keys::new(&options).unwrap())
    }

    #[tokio::test]
    async fn rejects_out_of_turn_contribution() {
        let opts = test_options();
        let db = storage_client(&opts.storage).await.unwrap();
        let lobby_state = SharedLobbyState::new(opts.lobby.clone());
        let transcript = test_transcript();
        let contrbution = valid_contribution(&transcript, 1);
        let result = contribute(
            SessionId::new(),
            Json(contrbution),
            Extension(lobby_state),
            Extension(opts),
            Extension(Arc::new(RwLock::new(transcript))),
            Extension(db),
            Extension(Arc::new(AtomicUsize::new(0))),
            Extension(shared_keys()),
        )
        .await;
        assert!(matches!(result, Err(ContributeError::NotUsersTurn)));
    }

    #[tokio::test]
    async fn rejects_invalid_contribution() {
        let opts = test_options();
        let db = storage_client(&opts.storage).await.unwrap();
        let lobby_state = SharedLobbyState::new(opts.lobby.clone());
        let participant = SessionId::new();
        lobby_state
            .insert_session(participant.clone(), create_test_session_info(100))
            .await
            .unwrap();
        lobby_state.enter_lobby(&participant).await.unwrap();
        lobby_state
            .set_current_contributor(&participant, opts.lobby.compute_deadline, db.clone())
            .await
            .unwrap();
        let transcript = test_transcript();
        let contribution = invalid_contribution(&transcript, 1);
        let result = contribute(
            participant,
            Json(contribution),
            Extension(lobby_state),
            Extension(opts),
            Extension(Arc::new(RwLock::new(transcript))),
            Extension(db),
            Extension(Arc::new(AtomicUsize::new(0))),
            Extension(shared_keys()),
        )
        .await;
        assert!(matches!(
            result,
            Err(ContributeError::InvalidContribution(_))
        ));
    }

    #[tokio::test]
    async fn accepts_valid_contribution() {
        let cfg = test_options();
        let keys = shared_keys();
        let lobby_state = SharedLobbyState::new(cfg.lobby.clone());
        let participant = SessionId::new();
        let db = storage_client(&cfg.storage).await.unwrap();
        let transcript = test_transcript();
        let contribution_1 = valid_contribution(&transcript, 1);
        let transcript_1 = {
            let mut transcript = transcript.clone();
            transcript
                .verify_add::<Engine>(
                    contribution_1.clone(),
                    Identity::Github {
                        id: 1234,
                        username: "test_user".to_string(),
                    },
                )
                .unwrap();
            transcript
        };
        let contribution_2 = valid_contribution(&transcript_1, 2);
        let transcript_2 = {
            let mut transcript = transcript_1.clone();
            transcript
                .verify_add::<Engine>(
                    contribution_2.clone(),
                    Identity::Github {
                        id: 1234,
                        username: "test_user".to_string(),
                    },
                )
                .unwrap();
            transcript
        };
        let shared_transcript = Arc::new(RwLock::new(transcript));

        lobby_state
            .insert_session(participant.clone(), create_test_session_info(100))
            .await
            .unwrap();
        lobby_state.enter_lobby(&participant).await.unwrap();

        lobby_state
            .set_current_contributor(&participant, cfg.lobby.compute_deadline, db.clone())
            .await
            .unwrap();
        let result = contribute(
            participant.clone(),
            Json(contribution_1),
            Extension(lobby_state.clone()),
            Extension(cfg.clone()),
            Extension(shared_transcript.clone()),
            Extension(db.clone()),
            Extension(Arc::new(AtomicUsize::new(0))),
            Extension(keys.clone()),
        )
        .await;

        assert!(matches!(result, Ok(_)));
        let transcript = read_json_file::<BatchTranscript>(cfg.transcript_file.clone()).await;
        assert_eq!(transcript, transcript_1);
        lobby_state
            .insert_session(participant.clone(), create_test_session_info(100))
            .await
            .unwrap();
        lobby_state.enter_lobby(&participant).await.unwrap();
        lobby_state
            .set_current_contributor(&participant, cfg.lobby.compute_deadline, db.clone())
            .await
            .unwrap();
        let result = contribute(
            participant.clone(),
            Json(contribution_2),
            Extension(lobby_state),
            Extension(cfg.clone()),
            Extension(shared_transcript.clone()),
            Extension(db.clone()),
            Extension(Arc::new(AtomicUsize::new(0))),
            Extension(keys.clone()),
        )
        .await;

        assert!(matches!(result, Ok(_)));
        let transcript = read_json_file::<BatchTranscript>(cfg.transcript_file.clone()).await;
        assert_eq!(transcript, transcript_2);
    }

    #[tokio::test]
    async fn aborts_contribution() {
        let opts = test_options();
        let lobby_state = SharedLobbyState::new(opts.lobby.clone());
        let transcript = Arc::new(RwLock::new(test_transcript()));
        let db = storage_client(&opts.storage).await.unwrap();

        let session_id = SessionId::new();
        let other_session_id = SessionId::new();

        lobby_state
            .insert_session(session_id.clone(), create_test_session_info(100))
            .await
            .unwrap();
        lobby_state.enter_lobby(&session_id).await.unwrap();
        lobby_state
            .insert_session(other_session_id.clone(), create_test_session_info(100))
            .await
            .unwrap();
        lobby_state.enter_lobby(&other_session_id).await.unwrap();

        lobby_state
            .set_current_contributor(&session_id, opts.lobby.compute_deadline, db.clone())
            .await
            .unwrap();

        let contribution_in_progress_response = try_contribute(
            other_session_id.clone(),
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

        contribute_abort(
            session_id,
            Extension(lobby_state.clone()),
            Extension(db.clone()),
        )
        .await
        .unwrap();

        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(30)).await;

        let success_response = try_contribute(
            other_session_id.clone(),
            Extension(lobby_state.clone()),
            Extension(db.clone()),
            Extension(transcript.clone()),
            Extension(test_options()),
        )
        .await;

        assert!(matches!(success_response, Ok(TryContributeResponse { .. })));
    }
}
