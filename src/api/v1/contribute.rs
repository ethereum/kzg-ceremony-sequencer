use crate::{
    io::write_json_file,
    keys::{SharedKeys, Signature, SignatureError},
    lobby::{SharedContributorState, SharedLobbyState},
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
use kzg_ceremony_crypto::{BatchContribution, CeremoniesError};
use serde::Serialize;
use serde_json::json;
use std::sync::atomic::Ordering;
use thiserror::Error;

#[derive(Serialize)]
pub struct ContributeReceipt {
    receipt:   String,
    signature: Signature,
}

impl IntoResponse for ContributeReceipt {
    fn into_response(self) -> Response {
        (StatusCode::OK, ErasedJson::pretty(self)).into_response()
    }
}

#[derive(Debug, Error)]
pub enum ContributeError {
    #[error("not your turn to participate")]
    NotUsersTurn,
    #[error("contribution invalid: {0}")]
    InvalidContribution(#[from] CeremoniesError),
    #[error("signature error: {0}")]
    Signature(SignatureError),
    #[error("storage error: {0}")]
    StorageError(#[from] StorageError),
}

impl IntoResponse for ContributeError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::NotUsersTurn => {
                let body = Json(json!({"error" : "not your turn to participate"}));
                (StatusCode::BAD_REQUEST, body)
            }
            Self::InvalidContribution(e) => {
                let body = Json(json!({ "error": format!("contribution invalid: {}", e) }));
                (StatusCode::BAD_REQUEST, body)
            }
            Self::Signature(err) => return err.into_response(),
            Self::StorageError(err) => return err.into_response(),
        };

        (status, body).into_response()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn contribute(
    session_id: SessionId,
    Json(contribution): Json<BatchContribution>,
    Extension(contributor_state): Extension<SharedContributorState>,
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(options): Extension<Options>,
    Extension(shared_transcript): Extension<SharedTranscript>,
    Extension(storage): Extension<PersistentStorage>,
    Extension(num_contributions): Extension<SharedCeremonyStatus>,
    Extension(keys): Extension<SharedKeys>,
) -> Result<ContributeReceipt, ContributeError> {
    contributor_state
        .begin_contributing(&session_id)
        .await
        .map_err(|_| ContributeError::NotUsersTurn)?;

    let id_token = {
        let mut lobby = lobby_state.write().await;
        lobby.participants.remove(&session_id).unwrap().token
    };

    // 2. Check if the program state transition was correct
    let result = {
        let mut transcript = shared_transcript.write().await;
        transcript
            .verify_add::<Engine>(contribution.clone())
            .map_err(ContributeError::InvalidContribution)
    };
    if let Err(e) = result {
        contributor_state.clear().await;
        storage
            .expire_contribution(id_token.unique_identifier())
            .await?;
        return Err(e);
    }

    let receipt = Receipt {
        id_token,
        witness: contribution.receipt(),
    };

    let (signed_msg, signature) = receipt
        .sign(&keys)
        .await
        .map_err(ContributeError::Signature)?;

    write_json_file(
        options.transcript_file,
        options.transcript_in_progress_file,
        shared_transcript,
    )
    .await;

    contributor_state.clear().await;
    storage.finish_contribution(&session_id.0).await?;

    num_contributions.fetch_add(1, Ordering::Relaxed);

    Ok(ContributeReceipt {
        receipt: signed_msg,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::v1::contribute::ContributeError,
        contribute,
        io::read_json_file,
        keys,
        keys::SharedKeys,
        lobby::SharedContributorState,
        storage::storage_client,
        test_util::{create_test_session_info, test_options},
        tests::{invalid_contribution, test_transcript, valid_contribution},
        Keys, SessionId,
    };
    use axum::{Extension, Json};
    use clap::Parser;
    use kzg_ceremony_crypto::BatchTranscript;
    use std::sync::{atomic::AtomicUsize, Arc};
    use tokio::sync::RwLock;

    fn shared_keys() -> SharedKeys {
        let options = keys::Options::parse_from(Vec::<&str>::new());
        Arc::new(Keys::new(&options).unwrap())
    }

    #[tokio::test]
    async fn rejects_out_of_turn_contribution() {
        let opts = test_options();
        let db = storage_client(&opts.storage).await.unwrap();
        let contributor_state = SharedContributorState::default();
        let lobby_state = SharedLobbyState::default();
        let transcript = test_transcript();
        let contrbution = valid_contribution(&transcript, 1);
        let result = contribute(
            SessionId::new(),
            Json(contrbution),
            Extension(contributor_state),
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
        let contributor_state = SharedContributorState::default();
        let lobby_state = SharedLobbyState::default();
        let participant = SessionId::new();
        {
            let mut lobby = lobby_state.write().await;
            lobby
                .participants
                .insert(participant.clone(), create_test_session_info(100));
        }
        contributor_state
            .set_current_contributor(&participant, opts.lobby.compute_deadline, db.clone())
            .await
            .unwrap();
        let transcript = test_transcript();
        let contribution = invalid_contribution(&transcript, 1);
        let result = contribute(
            participant,
            Json(contribution),
            Extension(contributor_state),
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
        let keys = shared_keys();
        let contributor_state = SharedContributorState::default();
        let lobby_state = SharedLobbyState::default();
        let participant = SessionId::new();
        let cfg = test_options();
        let db = storage_client(&cfg.storage).await.unwrap();
        let transcript = test_transcript();
        let contribution_1 = valid_contribution(&transcript, 1);
        let transcript_1 = {
            let mut transcript = transcript.clone();
            transcript
                .verify_add::<Engine>(contribution_1.clone())
                .unwrap();
            transcript
        };
        let contribution_2 = valid_contribution(&transcript_1, 2);
        let transcript_2 = {
            let mut transcript = transcript_1.clone();
            transcript
                .verify_add::<Engine>(contribution_2.clone())
                .unwrap();
            transcript
        };
        let shared_transcript = Arc::new(RwLock::new(transcript));

        {
            let mut lobby = lobby_state.write().await;
            lobby
                .participants
                .insert(participant.clone(), create_test_session_info(100));
        }
        contributor_state
            .set_current_contributor(&participant, cfg.lobby.compute_deadline, db.clone())
            .await
            .unwrap();
        let result = contribute(
            participant.clone(),
            Json(contribution_1),
            Extension(contributor_state.clone()),
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
        {
            let mut lobby = lobby_state.write().await;
            lobby
                .participants
                .insert(participant.clone(), create_test_session_info(100));
        }
        contributor_state
            .set_current_contributor(&participant, cfg.lobby.compute_deadline, db.clone())
            .await
            .unwrap();
        let result = contribute(
            participant.clone(),
            Json(contribution_2),
            Extension(contributor_state.clone()),
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
}
