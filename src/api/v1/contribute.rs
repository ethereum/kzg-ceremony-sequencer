use crate::{
    eth_sign::{JwtError, Receipt},
    io::write_json_file,
    keys::{SharedKeys, Signature},
    lobby::{clear_current_contributor, SharedContributorState},
    storage::PersistentStorage,
    Engine, Options, SessionId, SharedCeremonyStatus, SharedTranscript,
};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum_extra::response::ErasedJson;
use http::StatusCode;
use kzg_ceremony_crypto::{BatchContribution, CeremoniesError, G2};
use serde::Serialize;
use serde_json::json;
use std::sync::atomic::Ordering;

#[derive(Serialize)]
pub struct ContributeReceipt<T: Serialize> {
    receipt:   Receipt<T>,
    signature: Signature,
}

impl<T: Serialize> IntoResponse for ContributeReceipt<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, ErasedJson::pretty(self)).into_response()
    }
}

pub enum ContributeError {
    NotUsersTurn,
    InvalidContribution(CeremoniesError),
    Auth(JwtError),
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
            Self::Auth(err) => return err.into_response(),
        };

        (status, body).into_response()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn contribute(
    session_id: SessionId,
    Json(contribution): Json<BatchContribution>,
    Extension(contributor_state): Extension<SharedContributorState>,
    Extension(options): Extension<Options>,
    Extension(shared_transcript): Extension<SharedTranscript>,
    Extension(storage): Extension<PersistentStorage>,
    Extension(num_contributions): Extension<SharedCeremonyStatus>,
    Extension(keys): Extension<SharedKeys>,
) -> Result<ContributeReceipt<Vec<G2>>, ContributeError> {
    // 1. Check if this person should be contributing
    let id_token = {
        let active_contributor = contributor_state.read().await;
        let (id, session_info) = active_contributor
            .as_ref()
            .ok_or(ContributeError::NotUsersTurn)?;
        if &session_id != id {
            return Err(ContributeError::NotUsersTurn);
        }
        session_info.token.clone()
    };

    // We also know that if they were in the lobby
    // then they did not participate already because
    // when we auth participants, this is checked

    // 2. Check if the program state transition was correct
    let result = {
        let mut transcript = shared_transcript.write().await;
        transcript
            .verify_add::<Engine>(contribution.clone())
            .map_err(ContributeError::InvalidContribution)
    };
    if let Err(e) = result {
        clear_current_contributor(contributor_state).await;
        storage
            .expire_contribution(id_token.unique_identifier())
            .await;
        return Err(e);
    }

    let receipt = Receipt {
        id_token,
        witness: contribution.receipt(),
    };

    let signature = receipt.sign(&keys).await.map_err(ContributeError::Auth)?;

    write_json_file(
        options.transcript_file,
        options.transcript_in_progress_file,
        shared_transcript,
    )
    .await;

    let uid = {
        let guard = contributor_state.read().await;
        guard
            .as_ref()
            .expect("participant is guaranteed non-empty here")
            .0
            .to_string()
    };

    clear_current_contributor(contributor_state).await;
    storage.finish_contribution(&uid).await;
    num_contributions.fetch_add(1, Ordering::Relaxed);

    Ok(ContributeReceipt { receipt, signature })
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
    use kzg_ceremony_crypto::BatchTranscript;
    use std::sync::{atomic::AtomicUsize, Arc};
    use tokio::sync::RwLock;

    async fn shared_keys() -> SharedKeys {
        Arc::new(
            Keys::new(&keys::Options {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon about"
                    .into(),
            })
            .await
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn rejects_out_of_turn_contribution() {
        let opts = test_options();
        let db = storage_client(&opts.storage).await;
        let contributor_state = SharedContributorState::default();
        let transcript = test_transcript();
        let contrbution = valid_contribution(&transcript, 1);
        let result = contribute(
            SessionId::new(),
            Json(contrbution),
            Extension(contributor_state),
            Extension(opts),
            Extension(Arc::new(RwLock::new(transcript))),
            Extension(db),
            Extension(Arc::new(AtomicUsize::new(0))),
            Extension(shared_keys().await),
        )
        .await;
        assert!(matches!(result, Err(ContributeError::NotUsersTurn)));
    }

    #[tokio::test]
    async fn rejects_invalid_contribution() {
        let opts = test_options();
        let db = storage_client(&opts.storage).await;
        let contributor_state = SharedContributorState::default();
        let participant = SessionId::new();
        *contributor_state.write().await =
            Some((participant.clone(), create_test_session_info(100)));
        let transcript = test_transcript();
        let contribution = invalid_contribution(&transcript, 1);
        let result = contribute(
            participant,
            Json(contribution),
            Extension(contributor_state),
            Extension(opts),
            Extension(Arc::new(RwLock::new(transcript))),
            Extension(db),
            Extension(Arc::new(AtomicUsize::new(0))),
            Extension(shared_keys().await),
        )
        .await;
        assert!(matches!(
            result,
            Err(ContributeError::InvalidContribution(_))
        ));
    }

    #[tokio::test]
    async fn accepts_valid_contribution() {
        let keys = shared_keys().await;
        let contributor_state = SharedContributorState::default();
        let participant = SessionId::new();
        let cfg = test_options();
        let db = storage_client(&cfg.storage).await;
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

        *contributor_state.write().await =
            Some((participant.clone(), create_test_session_info(100)));
        let result = contribute(
            participant.clone(),
            Json(contribution_1),
            Extension(contributor_state.clone()),
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

        *contributor_state.write().await =
            Some((participant.clone(), create_test_session_info(100)));
        let result = contribute(
            participant.clone(),
            Json(contribution_2),
            Extension(contributor_state.clone()),
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
