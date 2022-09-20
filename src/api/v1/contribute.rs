use std::sync::atomic::Ordering;

use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use kzg_ceremony_crypto::interface::{Contribution, Transcript};
use serde_json::json;

use crate::{
    io::transcript::write_transcript_file,
    jwt::{errors::JwtError, Receipt},
    keys::SharedKeys,
    lobby::{clear_current_contributor, SharedContributorState},
    storage::PersistentStorage,
    Options, SessionId, SharedCeremonyStatus, SharedTranscript,
};

pub struct ContributeReceipt {
    encoded_receipt_token: String,
}

impl IntoResponse for ContributeReceipt {
    fn into_response(self) -> Response {
        (StatusCode::OK, self.encoded_receipt_token).into_response()
    }
}

pub enum ContributeError {
    NotUsersTurn,
    InvalidContribution,
    Auth(JwtError),
}

impl IntoResponse for ContributeError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::NotUsersTurn => {
                let body = Json(json!({"error" : "not your turn to participate"}));
                (StatusCode::BAD_REQUEST, body)
            }
            Self::InvalidContribution => {
                let body = Json(json!({"error" : "contribution invalid"}));
                (StatusCode::BAD_REQUEST, body)
            }
            Self::Auth(err) => return err.into_response(),
        };

        (status, body).into_response()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn contribute<T>(
    session_id: SessionId,
    Json(contribution): Json<T::ContributionType>,
    Extension(contributor_state): Extension<SharedContributorState>,
    Extension(options): Extension<Options>,
    Extension(shared_transcript): Extension<SharedTranscript<T>>,
    Extension(storage): Extension<PersistentStorage>,
    Extension(num_contributions): Extension<SharedCeremonyStatus>,
    Extension(keys): Extension<SharedKeys>,
) -> Result<ContributeReceipt, ContributeError>
where
    T: Transcript + Send + Sync + 'static,
    T::ContributionType: Send,
    <<T as Transcript>::ContributionType as Contribution>::Receipt: Send,
{
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
    {
        let transcript = shared_transcript.read().await;
        if transcript.verify_contribution(&contribution).is_err() {
            clear_current_contributor(contributor_state).await;
            storage
                .expire_contribution(id_token.unique_identifier())
                .await;
            return Err(ContributeError::InvalidContribution);
        }
    }

    {
        let mut transcript = shared_transcript.write().await;
        *transcript = transcript.update(&contribution);
    }

    let receipt = {
        Receipt {
            id_token,
            witness: contribution.get_receipt(),
        }
    };

    let encoded_receipt_token = receipt.encode(&keys).map_err(ContributeError::Auth)?;

    write_transcript_file(options.transcript, shared_transcript).await;

    let uid = contributor_state
        .read()
        .await
        .as_ref()
        .expect("participant is guaranteed non-empty here")
        .0
        .to_string();

    clear_current_contributor(contributor_state).await;
    storage.finish_contribution(&uid).await;
    num_contributions.fetch_add(1, Ordering::Relaxed);

    Ok(ContributeReceipt {
        encoded_receipt_token,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{atomic::AtomicUsize, Arc},
    };

    use axum::{Extension, Json};

    use crate::{
        api::v1::contribute::ContributeError,
        contribute, keys,
        keys::SharedKeys,
        lobby::SharedContributorState,
        read_transcript_file,
        storage::storage_client,
        test_transcript::{
            TestContribution::{InvalidContribution, ValidContribution},
            TestTranscript,
        },
        test_util::{create_test_session_info, test_options},
        Keys, SessionId, SharedTranscript,
    };

    async fn shared_keys() -> SharedKeys {
        Arc::new(
            Keys::new(&keys::Options {
                private_key: PathBuf::from("private.key"),
                public_key:  PathBuf::from("publickey.pem"),
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
        let result = contribute::<TestTranscript>(
            SessionId::new(),
            Json(ValidContribution(123)),
            Extension(contributor_state),
            Extension(opts),
            Extension(SharedTranscript::default()),
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
        let result = contribute::<TestTranscript>(
            participant,
            Json(InvalidContribution(123)),
            Extension(contributor_state),
            Extension(opts),
            Extension(SharedTranscript::default()),
            Extension(db),
            Extension(Arc::new(AtomicUsize::new(0))),
            Extension(shared_keys().await),
        )
        .await;
        assert!(matches!(result, Err(ContributeError::InvalidContribution)));
    }

    #[tokio::test]
    async fn accepts_valid_contribution() {
        let keys = shared_keys().await;
        let contributor_state = SharedContributorState::default();
        let participant = SessionId::new();
        let cfg = test_options();
        let db = storage_client(&cfg.storage).await;
        let shared_transcript = SharedTranscript::<TestTranscript>::default();

        *contributor_state.write().await =
            Some((participant.clone(), create_test_session_info(100)));
        let result = contribute::<TestTranscript>(
            participant.clone(),
            Json(ValidContribution(123)),
            Extension(contributor_state.clone()),
            Extension(cfg.clone()),
            Extension(shared_transcript.clone()),
            Extension(db.clone()),
            Extension(Arc::new(AtomicUsize::new(0))),
            Extension(keys.clone()),
        )
        .await;

        assert!(matches!(result, Ok(_)));
        let transcript =
            read_transcript_file::<TestTranscript>(cfg.transcript.transcript_file.clone()).await;
        assert_eq!(transcript, TestTranscript {
            initial:       ValidContribution(0),
            contributions: vec![ValidContribution(123)],
        });

        *contributor_state.write().await =
            Some((participant.clone(), create_test_session_info(100)));
        let result = contribute::<TestTranscript>(
            participant.clone(),
            Json(ValidContribution(175)),
            Extension(contributor_state.clone()),
            Extension(cfg.clone()),
            Extension(shared_transcript.clone()),
            Extension(db.clone()),
            Extension(Arc::new(AtomicUsize::new(0))),
            Extension(keys.clone()),
        )
        .await;

        assert!(matches!(result, Ok(_)));
        let transcript =
            read_transcript_file::<TestTranscript>(cfg.transcript.transcript_file.clone()).await;
        assert_eq!(transcript, TestTranscript {
            initial:       ValidContribution(0),
            contributions: vec![ValidContribution(123), ValidContribution(175)],
        });
    }
}
