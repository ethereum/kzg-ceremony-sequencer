use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use serde_json::json;

use crate::{
    data::transcript::write_transcript_file,
    jwt::{errors::JwtError, Receipt},
    storage::PersistentStorage,
    AppConfig, Contribution, SessionId, SharedTranscript, Transcript, lobby::{SharedContributorState, clear_current_contributor},
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

pub async fn contribute<T>(
    session_id: SessionId,
    Json(contribution): Json<T::ContributionType>,
    Extension(contributor_state): Extension<SharedContributorState>,
    Extension(config): Extension<AppConfig>,
    Extension(shared_transcript): Extension<SharedTranscript<T>>,
    Extension(storage): Extension<PersistentStorage>,
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

    let encoded_receipt_token = receipt.encode().map_err(ContributeError::Auth)?;

    write_transcript_file(
        config.transcript_file,
        config.transcript_in_progress_file,
        shared_transcript,
    )
    .await;

    let uid = contributor_state.read().await
        .as_ref()
        .expect("participant is guaranteed non-empty here")
        .0
        .to_string();

    // Remove this person from the contribution spot
    clear_current_contributor(contributor_state).await;

    storage.finish_contribution(&uid).await;

    Ok(ContributeReceipt {
        encoded_receipt_token,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axum::{Extension, Json};
    use chrono::DateTime;

    use crate::{
        api::v1::contribute::ContributeError,
        constants, contribute, keys, read_transcript_file,
        storage::test_storage_client,
        test_transcript::TestContribution::{InvalidContribution, ValidContribution},
        test_util::create_test_session_info,
        AppConfig, Keys, SessionId, SharedTranscript, TestTranscript, lobby::SharedContributorState,
    };

    fn config() -> AppConfig {
        let mut transcript = std::env::temp_dir();
        transcript.push("transcript.json");
        let mut transcript_work = std::env::temp_dir();
        transcript_work.push("transcript.json.new");
        AppConfig {
            eth_check_nonce_at_block:    "".to_string(),
            eth_min_nonce:               0,
            github_max_creation_time:    DateTime::parse_from_rfc3339(
                constants::GITHUB_ACCOUNT_CREATION_DEADLINE,
            )
            .unwrap(),
            eth_rpc_url:                 "".to_string(),
            transcript_file:             transcript,
            transcript_in_progress_file: transcript_work,
        }
    }

    async fn init_keys() {
        keys::KEYS
            .set(
                Keys::new(keys::Options {
                    private_key: PathBuf::from("private.key"),
                    public_key:  PathBuf::from("publickey.pem"),
                })
                .await
                .unwrap(),
            )
            .ok();
    }

    #[tokio::test]
    async fn rejects_out_of_turn_contribution() {
        let db = test_storage_client().await;
        let contributor_state = SharedContributorState::default();
        let result = contribute::<TestTranscript>(
            SessionId::new(),
            Json(ValidContribution(123)),
            Extension(contributor_state),
            Extension(config()),
            Extension(SharedTranscript::default()),
            Extension(db),
        )
        .await;
        assert!(matches!(result, Err(ContributeError::NotUsersTurn)));
    }

    #[tokio::test]
    async fn rejects_invalid_contribution() {
        init_keys().await;
        let db = test_storage_client().await;
        let contributor_state = SharedContributorState::default();
        let participant = SessionId::new();
        *contributor_state.write().await =
            Some((participant.clone(), create_test_session_info(100)));
        let result = contribute::<TestTranscript>(
            participant,
            Json(InvalidContribution(123)),
            Extension(contributor_state),
            Extension(config()),
            Extension(SharedTranscript::default()),
            Extension(db),
        )
        .await;
        assert!(matches!(result, Err(ContributeError::InvalidContribution)));
    }

    #[tokio::test]
    async fn accepts_valid_contribution() {
        init_keys().await;
        let db = test_storage_client().await;
        let contributor_state = SharedContributorState::default();
        let participant = SessionId::new();
        let cfg = config();
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
        )
        .await;

        assert!(matches!(result, Ok(_)));
        let transcript = read_transcript_file::<TestTranscript>(cfg.transcript_file.clone()).await;
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
        )
        .await;

        assert!(matches!(result, Ok(_)));
        let transcript = read_transcript_file::<TestTranscript>(cfg.transcript_file.clone()).await;
        assert_eq!(transcript, TestTranscript {
            initial:       ValidContribution(0),
            contributions: vec![ValidContribution(123), ValidContribution(175)],
        });
    }
}
