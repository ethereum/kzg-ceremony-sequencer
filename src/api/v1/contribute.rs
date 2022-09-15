use crate::{
    data::transcript::write_transcript_file,
    jwt::{errors::JwtError, Receipt},
    storage::PersistentStorage,
    AppConfig, Contribution, SessionId, SharedState, SharedTranscript, Transcript,
};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use serde_json::json;
use std::fmt::Debug;

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
    fn into_response(self) -> axum::response::Response {
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
    Extension(store): Extension<SharedState>,
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
    {
        let app_state = store.read().await;
        let id = &app_state
            .participant
            .as_ref()
            .ok_or(ContributeError::NotUsersTurn)?
            .0;
        if &session_id != id {
            return Err(ContributeError::NotUsersTurn);
        }
    }

    // We also know that if they were in the lobby
    // then they did not participate already because
    // when we auth participants, this is checked

    // 2. Check if the program state transition was correct
    {
        let transcript = shared_transcript.read().await;
        if T::verify_contribution(&transcript, &contribution).is_err() {
            let mut app_state = store.write().await;
            app_state.clear_current_contributor();
            return Err(ContributeError::InvalidContribution);
        }
    }

    {
        let mut transcript = shared_transcript.write().await;
        *transcript = transcript.update(&contribution);
    }

    let receipt = {
        let app_state = store.read().await;
        let session_info = &app_state
            .participant
            .as_ref()
            // TODO: Wrong locks architecture? I should be holding this lock,
            // without blocking the whole app_state
            .expect("Impossible: participant changed mid-contribution")
            .1;

        Receipt {
            id_token: session_info.token.clone(),
            witness:  contribution.get_receipt(),
        }
    };

    let encoded_receipt_token = receipt.encode().map_err(ContributeError::Auth)?;

    // TODO write to bkp + mv
    write_transcript_file(config.transcript_file.clone(), shared_transcript).await;

    let mut app_state = store.write().await;

    // Log the contributors unique social id
    // So if they use the same login again, they will
    // not be able to participate
    app_state
        .finished_contribution
        .insert(receipt.id_token.unique_identifier().to_owned());
    app_state.num_contributions += 1;

    let uid = app_state
        .participant
        .as_ref()
        .expect("participant is guaranteed non-empty here")
        .0
        .to_string();

    // Remove this person from the contribution spot
    app_state.clear_current_contributor();

    drop(app_state); // Release AppState lock
    storage.finish_contribution(&uid).await;

    Ok(ContributeReceipt {
        encoded_receipt_token,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        api::v1::contribute::ContributeError,
        constants, contribute,
        jwt::IdToken,
        keys, read_trancscript_file,
        storage::test_storage_client,
        test_transcript::TestContribution::{InvalidContribution, ValidContribution},
        test_util::create_test_session_info,
        AppConfig, Keys, SessionId, SessionInfo, SharedState, SharedTranscript, TestTranscript,
    };
    use axum::{Extension, Json};
    use chrono::DateTime;
    use std::{
        fs::File,
        path::PathBuf,
        time::{Instant, SystemTime},
    };

    fn config() -> AppConfig {
        let mut transcript = std::env::temp_dir();
        transcript.push("transcript.json");
        File::create(&transcript).unwrap();
        AppConfig {
            eth_check_nonce_at_block: "".to_string(),
            eth_min_nonce:            0,
            github_max_creation_time: DateTime::parse_from_rfc3339(
                constants::GITHUB_ACCOUNT_CREATION_DEADLINE,
            )
            .unwrap(),
            eth_rpc_url:              "".to_string(),
            transcript_file:          transcript,
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
        let app_state = SharedState::default();
        app_state.write().await.participant = None;
        let result = contribute::<TestTranscript>(
            SessionId::new(),
            Json(ValidContribution(123)),
            Extension(app_state),
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
        let app_state = SharedState::default();
        let participant = SessionId::new();
        app_state.write().await.participant =
            Some((participant.clone(), create_test_session_info(100)));
        let result = contribute::<TestTranscript>(
            participant,
            Json(InvalidContribution(123)),
            Extension(app_state),
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
        let app_state = SharedState::default();
        let participant = SessionId::new();
        let cfg = config();
        let shared_transcript = SharedTranscript::<TestTranscript>::default();

        app_state.write().await.participant =
            Some((participant.clone(), create_test_session_info(100)));
        let result = contribute::<TestTranscript>(
            participant.clone(),
            Json(ValidContribution(123)),
            Extension(app_state.clone()),
            Extension(cfg.clone()),
            Extension(shared_transcript.clone()),
            Extension(db.clone()),
        )
        .await;

        assert!(matches!(result, Ok(_)));
        let transcript = read_trancscript_file::<TestTranscript>(cfg.transcript_file.clone()).await;
        assert_eq!(transcript, TestTranscript {
            initial:       ValidContribution(0),
            contributions: vec![ValidContribution(123)],
        });

        app_state.write().await.participant =
            Some((participant.clone(), create_test_session_info(100)));
        let result = contribute::<TestTranscript>(
            participant.clone(),
            Json(ValidContribution(175)),
            Extension(app_state.clone()),
            Extension(cfg.clone()),
            Extension(shared_transcript.clone()),
            Extension(db.clone()),
        )
        .await;

        assert!(matches!(result, Ok(_)));
        let transcript = read_trancscript_file::<TestTranscript>(cfg.transcript_file.clone()).await;
        assert_eq!(transcript, TestTranscript {
            initial:       ValidContribution(0),
            contributions: vec![ValidContribution(123), ValidContribution(175)],
        });
    }
}
