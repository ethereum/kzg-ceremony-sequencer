use crate::{
    jwt::{errors::JwtError, Receipt},
    storage::PersistentStorage,
    SessionId, SharedState, SharedTranscript,
};
use axum::{response::IntoResponse, Extension, Json};
use http::StatusCode;
use serde_json::json;

use crate::{SessionId, SharedState, SharedTranscript, Transcript, Contribution};
use crate::jwt::errors::JwtError;
use crate::jwt::Receipt;

pub struct ContributeReceipt {
    encoded_receipt_token: String,
}

impl IntoResponse for ContributeReceipt {
    fn into_response(self) -> Response {
        (StatusCode::OK, self.encoded_receipt_token).into_response()
    }
}

pub enum ContributeError {
    ParticipantSpotEmpty,
    NotUsersTurn,
    InvalidContribution,
    TranscriptDecodeError,
    Auth(JwtError),
}

impl IntoResponse for ContributeError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match self {
            ContributeError::ParticipantSpotEmpty => {
                let body = Json(json!({"error" : "the spot to participate is empty"}));
                (StatusCode::BAD_REQUEST, body)
            }
            ContributeError::NotUsersTurn => {
                let body = Json(json!({"error" : "not your turn to participate"}));
                (StatusCode::BAD_REQUEST, body)
            }
            ContributeError::InvalidContribution => {
                let body = Json(json!({"error" : "contribution invalid"}));
                (StatusCode::BAD_REQUEST, body)
            }
            ContributeError::TranscriptDecodeError => {
                let body = Json(
                    json!({"error" : "contribution was valid, but could not decode transcript "}),
                );
                (StatusCode::BAD_REQUEST, body)
            }
            ContributeError::Auth(err) => return err.into_response(),
        };

        (status, body).into_response()
    }
}

pub(crate) async fn contribute<T: Transcript>(
    session_id: SessionId,
    Json(contribution): Json<T::ContributionType>,
    Extension(store): Extension<SharedState>,
    Extension(shared_transcript): Extension<SharedTranscript<T>>,
) -> Result<ContributeReceipt, ContributeError> {
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
            app_state.clear_contribution_spot();
            return Err(ContributeError::InvalidContribution);
        }
    }

    {
        let mut transcript = shared_transcript.write().await;
        let new_transcript = transcript.update(&contribution);
        *transcript = new_transcript;
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
            witness: contribution.get_receipt(),
        }
    };

    let encoded_receipt_token = receipt.encode().map_err(ContributeError::Auth)?;

    // TODO write to disk

    let mut app_state = store.write().await;

    // Log the contributors unique social id
    // So if they use the same login again, they will
    // not be able to participate
    app_state
        .finished_contribution
        .insert(receipt.id_token.unique_identifier().to_owned());
    app_state.num_contributions += 1;

    // Remove this person from the contribution spot
    app_state.clear_current_contributor();

    drop(app_state); // Release AppState lock
    storage.finish_contribution(&uid).await;

    Ok(ContributeReceipt {
        encoded_receipt_token,
    })
}

#[tokio::test]
async fn contribute_test() {}
