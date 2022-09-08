use std::convert::TryInto;

use crate::jwt::errors::JwtError;
use crate::jwt::Receipt;
use crate::{SessionId, SharedState, SharedTranscript};
use axum::{response::IntoResponse, Extension, Json};
use http::StatusCode;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use small_powers_of_tau::sdk::{
    transcript_verify_update, Transcript, TranscriptJSON, NUM_CEREMONIES,
};
use small_powers_of_tau::update_proof::UpdateProof;

// TODO: Move this into Small Powers of Tau repo
pub type UpdateProofJson = [String; 2];

#[derive(Debug, Serialize, Deserialize)]
pub struct ContributePayload {
    state: TranscriptJSON,
    witness: [UpdateProofJson; NUM_CEREMONIES],
}

pub enum ContributeResponse {
    ParticipantSpotEmpty,
    NotUsersTurn,
    InvalidContribution,
    TranscriptDecodeError,
    Auth(JwtError),
    Receipt(String),
}

impl IntoResponse for ContributeResponse {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match self {
            ContributeResponse::ParticipantSpotEmpty => {
                let body = Json(json!({"error" : "the spot to participate is empty"}));
                (StatusCode::BAD_REQUEST, body)
            }
            ContributeResponse::NotUsersTurn => {
                let body = Json(json!({"error" : "not your turn to participate"}));
                (StatusCode::BAD_REQUEST, body)
            }
            ContributeResponse::InvalidContribution => {
                let body = Json(json!({"error" : "contribution invalid"}));
                (StatusCode::BAD_REQUEST, body)
            }
            ContributeResponse::TranscriptDecodeError => {
                let body = Json(
                    json!({"error" : "contribution was valid, but could not decode transcript "}),
                );
                (StatusCode::BAD_REQUEST, body)
            }
            ContributeResponse::Auth(err) => return err.into_response(),
            ContributeResponse::Receipt(encoded_receipt_token) => {
                let body = Json(json!({ "receipt": encoded_receipt_token }));
                (StatusCode::OK, body)
            }
        };

        (status, body).into_response()
    }
}

pub(crate) async fn contribute(
    session_id: SessionId,
    Json(payload): Json<ContributePayload>,
    Extension(store): Extension<SharedState>,
    Extension(shared_transcript): Extension<SharedTranscript>,
) -> ContributeResponse {
    // 1. Check if this person should be contributing

    let mut app_state = store.write().await;

    let (id, session_info) = match &app_state.participant {
        Some(participant_id) => participant_id,
        None => {
            return ContributeResponse::ParticipantSpotEmpty;
        }
    };

    if &session_id != id {
        return ContributeResponse::NotUsersTurn;
    }

    // We also know that if they were in the lobby
    // then they did not participate already because
    // when we auth participants, this is checked

    // 2. Check if the program state transition was correct
    let mut transcript = shared_transcript.write().await;

    if !check_transition(&transcript, &payload.state, payload.witness.clone()) {
        app_state.clear_contribution_spot();

        return ContributeResponse::InvalidContribution;
    }

    let new_transcript: Option<Transcript> = (&payload.state).into();
    match new_transcript {
        Some(new_transcript) => {
            *transcript = new_transcript;
        }
        None => {
            return ContributeResponse::TranscriptDecodeError;
        }
    }

    // Given that the state transition was correct
    //
    // record this contribution and clean up the user

    let receipt = Receipt {
        id_token: session_info.token.clone(),
        witness: payload.witness,
    };
    let encoded_receipt_token = match receipt.encode() {
        Ok(encoded_token) => encoded_token,
        Err(err) => return ContributeResponse::Auth(err),
    };
    // Log the contributors unique social id
    // So if they use the same login again, they will
    // not be able to participate
    app_state
        .finished_contribution
        .insert(receipt.id_token.unique_identifier().to_owned());
    app_state.receipts.push(receipt);
    app_state.num_contributions += 1;

    // Remove this person from the contribution spot
    app_state.clear_contribution_spot();

    ContributeResponse::Receipt(encoded_receipt_token)
}

fn check_transition(
    old_transcript: &Transcript,
    new_transcript_json: &TranscriptJSON,
    witness: [UpdateProofJson; NUM_CEREMONIES],
) -> bool {
    let mut update_proofs = Vec::new();
    for proof_json in witness {
        let update_proof = match UpdateProof::deserialise(proof_json) {
            Some(proof) => proof,
            None => return false,
        };
        update_proofs.push(update_proof);
    }
    let update_proofs: [UpdateProof; NUM_CEREMONIES] = update_proofs.try_into().unwrap();

    let new_transcript: Option<Transcript> = new_transcript_json.into();
    let new_transcript = match new_transcript {
        Some(transcript) => transcript,
        None => return false,
    };

    let random_hex_elements = random_hex_strs();

    // TODO: Do this in parallel in small powers of tau repo
    transcript_verify_update(
        old_transcript,
        &new_transcript,
        &update_proofs,
        random_hex_elements,
    )
}

fn random_hex_strs() -> [String; NUM_CEREMONIES] {
    let mut rng = rand::thread_rng();

    let mut secrets: [String; NUM_CEREMONIES] = [
        String::default(),
        String::default(),
        String::default(),
        String::default(),
    ];

    for i in 0..NUM_CEREMONIES {
        // We use 64 bytes for the secret to reduce bias when reducing
        let mut bytes = [0u8; 64];
        rng.fill(&mut bytes);

        let mut hex_string = hex::encode(&bytes);
        // prepend 0x because this is standard in ethereum
        hex_string.insert_str(0, "0x");
        secrets[i] = hex_string
    }

    secrets
}
