use crate::{
    constants::HISTORY_RECEIPTS_COUNT,
    keys::{Keys, KEYS},
    SharedState, SharedTranscript,
};
use axum::{
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum_extra::response::ErasedJson;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use small_powers_of_tau::sdk::TranscriptJSON;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct StatusResponse {
    lobby_size: usize,
    num_contributions: usize,
    // Receipts are returned in encoded format
    receipts: Vec<String>,
}

impl IntoResponse for StatusResponse {
    fn into_response(self) -> Response {
        let status = StatusCode::OK;
        (status, Json(self)).into_response()
    }
}

pub(crate) async fn status(Extension(store): Extension<SharedState>) -> StatusResponse {
    let app_state = store.read().await;

    let lobby_size = app_state.lobby.len();
    let num_contributions = app_state.num_contributions;

    let receipts: Vec<_> = app_state
        .receipts
        .iter()
        .rev()
        .take(HISTORY_RECEIPTS_COUNT)
        .map(|receipt| receipt.encode().unwrap())
        .collect();

    StatusResponse {
        lobby_size,
        num_contributions,
        receipts,
    }
}

pub struct CurrentStateResponse {
    state: TranscriptJSON,
}

impl IntoResponse for CurrentStateResponse {
    fn into_response(self) -> Response {
        // We use ErasedJson for the case that one wants to view the
        // transcript in the browser and it needs to be prettified
        (StatusCode::OK, ErasedJson::pretty(self.state)).into_response()
    }
}

pub(crate) async fn current_state(
    Extension(transcript): Extension<SharedTranscript>,
) -> CurrentStateResponse {
    let app_state = transcript.read().await;
    let transcript_json = TranscriptJSON::from(&*app_state);
    CurrentStateResponse {
        state: transcript_json,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtInfoResponse {
    alg: &'static str,
    rsa_pem_key: String,
}

impl IntoResponse for JwtInfoResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, ErasedJson::pretty(self)).into_response()
    }
}

// Returns the relevant JWT information
pub(crate) async fn jwt_info() -> JwtInfoResponse {
    let rsa_public_key_pem_as_string = KEYS.decode_key_to_string();

    JwtInfoResponse {
        alg: Keys::alg_str(),
        rsa_pem_key: rsa_public_key_pem_as_string,
    }
}

// TODO: rewrite the tests
// #[cfg(test)]
// mod tests {

//     use super::*;
//     use small_powers_of_tau::sdk::Transcript;
//     use std::env;

//     use crate::{
//         api::v1::queue::queue_join,
//         jwt::{IdToken, Receipt},
//         sessions::SessionInfo,
//         SharedTranscript,
//     };

//     #[tokio::test]
//     async fn current_transcript_mock() {
//         let expected_transcript = SharedTranscript::default();

//         let response = current_transcript(Extension(expected_transcript.clone())).await;
//         //
//         let expected_transcript = expected_transcript.read().await;

//         let got_transcript_json = &response.transcript;
//         let expected_transcript_json = TranscriptJSON::from(&*expected_transcript);

//         assert_eq!(
//             serde_json::to_string(got_transcript_json).unwrap(),
//             serde_json::to_string(&expected_transcript_json).unwrap()
//         )
//     }
//     #[tokio::test]
//     async fn history_mock() {
//         env::set_var("JWT_SECRET", "password");

//         let state = SharedState::default();
//         // Should be empty
//         let response = history(Extension(state.clone())).await;
//         assert!(response.receipts.is_empty());

//         let to_add = HISTORY_RECEIPTS_COUNT * 2;

//         {
//             let mut state = state.write().await;

//             for i in 0..to_add {
//                 let receipt = Receipt {
//                     id_token: crate::jwt::IdToken {
//                         sub: i.to_string(),
//                         nickname: i.to_string(),
//                         provider: i.to_string(),
//                         exp: i as u64,
//                     },
//                     witness: Default::default(),
//                 };

//                 state.receipts.push(receipt);
//             }
//         }

//         // Make another request
//         let response = history(Extension(state.clone())).await;

//         let state = state.read().await;

//         assert_eq!(response.receipts.len(), HISTORY_RECEIPTS_COUNT);
//         assert_eq!(state.receipts.len(), to_add);

//         for (receipt_response, receipt_state) in response
//             .receipts
//             .into_iter()
//             .zip(state.receipts.iter().rev())
//         {
//             assert_eq!(receipt_response, receipt_state.encode().unwrap())
//         }
//     }

//     #[tokio::test]
//     async fn status_mock_empty_queue() {
//         let state = SharedState::default();
//         let transcript = SharedTranscript::default();

//         // TODO: We can put a summary method on `Transcript`
//         let summary = transcript.clone().read().await.sub_ceremonies[0].summary();

//         let response = status(None, Extension(state), Extension(transcript)).await;
//         // Since no session id was given, deadline and position will be None
//         let position = None;
//         let deadline = None;
//         // No-one has been added to the queue yet
//         let queue_size = 0;

//         let expected_response = StatusResponse {
//             state: summary,
//             queue_size,
//             position,
//             deadline,
//         };
//         assert_eq!(expected_response, response);
//     }
//     #[tokio::test]
//     async fn status_mock_session_id() {
//         let state = SharedState::default();
//         let transcript = SharedTranscript::default();
//         let summary = transcript.clone().read().await.sub_ceremonies[0].summary();

//         let session_id = SessionId::new();

//         {
//             // When a user is successful authorised
//             // they are given a session Id. Here we emulate that
//             state.clone().write().await.sessions.insert(
//                 session_id.clone(),
//                 SessionInfo {
//                     token: IdToken {
//                         sub: String::default(),
//                         nickname: String::default(),
//                         provider: String::default(),
//                         exp: 0,
//                     },
//                     last_ping_time: Instant::now(),
//                 },
//             );
//             // Add user to the queue
//             queue_join(session_id.clone(), Extension(state.clone())).await;
//         }

//         let response = status(Some(session_id), Extension(state), Extension(transcript)).await;

//         let position = Some(1);
//         let deadline = Some(ACTIVE_ZONE_CHECKIN_DEADLINE);
//         let queue_size = 1;

//         let expected_response = StatusResponse {
//             state: summary,
//             queue_size,
//             position,
//             deadline,
//         };
//         assert_eq!(expected_response, response);
//     }
// }
