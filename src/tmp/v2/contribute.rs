use crate::SharedState;

use super::auth::tokens::{
    create_receipt_jwt, AccessToken, ContributionToken, IdToken, Receipt, RefreshToken,
};
use axum::{response::IntoResponse, Extension, Json};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
pub struct ContributeStartPayload {
    access_token: String,
    id_token: String,
}
// A user will trade their access token
// and refresh token for a contribution token
pub(crate) async fn contribute_start(
    // TODO: can we pass both refresh token and access token in as parameters?
    // TODO: only one of them can be in the Auth header
    refresh_token: RefreshToken,
    Json(payload): Json<ContributeStartPayload>,
    Extension(store): Extension<SharedState>,
) -> impl IntoResponse {
    let mut app_state = store.write().await;

    // 1. First check if this refresh token has been revoked
    let unique_id = match app_state.refresh_token_store.get(&refresh_token.id) {
        Some(unique_id) => unique_id,
        None => {
            let body = Json(json!({"error" : "invalid refresh token, not in whitelist"}));
            return (StatusCode::BAD_REQUEST, body).into_response();
        }
    };

    // 2. Decode and check that access and id tokens are valid
    let access_token = match AccessToken::decode(&payload.access_token) {
        Ok(token) => token,
        Err(_) => {
            let body = Json(json!({"error" : "invalid access token"}));
            return (StatusCode::BAD_REQUEST, body).into_response();
        }
    };
    let id_token = match IdToken::decode(&payload.id_token) {
        Ok(token) => token,
        Err(_) => {
            let body = Json(json!({"error" : "invalid id token"}));
            return (StatusCode::BAD_REQUEST, body).into_response();
        }
    };

    //2a. Now check that the ID matches the id in access and ID token
    let tokens_consistent = access_token.sub == id_token.sub && &id_token.sub == unique_id;
    if !tokens_consistent {
        let body = Json(json!({"error" : "id in tokens are not the same"}));
        return (StatusCode::BAD_REQUEST, body).into_response();
    }

    // 3. Create a contribution token
    let contrib_token = ContributionToken::from_id_token(id_token);
    let contrib_token_encoded = match contrib_token.encode() {
        Ok(token) => token,
        Err(err) => return err.into_response(),
    };

    // 4. Check that they are the person at the front of the queue
    match app_state.get_first() {
        Some((id, queue_status)) => {
            // This should not fail, but we check it here while debugging
            if !queue_status.has_checked_in() {
                let body =
                    Json(json!({"error" : "invalid queue status, user should be checked in "}));
                return (StatusCode::INTERNAL_SERVER_ERROR, body).into_response();
            }

            if unique_id != id {
                let body = Json(json!({"error" : "it is not your turn to contribute"}));
                return (StatusCode::BAD_REQUEST, body).into_response();
            }
        }
        None => {
            let body =
                Json(json!({"error" : "queue is empty, join queue before trying to contribute"}));
            return (StatusCode::BAD_REQUEST, body).into_response();
        }
    };

    // 4. Invalidate the refresh token and return the contribution token
    // TODO: we could do this first and then release the lock immediately as we do not need to
    // TODO: add to the database. Though its a problem, if token encoding fails
    app_state.refresh_token_store.remove(&refresh_token.id);

    let body = Json(json!({ "contribution_token": contrib_token_encoded }));
    return (StatusCode::OK, body).into_response();
}

// This is the updated program state
// that the contributor has sent
#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramState {
    program_state: u64,
    witness: u64,
}

pub(crate) async fn contribute_end(
    // Users should use a contribution token which is short-lived
    user: IdToken,
    Json(payload): Json<ProgramState>,
    Extension(store): Extension<SharedState>,
) -> impl IntoResponse {
    let mut app_state = store.write().await;

    let expected_user = match app_state.get_first() {
        Some(user) => user,
        None => {
            // This means the queue is empty. Return a 40X and tell the user
            let body = Json(json!({"error" : "The queue is empty, cannot contribute"}));
            return (StatusCode::UNPROCESSABLE_ENTITY, body).into_response();
        }
    };
    // 1. Check if this is the user's turn to contribute
    // TODO: We will kick out a user, if they call this method more than 3(?) times
    //
    //
    let is_correct_user = expected_user.0 == user.unique_identifier();
    if !is_correct_user {
        let body = Json(json!({"error" : "Not users turn to contribute"}));
        return (StatusCode::BAD_REQUEST, body).into_response();
    }

    // 1a. TODO: We need to formalise what happens if a user times out
    //    TODO: where do we time out users and kick them from the queue?
    // TODO: should we check if a user times out here?
    // TODO: should we just check when they come to contribute and then kick them here?

    // 2. Check that the transition from current counter (program state)
    // to  the one the user sent in is correct

    if app_state.program_state + 1 != payload.program_state {
        let body = Json(json!({"error" : "invalid update to current state"}));
        return (StatusCode::BAD_REQUEST, body).into_response();
    }

    // 3. Now we can change the program state (save the witness)
    // If a client wants to eagerly pull it, they can
    app_state.program_state = payload.program_state;

    //4. Lastly we remove the current user from the queue
    // Do this last because we do not want the next person to contribute
    // until all of the above have been completed
    let _ = app_state.pop_first();

    //5. send back a JWT with the witness to the user
    // this means the coordinator acknowledges that they
    // have included their contribution
    let receipt = Receipt {
        witness: payload.witness,
        id_token: user,
    };
    let token = match create_receipt_jwt(&receipt) {
        Ok(token) => token,
        Err(auth_error) => return auth_error.into_response(),
    };

    let body = Json(json!({ "receipt": token }));
    return (StatusCode::OK, body).into_response();
}
