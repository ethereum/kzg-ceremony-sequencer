use std::time::Duration;

use axum::{response::IntoResponse, Extension, Json};
use http::StatusCode;
use serde_json::json;

use crate::{
    config::ACTIVE_ZONE_CHECKIN_DEADLINE,
    queue::{id_token_to_access_token, ActiveZoneCheckPoint}, SharedState,
};

use super::auth::tokens::IdToken;

// If a user was not previously in the active zone
// they call this with their idToken to attain an access and refresh token
// TODO: So Ideally we don't want the IdToken to be used for this
// TODO but its either this or have access tokens which are long lived
// TODO if we make access tokens revocable, then we slowly are just implementing
// TODO sessions
pub(crate) async fn queue_active(
    user: IdToken,
    Extension(store): Extension<SharedState>,
) -> impl IntoResponse {
    let id = user.unique_identifier();

    let mut app_state = store.write().await;
    // 1. First check if they are in the queue
    let position = match app_state.find_position(id) {
        Some(position) => position,
        None => {
            // User not in the queue
            let body = Json(json!({"error" : "user is not in the queue"}));
            return (StatusCode::BAD_REQUEST, body).into_response();
        }
    };

    // TODO: do we have a lock on this, as in the position won't change while in function?
    let (_, queue_status) = app_state.get_index(position).unwrap();

    match queue_status {
        ActiveZoneCheckPoint::CheckedIn { .. } => {
            let status = StatusCode::BAD_REQUEST;
            let body = Json(json!({
                "error": "use has already checked in and should have received an access token",
            }));
            return (status, body).into_response();
        }
        ActiveZoneCheckPoint::InQueue => {
            // Arriving here means that the user is not in the active zone
            let status = StatusCode::BAD_REQUEST;
            let body = Json(json!({
                "error": format!("you are not in the active zone. threshold : {}", ActiveZoneCheckPoint::threshold()),
            }));
            return (status, body).into_response();
        }
        ActiveZoneCheckPoint::InActiveSet(time_entered) => {
            // Check if the user went over the deadline to enter active zone
            let passed_deadline =
                time_entered.elapsed() > Duration::from_secs(ACTIVE_ZONE_CHECKIN_DEADLINE as u64);
            if passed_deadline {
                let status = StatusCode::BAD_REQUEST;
                let body = Json(json!({
                    "error": "user has passed the deadline to check into the active zone",
                }));
                return (status, body).into_response();
            }

            // change their queue status
            app_state.user_checked_in(id).expect("infallible");

            // If they did not, then we can generate a token for them and mark them as checkedin
            let (refresh_token, response) = id_token_to_access_token(&user, position);
            if let Some(rt) = refresh_token {
                app_state.refresh_token_store.insert(rt.id, id.to_owned());
            }
            response.into_response()
        }
    }
}

pub(crate) async fn queue_join(
    claims: IdToken,
    Extension(store): Extension<SharedState>,
) -> impl IntoResponse {
    let unique_id = claims.unique_identifier();

    let app_state = &mut store.write().await;
    // 1. TODO: Check if this user has already contributed (Persistent storage)

    //2.  Check if this user is already in the queue (Possibly change to persistent storage)
    if app_state.id_found(unique_id) {
        let status = StatusCode::CONFLICT;
        let body = Json(json!({
            "error": "user is already in queue",
        }));
        return (status, body).into_response();
    };
    //3. Add user to queue
    let user_queue_status = ActiveZoneCheckPoint::from_queue_size(app_state.queue_len());
    // TODO: Assert user_status != InActiveSet
    let queue_position = app_state.insert(claims.unique_identifier(), user_queue_status);

    // If the user is not in the active zone, then we do not need to give them an access
    // and refresh token
    match user_queue_status {
        ActiveZoneCheckPoint::CheckedIn { .. } => {
            let (refresh_token, response) = id_token_to_access_token(&claims, queue_position);
            // If a refresh token was generated then, we can add it to the store
            if let Some(rt) = refresh_token {
                app_state
                    .refresh_token_store
                    .insert(rt.id, unique_id.to_owned());
            }

            response.into_response()
        }
        ActiveZoneCheckPoint::InActiveSet(_) => {
            unreachable!("a user at this point is either in the active zone or they are not")
        }
        ActiveZoneCheckPoint::InQueue => {
            let status = StatusCode::OK;
            let body = Json(json!({
                "position": queue_position,
            }));

            (status, body).into_response()
        }
    }
}
