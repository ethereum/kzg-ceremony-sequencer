use crate::{
    api::v1::auth::tokens::{AccessToken, IdToken, RefreshToken},
    config::ONLINE_THRESHOLD,
};
use axum::{response::IntoResponse, Json};
use http::StatusCode;
use indexmap::IndexMap;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Instant,
};
use tokio::sync::RwLock;

pub(crate) fn id_token_to_access_token(
    id_token: &IdToken,
    queue_position: usize,
) -> (Option<RefreshToken>, impl IntoResponse) {
    let unique_id = id_token.unique_identifier();

    // Access token to allow user to ping endpoints
    let access_token = AccessToken::from_id(unique_id.to_owned());
    let access_token_encoded = access_token.encode();
    let access_token_encoded = match access_token_encoded {
        Ok(access_token) => access_token,
        Err(err) => return (None, err.into_response()),
    };

    let refresh_token_id = uuid::Uuid::new_v4().to_string();
    let refresh_token = RefreshToken::from_id_position(refresh_token_id, queue_position);
    let refresh_token_encoded = refresh_token.encode();
    let refresh_token_encoded = match refresh_token_encoded {
        Ok(refresh_token) => refresh_token,
        Err(err) => return (None, err.into_response()),
    };

    let status = StatusCode::OK;
    let body = Json(json!({
        "position": queue_position,
        "access_token" : access_token_encoded,
        "refresh_token" : refresh_token_encoded,
    }));

    return (Some(refresh_token), (status, body).into_response());
}

#[derive(Debug, Copy, Clone)]
pub enum ActiveZoneCheckPoint {
    // This means that they have pinged atleast once
    // while in the active zone.
    //
    // This can happen automatically if a user joins the queue and is in
    // the active zone
    //
    // Stores when the token they are using should expire
    // This means that when they get to the front of the queue
    // We can kick them, if their time is up as they will not be coming
    CheckedIn { last_check_in: Instant },
    // This means that the user has moved into the
    // active zone at a particular time
    //
    // They have a deadline to check-in
    // and get their Access/Refresh Tokens
    InActiveSet(Instant),
    // This means that the user is in the Queue
    InQueue,
}

impl ActiveZoneCheckPoint {
    // Get user status from queue size
    // This is before the user has been added
    pub fn from_queue_size(queue_size: usize) -> Self {
        if queue_size >= ONLINE_THRESHOLD {
            ActiveZoneCheckPoint::InQueue
        } else {
            ActiveZoneCheckPoint::CheckedIn {
                last_check_in: Instant::now(),
            }
        }
    }

    pub const fn threshold() -> usize {
        ONLINE_THRESHOLD
    }

    pub fn has_checked_in(&self) -> bool {
        match self {
            ActiveZoneCheckPoint::CheckedIn { .. } => true,
            _ => false,
        }
    }
}
