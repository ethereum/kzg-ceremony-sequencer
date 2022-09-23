use std::sync::atomic::Ordering;

use crate::{keys::SharedKeys, lobby::SharedLobbyState, Options, SharedCeremonyStatus};
use axum::{
    body::StreamBody,
    response::{IntoResponse, Response},
    Extension, Json,
};
use http::StatusCode;
use serde::Serialize;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct StatusResponse {
    lobby_size:        usize,
    num_contributions: usize,
    sequencer_address: String,
}

impl IntoResponse for StatusResponse {
    fn into_response(self) -> Response {
        let status = StatusCode::OK;
        (status, Json(self)).into_response()
    }
}

pub async fn status(
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(ceremony_status): Extension<SharedCeremonyStatus>,
    Extension(keys): Extension<SharedKeys>
) -> StatusResponse {
    let lobby_size = {
        let state = lobby_state.read().await;
        state.participants.len()
    };

    let num_contributions = ceremony_status.load(Ordering::Relaxed);
    let sequencer_address = keys.address();


    StatusResponse {
        lobby_size,
        num_contributions,
        sequencer_address,
    }
}

pub async fn current_state(Extension(options): Extension<Options>) -> impl IntoResponse {
    let f = match File::open(options.transcript.transcript_file).await {
        Ok(file) => file,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not open transcript file",
            ))
        }
    };
    let stream = ReaderStream::new(f);
    let body = StreamBody::new(stream);
    Ok((StatusCode::OK, body))
}
