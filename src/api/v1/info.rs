use std::sync::atomic::Ordering;

use crate::{keys::SharedKeys, lobby::SharedLobbyState, Options, SharedCeremonyStatus};
use axum::{
    body::StreamBody,
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum_extra::response::ErasedJson;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio_util::io::ReaderStream;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct StatusResponse {
    lobby_size:        usize,
    num_contributions: usize,
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
) -> StatusResponse {
    let lobby_size = {
        let state = lobby_state.read().await;
        state.participants.len()
    };

    let num_contributions = ceremony_status.load(Ordering::Relaxed);

    StatusResponse {
        lobby_size,
        num_contributions,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtInfoResponse {
    alg:         &'static str,
    rsa_pem_key: String,
}

impl IntoResponse for JwtInfoResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, ErasedJson::pretty(self)).into_response()
    }
}

#[allow(clippy::unused_async)]
pub async fn jwt_info(Extension(keys): Extension<SharedKeys>) -> JwtInfoResponse {
    let address = keys.address();

    JwtInfoResponse {
        alg:         "eth",
        rsa_pem_key: address,
    }
}
