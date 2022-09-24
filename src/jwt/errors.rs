use axum::{
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use serde_json::json;
use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum JwtError {
    #[error("token creation error")]
    TokenCreation,
    #[error("invalid token")]
    InvalidToken,
}

impl IntoResponse for JwtError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "token creation error"),
            Self::InvalidToken => (StatusCode::BAD_REQUEST, "invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
