use axum::{
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use serde_json::json;

#[derive(Debug)]
pub enum JwtError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

impl IntoResponse for JwtError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            JwtError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            JwtError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            JwtError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            JwtError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
