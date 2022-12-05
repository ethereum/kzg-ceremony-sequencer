use super::{
    auth::{AuthError, AuthErrorPayload},
    contribute::ContributeError,
    lobby::TryContributeError,
};
use crate::{keys::SignatureError, sessions::SessionError};
use axum::{
    response::{IntoResponse, Redirect, Response},
    Json,
};
use http::StatusCode;
use kzg_ceremony_crypto::{CeremoniesError, ErrorCode};
use serde_json::json;
use std::fmt::Display;
use url::Url;

fn error_to_json<Err: Display + ErrorCode>(error: &Err) -> Json<serde_json::Value> {
    Json(json!({
        "code": error.to_error_code(),
        "error": error.to_string()
    }))
}

impl IntoResponse for SignatureError {
    fn into_response(self) -> Response {
        match self {
            Self::SignatureCreation => {
                (StatusCode::INTERNAL_SERVER_ERROR, error_to_json(&self)).into_response()
            }
            Self::InvalidToken => (StatusCode::BAD_REQUEST, error_to_json(&self)).into_response(),
            Self::InvalidSignature => {
                (StatusCode::BAD_REQUEST, error_to_json(&self)).into_response()
            }
        }
    }
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidSessionId => {
                (StatusCode::BAD_REQUEST, error_to_json(&self)).into_response()
            }
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let redirect_url = self.redirect.and_then(|r| Url::parse(&r).ok());
        match redirect_url {
            Some(mut redirect_url) => {
                redirect_url
                    .query_pairs_mut()
                    .append_pair("code", &self.payload.to_error_code())
                    .append_pair("error", &format!("{}", self.payload));

                Redirect::to(redirect_url.as_str()).into_response()
            }
            None => self.payload.into_response(),
        }
    }
}

impl IntoResponse for AuthErrorPayload {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::FetchUserDataError | Self::CouldNotExtractUserData => {
                (StatusCode::INTERNAL_SERVER_ERROR, error_to_json(&self))
            }
            Self::LobbyIsFull => (StatusCode::SERVICE_UNAVAILABLE, error_to_json(&self)),
            Self::InvalidAuthCode | Self::UserAlreadyContributed => {
                (StatusCode::BAD_REQUEST, error_to_json(&self))
            }
            Self::UserCreatedAfterDeadline => (StatusCode::UNAUTHORIZED, error_to_json(&self)),
            Self::Storage(storage_error) => return storage_error.into_response(),
        };
        (status, body).into_response()
    }
}

impl IntoResponse for ContributeError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::NotUsersTurn => (StatusCode::BAD_REQUEST, error_to_json(&self)),
            Self::InvalidContribution(e) => return CeremoniesErrorFormatter(e).into_response(),
            Self::OurSignature(err) => return err.into_response(),
            Self::StorageError(err) => return err.into_response(),
            Self::TaskError(_) => (StatusCode::INTERNAL_SERVER_ERROR, error_to_json(&self)),
        };

        (status, body).into_response()
    }
}

impl IntoResponse for TryContributeError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::UnknownSessionId => (StatusCode::UNAUTHORIZED, error_to_json(&self)),
            Self::RateLimited | Self::LobbyIsFull => {
                (StatusCode::BAD_REQUEST, error_to_json(&self))
            }
            Self::AnotherContributionInProgress => (StatusCode::OK, error_to_json(&self)),
            Self::StorageError(err) => return err.into_response(),
        };

        (status, body).into_response()
    }
}

struct CeremoniesErrorFormatter(CeremoniesError);

impl IntoResponse for CeremoniesErrorFormatter {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "code": self.0.to_error_code(),
            "error" : format!("contribution invalid: {}", self.0)
        }));

        (StatusCode::BAD_REQUEST, body).into_response()
    }
}
