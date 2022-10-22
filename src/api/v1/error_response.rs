use axum::{
    response::{IntoResponse, Redirect, Response},
    Json,
};
use error_codes::ErrorCode;
use http::StatusCode;
use kzg_ceremony_crypto::CeremoniesError;
use serde_json::json;
use url::Url;

use crate::{keys::SignatureError, sessions::SessionError};

use super::{
    auth::{AuthError, AuthErrorPayload},
    contribute::ContributeError,
    lobby::TryContributeError,
};

impl IntoResponse for SignatureError {
    fn into_response(self) -> Response {
        match self {
            Self::SignatureCreation => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "code": self.to_error_code(),
                    "error": "couldn't sign the receipt"
                })),
            )
                .into_response(),
            Self::InvalidToken => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "code": self.to_error_code(),
                    "error": "signature is not a valid hex string"
                })),
            )
                .into_response(),
            Self::InvalidSignature => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "code": self.to_error_code(),
                    "error": "couldn't create signature from string"
                })),
            )
                .into_response(),
        }
    }
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidSessionId => {
                let json = Json(json!({
                    "code": self.to_error_code(),
                    "error": "invalid Bearer token",
                }));
                (StatusCode::BAD_REQUEST, json).into_response()
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
                    .append_pair("code", self.payload.to_error_code())
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
            Self::InvalidAuthCode => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "error": "invalid authorisation code",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            Self::FetchUserDataError => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "error": "could not fetch user data from auth server",
                }));
                (StatusCode::INTERNAL_SERVER_ERROR, body)
            }
            Self::CouldNotExtractUserData => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "error": "could not extract user data from auth server response",
                }));
                (StatusCode::INTERNAL_SERVER_ERROR, body)
            }
            Self::LobbyIsFull => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "error": "lobby is full",
                }));
                (StatusCode::SERVICE_UNAVAILABLE, body)
            }
            Self::UserAlreadyContributed => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "error": "user has already contributed"
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            Self::UserCreatedAfterDeadline => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "error": "user account was created after the deadline"
                }));
                (StatusCode::UNAUTHORIZED, body)
            }
            Self::Storage(storage_error) => return storage_error.into_response(),
        };
        (status, body).into_response()
    }
}

impl IntoResponse for ContributeError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::NotUsersTurn => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "error" : "not your turn to participate"
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            Self::InvalidContribution(e) => return CeremoniesErrorFormatter(e).into_response(),
            Self::Signature(err) => return err.into_response(),
            Self::StorageError(err) => return err.into_response(),
        };

        (status, body).into_response()
    }
}

impl IntoResponse for TryContributeError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::UnknownSessionId => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "error": "unknown session id",
                }));
                (StatusCode::UNAUTHORIZED, body)
            }

            Self::RateLimited => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "error": "call came too early. rate limited",
                }));
                (StatusCode::BAD_REQUEST, body)
            }

            Self::AnotherContributionInProgress => {
                let body = Json(json!({
                    "code": self.to_error_code(),
                    "message": "another contribution in progress",
                }));
                (StatusCode::OK, body)
            }
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
