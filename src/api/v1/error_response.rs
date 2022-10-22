use axum::{
    response::{IntoResponse, Redirect, Response},
    Json,
};
use http::StatusCode;
use kzg_ceremony_crypto::{CeremoniesError, CeremonyError};
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
                    "code": "SignatureError::SignatureCreation",
                    "error": "couldn't sign the receipt"
                })),
            )
                .into_response(),
            Self::InvalidToken => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "code": "SignatureError::InvalidToken",
                    "error": "signature is not a valid hex string"
                })),
            )
                .into_response(),
            Self::InvalidSignature => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "code": "SignatureError::InvalidSignature",
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
                    "code": "SessionError::InvalidSessionId",
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
                    .append_pair("error", "")
                    .append_pair("message", &format!("{}", self.payload));

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
                    "code": "AuthError::InvalidAuthCode",
                    "error": "invalid authorisation code",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            Self::FetchUserDataError => {
                let body = Json(json!({
                    "code": "AuthError::FetchUserDataError",
                    "error": "could not fetch user data from auth server",
                }));
                (StatusCode::INTERNAL_SERVER_ERROR, body)
            }
            Self::CouldNotExtractUserData => {
                let body = Json(json!({
                    "code": "AuthError::CouldNotExtractUserData",
                    "error": "could not extract user data from auth server response",
                }));
                (StatusCode::INTERNAL_SERVER_ERROR, body)
            }
            Self::LobbyIsFull => {
                let body = Json(json!({
                    "code": "AuthError::LobbyIsFull",
                    "error": "lobby is full",
                }));
                (StatusCode::SERVICE_UNAVAILABLE, body)
            }
            Self::UserAlreadyContributed => {
                let body = Json(json!({
                    "code": "AuthError::UserAlreadyContributed",
                    "error": "user has already contributed"
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            Self::UserCreatedAfterDeadline => {
                let body = Json(json!({
                    "code": "AuthError::UserCreatedAfterDeadline",
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
                    "code": "ContributeError::NotUsersTurn",
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
                    "code": "TryContributeError::UnknownSessionId",
                    "error": "unknown session id",
                }));
                (StatusCode::UNAUTHORIZED, body)
            }

            Self::RateLimited => {
                let body = Json(json!({
                    "code": "TryContributeError::RateLimited",
                    "error": "call came too early. rate limited",
                }));
                (StatusCode::BAD_REQUEST, body)
            }

            Self::AnotherContributionInProgress => {
                let body = Json(json!({
                    "code": "TryContributeError::AnotherContributionInProgress",
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
        let error = format!("contribution invalid: {}", self.0);

        let code = match self.0 {
            CeremoniesError::UnexpectedNumContributions(..) => {
                "CeremoniesError::UnexpectedNumContributions"
            }
            CeremoniesError::InvalidCeremony(_, err) => match err {
                CeremonyError::UnsupportedNumG1Powers(_) => "CeremonyError::UnsupportedNumG1Powers",
                CeremonyError::UnsupportedNumG2Powers(_) => "CeremonyError::UnsupportedNumG2Powers",
                CeremonyError::UnexpectedNumG1Powers(..) => "CeremonyError::UnexpectedNumG1Powers",
                CeremonyError::UnexpectedNumG2Powers(..) => "CeremonyError::UnexpectedNumG2Powers",
                CeremonyError::InconsistentNumG1Powers(..) => {
                    "CeremonyError::InconsistentNumG1Powers"
                }
                CeremonyError::InconsistentNumG2Powers(..) => {
                    "CeremonyError::InconsistentNumG2Powers"
                }
                CeremonyError::UnsupportedMoreG2Powers(..) => {
                    "CeremonyError::UnsupportedMoreG2Powers"
                }
                CeremonyError::InvalidG1Power(..) => "CeremonyError::InvalidG1Power",
                CeremonyError::InvalidG2Power(..) => "CeremonyError::InvalidG2Power",
                CeremonyError::ParserError(_) => "CeremonyError::ParserError",
                CeremonyError::InvalidPubKey(_) => "CeremonyError::InvalidPubKey",
                CeremonyError::InvalidWitnessProduct(..) => "CeremonyError::InvalidWitnessProduct",
                CeremonyError::InvalidWitnessPubKey(..) => "CeremonyError::InvalidWitnessPubKey",
                CeremonyError::PubKeyPairingFailed => "CeremonyError::PubKeyPairingFailed",
                CeremonyError::G1PairingFailed => "CeremonyError::G1PairingFailed",
                CeremonyError::G2PairingFailed => "CeremonyError::G2PairingFailed",
                CeremonyError::ZeroPubkey => "CeremonyError::ZeroPubkey",
                CeremonyError::ZeroG1(_) => "CeremonyError::ZeroG1",
                CeremonyError::ZeroG2(_) => "CeremonyError::ZeroG2",
                CeremonyError::InvalidG1FirstValue => "CeremonyError::InvalidG1FirstValue",
                CeremonyError::InvalidG2FirstValue => "CeremonyError::InvalidG2FirstValue",
                CeremonyError::InvalidG1One(_) => "CeremonyError::InvalidG1One",
                CeremonyError::InvalidG2One(_) => "CeremonyError::InvalidG2One",
                CeremonyError::InvalidG2Pubkey(_) => "CeremonyError::InvalidG2Pubkey",
                CeremonyError::DuplicateG1(..) => "CeremonyError::DuplicateG1",
                CeremonyError::DuplicateG2(..) => "CeremonyError::DuplicateG2",
                CeremonyError::ContributionNoEntropy => "CeremonyError::ContributionNoEntropy",
                CeremonyError::WitnessLengthMismatch(..) => "CeremonyError::WitnessLengthMismatch",
            },
        };

        let body = Json(json!({
            "code": code,
            "error" : error
        }));

        (StatusCode::BAD_REQUEST, body).into_response()
    }
}
