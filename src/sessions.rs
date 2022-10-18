use async_session::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    response::{IntoResponse, Response},
    Json, TypedHeader,
};
use headers::{authorization::Bearer, Authorization};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt::{Display, Formatter};
use thiserror::Error;
use tokio::time::Instant;
use tracing::warn;
use uuid::Uuid;

#[derive(Debug, Hash, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename = "session_id")]
pub struct SessionId(pub String);

impl SessionId {
    // Create a random session id
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for SessionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("unknown session id")]
    InvalidSessionId,
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::InvalidSessionId => (StatusCode::BAD_REQUEST, "invalid Bearer token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IdToken {
    pub sub:      String,
    pub nickname: String,
    // The provider whom the client used to login with
    // Example, Google, Ethereum, Facebook
    pub provider: String,
    pub exp:      u64,
}

impl IdToken {
    // The sub field is used as a unique identifier
    // For example, see: https://developers.google.com/identity/protocols/oauth2/openid-connect#obtainuserinfo
    // We can use this to identify when a user signs in with the same
    // login and signup
    pub fn unique_identifier(&self) -> &str {
        &self.sub
    }
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub token:                 IdToken,
    // Specifies the last time the user pinged
    pub last_ping_time:        Instant,
    // Indicates whether an early /lobby/try_contribute call is accepted.
    // (only allowed right after authentication)
    pub is_first_ping_attempt: bool,
}

#[async_trait]
impl<B> FromRequest<B> for SessionId
where
    B: Send,
{
    type Rejection = SessionError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|_| {
                    warn!("Bearer token missing");
                    SessionError::InvalidSessionId
                })?;

        Ok(Self(bearer.token().to_owned()))
    }
}
