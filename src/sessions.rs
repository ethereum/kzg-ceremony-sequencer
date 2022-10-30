use async_session::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    TypedHeader,
};
use headers::{authorization::Bearer, Authorization};
use http::StatusCode;
use kzg_ceremony_crypto::{signature::identity::Identity, ErrorCode};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use strum::IntoStaticStr;
use thiserror::Error;
use tokio::time::Instant;
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

#[derive(Debug, Error, IntoStaticStr)]
pub enum SessionError {
    #[error("unknown session id")]
    InvalidSessionId,
}

impl ErrorCode for SessionError {
    fn to_error_code(&self) -> String {
        format!("SessionError::{}", <&str>::from(self))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IdToken {
    pub identity: Identity,
    pub exp:      u64,
}

impl IdToken {
    // The sub field is used as a unique identifier
    // For example, see: https://developers.google.com/identity/protocols/oauth2/openid-connect#obtainuserinfo
    // We can use this to identify when a user signs in with the same
    // login and signup
    pub fn unique_identifier(&self) -> String {
        self.identity.unique_id()
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
                .map_err(|_| SessionError::InvalidSessionId)?;

        Ok(Self(bearer.token().to_owned()))
    }
}
