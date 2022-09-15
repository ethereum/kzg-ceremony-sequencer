use std::fmt::{Display, Formatter};

use crate::jwt::{errors::JwtError, IdToken};
use async_session::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    TypedHeader,
};
use headers::{authorization::Bearer, Authorization};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Debug, Hash, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename = "session_id")]
pub struct SessionId(String);

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
    type Rejection = JwtError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|_| JwtError::InvalidToken)?;

        Ok(Self(bearer.token().to_owned()))
    }
}
