use crate::jwt::{errors::JwtError, IdToken};
use async_session::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    TypedHeader,
};
use headers::{authorization::Bearer, Authorization};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Hash, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SessionId {
    // TODO: Can change to a named tuple, just need to check how serde
    // deserialises everything
    session_id: String,
}

impl SessionId {
    // Create a random session id
    pub fn new() -> SessionId {
        SessionId {
            session_id: Uuid::new_v4().to_string(),
        }
    }

    pub fn to_string(&self) -> String {
        self.session_id.to_owned()
    }
    pub fn as_string(&self) -> &str {
        &self.session_id
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SessionInfo {
    pub(crate) token: IdToken,
    // Specifies the last time the user pinged
    pub(crate) last_ping_time: Instant,
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
        let session_id = SessionId {
            session_id: bearer.token().to_owned(),
        };
        Ok(session_id)
    }
}
