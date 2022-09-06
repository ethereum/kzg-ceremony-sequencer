use super::errors::AuthError;
use crate::{
    auth::keys,
    config::{COMPUTE_DEADLINE, SECS_TO_MILLISECS},
};
use async_session::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    headers::authorization::Bearer,
    TypedHeader,
};
use headers::Authorization;
use jsonwebtoken::{decode, encode, Header, Validation};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

// Receipt for contributor that coordinator has
// included their contribution
#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub(crate) id_token: IdToken,
    // This is the witness
    pub witness: u64,
}
// TODO: this is not really auth related
// TODO: will move in the future
pub(crate) fn create_receipt_jwt(receipt: &Receipt) -> Result<String, AuthError> {
    let token = encode(&Header::default(), receipt, &keys::KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    Ok(token)
}

// This is the JWT token that the coordinator will hand out to contributors
// after they have authenticated through oAUTH
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IdToken {
    pub(crate) sub: String,
    pub nickname: String,
    // The provider whom the client used to login with
    // Example, Google, Ethereum, Facebook
    pub provider: String,
    pub exp: u64,
}

impl IdToken {
    // The sub field is used as a unique identifier
    // For example, see: https://developers.google.com/identity/protocols/oauth2/openid-connect#obtainuserinfo
    // We can then use this to identify users in the queue
    // TODO: we could use UUID instead as this is only need to place users in the queue
    // TODO: though sub field is cleaner
    pub fn unique_identifier(&self) -> &str {
        &self.sub
    }

    pub fn encode(&self) -> Result<String, AuthError> {
        encode(&Header::default(), self, &crate::auth::keys::KEYS.encoding)
            .map_err(|_| AuthError::TokenCreation)
    }
    pub fn decode(contrib_token: &str) -> Result<Self, AuthError> {
        let token_data =
            decode::<Self>(contrib_token, &keys::KEYS.decoding, &Validation::default())
                .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[async_trait]
impl<B> FromRequest<B> for IdToken
where
    B: Send,
{
    type Rejection = AuthError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data =
            decode::<IdToken>(bearer.token(), &keys::KEYS.decoding, &Validation::default())
                .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

impl Display for IdToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Subject: {}\nCompany: {}", self.sub, self.provider)
    }
}

// AccessToken gives users access to ping the server
// and exchange the AccessToken for a ContributionToken
// at some point in the future
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessToken {
    // Unique identifier
    pub sub: String,
    pub exp: u64,
}

impl AccessToken {
    pub fn unique_identifier(&self) -> &str {
        &self.sub
    }

    pub fn from_id(id: String) -> Self {
        // Every access token expires after COMPUTE_DEADLINE
        AccessToken {
            sub: id,
            exp: (COMPUTE_DEADLINE * SECS_TO_MILLISECS) as u64,
        }
    }

    pub fn refresh(access_token: &str) -> Result<AccessToken, AuthError> {
        let token_data = decode::<Self>(access_token, &keys::KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(AccessToken::from_id(token_data.claims.sub))
    }

    pub fn encode(&self) -> Result<String, AuthError> {
        encode(&Header::default(), self, &crate::auth::keys::KEYS.encoding)
            .map_err(|_| AuthError::TokenCreation)
    }
    pub fn decode(access_token: &str) -> Result<Self, AuthError> {
        let token_data = decode::<Self>(access_token, &keys::KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[async_trait]
impl<B> FromRequest<B> for AccessToken
where
    B: Send,
{
    type Rejection = AuthError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data =
            decode::<AccessToken>(bearer.token(), &keys::KEYS.decoding, &Validation::default())
                .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: String,
    pub exp: u64,
}

impl RefreshToken {
    pub fn from_id_position(id: String, queue_position: usize) -> Self {
        RefreshToken {
            id,
            exp: Self::compute_worse_case_queue_time_in_ms(queue_position),
        }
    }

    // computes the worse case time for a participant and returns that in milliseconds
    fn compute_worse_case_queue_time_in_ms(position_in_queue: usize) -> u64 {
        // The worse case is when each participant takes too long
        // and hits the deadline.
        let worse_case_time_in_seconds = COMPUTE_DEADLINE * position_in_queue;

        (worse_case_time_in_seconds * SECS_TO_MILLISECS) as u64
    }

    pub fn encode(&self) -> Result<String, AuthError> {
        encode(&Header::default(), self, &crate::auth::keys::KEYS.encoding)
            .map_err(|_| AuthError::TokenCreation)
    }
    pub fn decode(access_token: &str) -> Result<Self, AuthError> {
        let token_data = decode::<Self>(access_token, &keys::KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[async_trait]
impl<B> FromRequest<B> for RefreshToken
where
    B: Send,
{
    type Rejection = AuthError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data =
            decode::<RefreshToken>(bearer.token(), &keys::KEYS.decoding, &Validation::default())
                .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[derive(Debug, Serialize, Deserialize)]
// This token is used to contribute to the ceremony
pub struct ContributionToken {
    id_token: IdToken,
    exp: u64,
}

impl ContributionToken {
    pub(crate) fn from_id_token(id_token: IdToken) -> Self {
        Self {
            id_token,
            exp: Self::exp(),
        }
    }

    const fn exp() -> u64 {
        // These are valid for as long as the user is allowed to contribute for
        COMPUTE_DEADLINE as u64
    }

    pub fn encode(&self) -> Result<String, AuthError> {
        encode(&Header::default(), self, &crate::auth::keys::KEYS.encoding)
            .map_err(|_| AuthError::TokenCreation)
    }
    pub fn decode(contrib_token: &str) -> Result<Self, AuthError> {
        let token_data =
            decode::<Self>(contrib_token, &keys::KEYS.decoding, &Validation::default())
                .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}
