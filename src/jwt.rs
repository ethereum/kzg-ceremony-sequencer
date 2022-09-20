pub mod errors;
use errors::JwtError;

use crate::{keys, Keys};
use serde::{Deserialize, Serialize};

// Receipt for contributor that sequencer has
// included their contribution
#[derive(Serialize)]
pub struct Receipt<T> {
    pub(crate) id_token: IdToken,
    pub witness:         T,
}

impl<T: Serialize> Receipt<T> {
    pub fn encode(&self, keys: &keys::Keys) -> Result<String, JwtError> {
        keys.encode(self).map_err(|_| JwtError::TokenCreation)
    }
}

// This is the JWT token that the sequencer will hand out to contributors
// after they have authenticated through oAUTH
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn encode(&self, keys: &Keys) -> Result<String, JwtError> {
        keys.encode(self).map_err(|_| JwtError::TokenCreation)
    }

    #[allow(unused)]
    pub fn decode(token: &str, keys: &Keys) -> Result<Self, JwtError> {
        let token_data = keys.decode(token).map_err(|_| JwtError::InvalidToken)?;
        Ok(token_data.claims)
    }
}
