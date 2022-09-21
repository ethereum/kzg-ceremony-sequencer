pub mod errors;
use errors::JwtError;

use crate::keys::{Keys, Signature};
use serde::{Deserialize, Serialize};

// Receipt for contributor that sequencer has
// included their contribution
#[derive(Serialize)]
pub struct Receipt<T> {
    pub(crate) id_token: IdToken,
    pub witness:         T,
}

#[derive(Serialize)]
pub struct SignedReceipt {
    pub receipt_message: String,
    pub signature: Signature,
}

impl<T: Serialize> Receipt<T> {
    pub async fn sign(&self, keys: &Keys) -> Result<SignedReceipt, JwtError> {
        let receipt_message = serde_json::to_string(self).unwrap();
        keys
            .sign(&receipt_message)
            .await
            .map(move |signature| {
                SignedReceipt {
                    receipt_message,
                    signature
                }
            })
            .map_err(|_| JwtError::TokenCreation)
    }
}

// This is the JWT token that the sequencer will hand out to contributors
// after they have authenticated through oAUTH
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IdToken {
    pub sub:      String,
    pub nickname: String,
    // The provider whom the client used to login with
    // Example, Google, Ethereum, Facebook
    pub provider: String,
    pub exp:      u64,
}

#[derive(Serialize)]
pub struct SignedIdToken {
    pub token_message: String,
    pub signature: Signature,

}

impl IdToken {
    // The sub field is used as a unique identifier
    // For example, see: https://developers.google.com/identity/protocols/oauth2/openid-connect#obtainuserinfo
    // We can use this to identify when a user signs in with the same
    // login and signup
    pub fn unique_identifier(&self) -> &str {
        &self.sub
    }

    pub async fn sign(&self, keys: &Keys) -> Result<SignedIdToken, JwtError> {
        let token_message = serde_json::to_string(&self).unwrap();

        keys
            .sign(&token_message)
            .await
            .map(move |signature| {
                SignedIdToken {
                    token_message,
                    signature
                }
            })
            .map_err(|_| JwtError::TokenCreation)
    }

    pub fn verify(token: &SignedIdToken, keys: &Keys) -> Result<Self, JwtError> {
        let is_valid = keys.verify(&token.token_message, &token.signature);

        if !is_valid {
            return Err(JwtError::InvalidToken);
        }

        serde_json::from_str(&token.token_message)
            .map_err(|_| JwtError::TokenCreation)
    }
}
