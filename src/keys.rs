use axum::{
    response::{IntoResponse, Response},
    Json,
};
use clap::Parser;
use ethers_core::types::RecoveryMessage;
use ethers_signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer};
use eyre::Result;
use http::StatusCode;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct Options {
    #[clap(
        long,
        env,
        default_value = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon about"
    )]
    pub mnemonic: String,
}

#[derive(Serialize)]
pub struct Signature(String);

#[derive(Debug)]
pub enum SignatureError {
    SignatureCreation,
    InvalidToken,
    InvalidSignature,
}

impl IntoResponse for SignatureError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::SignatureCreation => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "couldn't sign the receipt",
            ),
            Self::InvalidToken => (
                StatusCode::BAD_REQUEST,
                "signature is not a valid hex string",
            ),
            Self::InvalidSignature => (
                StatusCode::BAD_REQUEST,
                "couldn't create signature from string",
            ),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

pub struct Keys {
    wallet: LocalWallet,
}

pub type SharedKeys = Arc<Keys>;

impl Keys {
    pub async fn new(options: &Options) -> Result<Self> {
        let phrase = options.mnemonic.as_ref();
        let wallet = MnemonicBuilder::<English>::default()
            .phrase(phrase)
            .build()?;
        Ok(Self { wallet })
    }

    pub async fn sign(&self, message: &str) -> Result<Signature, SignatureError> {
        let signature = self
            .wallet
            .sign_message(message)
            .await
            .map_err(|_| SignatureError::SignatureCreation)?;
        Ok(Signature(hex::encode::<Vec<u8>>(signature.into())))
    }

    #[allow(unused)]
    pub fn verify(&self, message: &str, signature: &Signature) -> Result<(), SignatureError> {
        let h = hex::decode(&signature.0).map_err(|_| SignatureError::InvalidToken)?;
        let signature = ethers_core::types::Signature::try_from(h.as_ref())
            .map_err(|_| SignatureError::InvalidSignature)?;
        signature
            .verify(
                RecoveryMessage::Data(message.as_bytes().to_owned()),
                self.wallet.address(),
            )
            .map_err(|_| SignatureError::InvalidToken)
    }

    pub fn address(&self) -> String {
        let adr = self.wallet.address();
        hex::encode(adr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[tokio::test]
    async fn sign_and_verify() {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub struct Token {
            foo: String,
            exp: u64,
        }

        let t = Token {
            foo: String::from("hello world"),
            exp: 200_000_000_000,
        };

        let keys = Keys::new(&Options {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon about"
                .into(),
        })
        .await
        .unwrap();

        let message = serde_json::to_string(&t).unwrap();
        let signature = keys.sign(&message).await.unwrap();

        let result = keys.verify(&message, &signature);
        println!("result {:?}", result);
    }
}
