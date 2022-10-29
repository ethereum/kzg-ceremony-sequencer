use clap::Parser;
use ethers_core::{
    rand::thread_rng,
    types::{RecoveryMessage, H160},
    utils::to_checksum,
};
use ethers_signers::{LocalWallet, Signer};
use eyre::Result;
use kzg_ceremony_crypto::ErrorCode;
use serde::Serialize;
use std::{fmt, sync::Arc};
use strum::IntoStaticStr;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
#[group(skip)]
pub struct Options {
    /// Ethereum private key to use for signing receipts.
    #[clap(long, env)]
    pub signing_key: Option<String>,
}

#[derive(Serialize)]
pub struct Signature(String);

#[derive(Debug, Error, IntoStaticStr)]
pub enum SignatureError {
    #[error("couldn't sign the receipt")]
    SignatureCreation,
    #[error("signature is not a valid hex string")]
    InvalidToken,
    #[error("couldn't create signature from string")]
    InvalidSignature,
}

impl ErrorCode for SignatureError {
    fn to_error_code(&self) -> String {
        format!("SignatureError::{}", <&str>::from(self))
    }
}

pub struct Keys {
    wallet: LocalWallet,
}

pub type SharedKeys = Arc<Keys>;

#[derive(Debug, Eq, PartialEq)]
pub struct Address(H160);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", to_checksum(&self.0, None))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&to_checksum(&self.0, None))
    }
}

impl Keys {
    pub fn new(options: &Options) -> Result<Self> {
        match &options.signing_key {
            Some(signing_key) => {
                let wallet = signing_key.parse::<LocalWallet>()?;
                info!(address = ?wallet.address(), "Wallet created from the provided signing key");
                Ok(Self { wallet })
            }
            None => {
                let wallet = LocalWallet::new(&mut thread_rng());
                warn!(address = ?wallet.address(), "Random wallet created. Make sure to provide a signing key in prod!");
                Ok(Self { wallet })
            }
        }
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

    pub fn address(&self) -> Address {
        Address(self.wallet.address())
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

        let options = Options::parse_from(Vec::<&str>::new());
        let keys = Keys::new(&options).unwrap();

        let message = serde_json::to_string(&t).unwrap();
        let signature = keys.sign(&message).await.unwrap();

        let result = keys.verify(&message, &signature);
        println!("result {:?}", result);
    }
}
