use clap::Parser;
use ethers_signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer};
use eyre::Result;
use serde::Serialize;
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

    pub async fn sign(&self, message: &str) -> Result<Signature> {
        let signature = self.wallet.sign_message(message).await?;
        Ok(Signature(hex::encode::<Vec<u8>>(signature.into())))
    }

    pub fn verify(&self, message: &str, signature: &Signature) -> bool {
        false
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
    async fn develop_crypto() {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub struct Token {
            foo: String,
            exp: u64,
        }

        let wallet = MnemonicBuilder::<English>::default()
            .phrase(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon about",
            )
            .build()
            .unwrap();

        let message = wallet.sign_message(&[0, 1, 2]).await;
        println!("message: {:?}", message);
    }

    #[tokio::test]
    async fn encode_decode_pem() {
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

        assert!(keys.verify(&message, &signature));
    }
}
