use clap::Parser;
use eyre::Result;
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Serialize};
use std::{path::PathBuf, str::FromStr};
use tokio::try_join;
use tracing::info;

// TODO: Make part of app state instead of global
pub static KEYS: OnceCell<Keys> = OnceCell::new();

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct Options {
    /// Public key file (.pem) to use for JWT verification
    #[clap(long, env, default_value = "publickey.pem")]
    pub public_key: PathBuf,

    /// Private key file (.key) to use for JWT verification
    #[clap(long, env, default_value = "private.key")]
    pub private_key: PathBuf,
}

pub struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    pubkey:   String,
}

impl Keys {
    pub async fn new(options: Options) -> Result<Self> {
        info!(public_key = ?options.public_key, private_key=?options.private_key, "Loading JWT keys");
        let (private_key, public_key) = try_join!(
            tokio::fs::read(&options.private_key),
            tokio::fs::read(&options.public_key)
        )?;
        Ok(Self {
            encoding: EncodingKey::from_rsa_pem(&private_key)?,
            decoding: DecodingKey::from_rsa_pem(&public_key)?,
            pubkey:   String::from_utf8(public_key)?,
        })
    }

    pub fn encode<T: Serialize>(&self, token: &T) -> Result<String, jsonwebtoken::errors::Error> {
        encode(&Header::new(Self::alg()), token, &self.encoding)
    }

    #[allow(unused)]
    pub fn decode<T: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<TokenData<T>, jsonwebtoken::errors::Error> {
        decode::<T>(token, &self.decoding, &Validation::new(Self::alg()))
    }

    pub const fn alg_str() -> &'static str {
        "PS256"
    }

    fn alg() -> Algorithm {
        Algorithm::from_str(Self::alg_str()).expect("unknown algorithm")
    }

    pub fn decode_key_to_string(&self) -> String {
        self.pubkey.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[ignore] // Do not run this test by default due to dependency on files.
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

        let keys = Keys::new(Options {
            public_key:  "../publickey.pem".into(),
            private_key: "../private.key".into(),
        })
        .await
        .unwrap();
        let encoded_token = keys.encode(&t).unwrap();
        let token_data = keys.decode::<Token>(&encoded_token).unwrap();
        let got_token = token_data.claims;

        assert_eq!(got_token, t);
    }
}
