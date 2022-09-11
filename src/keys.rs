use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use once_cell::sync::Lazy;
use serde::{de::DeserializeOwned, Serialize};
use std::str::FromStr;

// Keys needed by the sequencer to attest to JWT claims
pub(crate) static KEYS: Lazy<Keys> = Lazy::new(|| Keys::new());

pub(crate) struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new() -> Self {
        let private_key = include_bytes!("../private.key");
        let public_key = include_bytes!("../publickey.pem");
        Self {
            encoding: EncodingKey::from_rsa_pem(private_key).unwrap(),
            decoding: DecodingKey::from_rsa_pem(public_key).unwrap(),
        }
    }

    pub(crate) fn encode<T: Serialize>(
        &self,
        token: &T,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        encode(&Header::new(Keys::alg()), token, &self.encoding)
    }
    #[allow(unused)]
    pub(crate) fn decode<T: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<TokenData<T>, jsonwebtoken::errors::Error> {
        decode::<T>(token, &self.decoding, &Validation::new(Keys::alg()))
    }

    pub fn alg_str() -> &'static str {
        "PS256"
    }
    fn alg() -> Algorithm {
        Algorithm::from_str(Keys::alg_str()).expect("unknown algorithm")
    }

    pub fn decode_key_to_string(&self) -> String {
        include_str!("../publickey.pem").to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[test]
    fn encode_decode_pem() {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub struct Token {
            foo: String,
            exp: u64,
        }

        let t = Token {
            foo: String::from("hello world"),
            exp: 200000000000,
        };

        let keys = Keys::new();
        let encoded_token = keys.encode(&t).unwrap();
        let token_data = keys.decode::<Token>(&encoded_token).unwrap();
        let got_token = token_data.claims;

        assert_eq!(got_token, t)
    }
}
