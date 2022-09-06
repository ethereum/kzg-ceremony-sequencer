use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use once_cell::sync::Lazy;
use serde::{de::DeserializeOwned, Serialize};

// Keys needed by the coordinator to attest to JWT claims
pub(crate) static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

pub(crate) struct Keys {
    pub(crate) encoding: EncodingKey,
    pub(crate) decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        // TODO: This uses HMAC which is not right for our usecase
        // TODO: since we want contributors to verify the veracity of
        // TODO: of the token
        // TODO: we will add the public key to AuthBody when we send it to contributor
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }

    pub fn encode<T: Serialize>(&self, token: &T) -> Result<String, jsonwebtoken::errors::Error> {
        encode(&Header::default(), token, &self.encoding)
    }
    pub fn decode<T: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<TokenData<T>, jsonwebtoken::errors::Error> {
        decode::<T>(token, &self.decoding, &Validation::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[test]
    fn encode_decode() {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub struct Token {
            foo: String,
            exp: u64,
        }

        let t = Token {
            foo: String::from("hello world"),
            exp: 200000000000,
        };

        let keys = Keys::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let encoded_token = keys.encode(&t).unwrap();
        let token_data = keys.decode::<Token>(&encoded_token).unwrap();
        let got_token = token_data.claims;

        assert_eq!(got_token, t)
    }
}
