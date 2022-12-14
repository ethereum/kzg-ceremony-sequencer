use serde::{Deserialize, Serialize};
use std::{fmt, fmt::Display, str::FromStr};
use thiserror::Error;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Identity {
    None,
    Ethereum { address: [u8; 20] },
    Github { id: u64, username: String },
}

impl Identity {
    /// Parse Ethereum identity from address from hex string.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] if the input is not a valid Ethereum address.
    pub fn eth_from_str(address: &str) -> Result<Self, IdentityError> {
        if address.len() != 42 || &address[..2] != "0x" {
            return Err(IdentityError::InvalidEthereumAddress);
        }
        let address = hex::decode(&address[2..])
            .map_err(|_| IdentityError::InvalidEthereumAddress)?
            .try_into()
            .map_err(|_| IdentityError::InvalidEthereumAddress)?;

        Ok(Self::Ethereum { address })
    }

    #[must_use]
    pub fn unique_id(&self) -> String {
        self.to_string()
    }

    #[must_use]
    pub fn nickname(&self) -> String {
        match self {
            Self::Ethereum { address } => format!("0x{}", hex::encode(address)),
            Self::Github { username, .. } => username.to_string(),
            Self::None => "<<unauthorized>>".to_string(),
        }
    }

    #[must_use]
    pub fn provider_name(&self) -> String {
        match self {
            Self::Ethereum { .. } => "Ethereum",
            Self::Github { .. } => "Github",
            Self::None => "None",
        }
        .to_string()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum IdentityError {
    #[error("invalid identity")]
    UnsupportedType,
    #[error("Missing fields")]
    MissingField,
    #[error("Too many fields")]
    TooManyFields,
    #[error("Invalid Ethereum address")]
    InvalidEthereumAddress,
    #[error("Invalid Github ID")]
    InvalidGithubId,
}

impl Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, ""),
            Self::Ethereum { address } => write!(f, "eth|0x{}", hex::encode(address)),
            Self::Github { id, username } => write!(f, "git|{id}|{username}"),
        }
    }
}

impl FromStr for Identity {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('|');
        match parts.next() {
            Some("eth") => {
                let address = parts.next().ok_or(IdentityError::MissingField)?;
                if parts.next().is_some() {
                    return Err(IdentityError::TooManyFields);
                }

                if address.len() != 42 || &address[..2] != "0x" {
                    return Err(IdentityError::InvalidEthereumAddress);
                }
                let address = hex::decode(&address[2..])
                    .map_err(|_| IdentityError::InvalidEthereumAddress)?
                    .try_into()
                    .map_err(|_| IdentityError::InvalidEthereumAddress)?;

                Ok(Self::Ethereum { address })
            }
            Some("git") => {
                let id = parts.next().ok_or(IdentityError::MissingField)?;
                let username = parts.next().ok_or(IdentityError::MissingField)?;
                if parts.next().is_some() {
                    return Err(IdentityError::TooManyFields);
                }

                let id = id.parse().map_err(|_| IdentityError::InvalidGithubId)?;
                let username = username.to_string();

                Ok(Self::Github { id, username })
            }
            Some("") => {
                if parts.next().is_some() {
                    return Err(IdentityError::TooManyFields);
                }
                Ok(Self::None)
            }
            _ => Err(IdentityError::UnsupportedType),
        }
    }
}

impl Serialize for Identity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none() {
        let identity = Identity::None;
        assert_eq!(identity.to_string(), "");
        assert_eq!(identity, "".parse().unwrap());
        assert_eq!(identity.provider_name(), "None");
        assert_eq!(identity.nickname(), "<<unauthorized>>");
    }

    #[test]
    fn test_eth() {
        let identity = Identity::Ethereum { address: [0; 20] };
        assert_eq!(
            identity.to_string(),
            "eth|0x0000000000000000000000000000000000000000"
        );
        assert_eq!(
            identity,
            "eth|0x0000000000000000000000000000000000000000"
                .parse()
                .unwrap()
        );
        assert_eq!(
            "eth|D".parse::<Identity>().err().unwrap(),
            IdentityError::InvalidEthereumAddress
        );
        assert_eq!(
            "eth|0xD".parse::<Identity>().err().unwrap(),
            IdentityError::InvalidEthereumAddress
        );
        assert_eq!(
            "eth|0x0000000000000000000000000000000000000000|"
                .parse::<Identity>()
                .err()
                .unwrap(),
            IdentityError::TooManyFields
        );
    }

    #[test]
    fn test_git() {
        let identity = Identity::Github {
            id:       123,
            username: "username".to_string(),
        };
        assert_eq!(identity.to_string(), "git|123|username");
        assert_eq!(identity, "git|123|username".parse().unwrap());
        assert_eq!(
            "git|123|username|".parse::<Identity>().err().unwrap(),
            IdentityError::TooManyFields
        );
    }

    #[test]
    fn test_invalid() {
        assert_eq!(
            "|".parse::<Identity>().err().unwrap(),
            IdentityError::TooManyFields
        );
        assert_eq!(
            "google|".parse::<Identity>().err().unwrap(),
            IdentityError::UnsupportedType
        );
    }
}
