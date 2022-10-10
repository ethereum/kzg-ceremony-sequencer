use std::{fmt, fmt::Display, str::FromStr};
use thiserror::Error;

pub enum Identity {
    None,
    Ethereum { address: [u8; 20] },
    Github { id: u64, username: String },
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
    #[error("Invalid Github username")]
    InvalidGithubUsername,
}

impl Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Identity::None => write!(f, ""),
            Identity::Ethereum { address } => write!(f, "eth|0x{}", hex::encode(address)),
            Identity::Github { id, username } => write!(f, "git|{}|{}", id, username),
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
                parts
                    .next()
                    .is_some()
                    .then(|| ())
                    .ok_or(IdentityError::TooManyFields)?;

                let address = hex::decode(address)
                    .map_err(|_| IdentityError::InvalidEthereumAddress)?
                    .try_into()
                    .map_err(|_| IdentityError::InvalidEthereumAddress)?;

                Ok(Identity::Ethereum { address })
            }
            Some("git") => {
                let id = parts.next().ok_or(IdentityError::MissingField)?;
                let username = parts.next().ok_or(IdentityError::MissingField)?;
                parts
                    .next()
                    .is_some()
                    .then(|| ())
                    .ok_or(IdentityError::TooManyFields)?;

                let id = id.parse().map_err(|_| IdentityError::InvalidGithubId)?;
                let username = username.to_string();

                Ok(Identity::Github { id, username })
            }
            Some(_) => Err(IdentityError::UnsupportedType),
            None => Ok(Identity::None),
        }
    }
}
