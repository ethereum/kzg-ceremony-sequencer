#![cfg(test)]

use crate::{
    sessions::{IdToken, SessionInfo},
    Options,
};
use clap::Parser;
use kzg_ceremony_crypto::signature::identity::Identity;
use tokio::time::Instant;

#[must_use]
pub fn test_jwt(exp: u64) -> IdToken {
    IdToken {
        identity: Identity::Github {
            id:       1234,
            username: "test_user".to_string(),
        },
        exp,
    }
}

#[must_use]
pub fn create_test_session_info(exp: u64) -> SessionInfo {
    SessionInfo {
        token:                 test_jwt(exp),
        last_ping_time:        Instant::now(),
        is_first_ping_attempt: true,
    }
}

#[must_use]
pub fn test_options() -> Options {
    let args: Vec<&str> = vec![
        "kzg-ceremony-sequencer",
        "--gh-client-secret",
        "INVALID",
        "--gh-client-id",
        "INVALID",
        "--eth-rpc-url",
        "INVALID",
        "--eth-client-secret",
        "INVALID",
        "--eth-client-id",
        "INVALID",
        "--database-url",
        "sqlite://:memory:",
    ];
    Options::parse_from(args)
}
