#![cfg(test)]

use tokio::time::Instant;

use crate::{jwt, sessions::SessionInfo, Options};
use clap::Parser;

pub fn test_jwt(exp: u64) -> jwt::IdToken {
    jwt::IdToken {
        sub: String::from("foo"),
        nickname: String::from("foo"),
        provider: String::from("foo"),
        exp,
    }
}

pub fn create_test_session_info(exp: u64) -> SessionInfo {
    SessionInfo {
        token:                 test_jwt(exp),
        last_ping_time:        Instant::now(),
        is_first_ping_attempt: true,
    }
}

pub fn test_options() -> Options {
    let args: Vec<&str> = vec![
        "kzg-ceremony-sequencer",
        "--github-client-secret",
        "INVALID",
        "--github-client-id",
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
