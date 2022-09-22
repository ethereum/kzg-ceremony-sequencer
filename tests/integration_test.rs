#![cfg(test)]

use crate::mock_auth_service::{AuthState, GhUser};
use clap::Parser;
use cli_batteries::await_shutdown;
use http::StatusCode;
use kzg_ceremony_sequencer::{start_server, Options};
use std::collections::HashMap;
use tempfile::tempdir;
use tokio::sync::{broadcast, oneshot, Mutex, OnceCell};
use url::Url;

mod mock_auth_service;

fn test_options() -> Options {
    let args: Vec<&str> = vec![
        "kzg-ceremony-sequencer",
        "--server",
        "http://127.0.0.1:3000",
        "--github-token-url",
        "http://127.0.0.1:3001/github/oauth/token",
        "--github-userinfo-url",
        "http://127.0.0.1:3001/github/user",
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

struct Harness {
    options:     Options,
    auth_state:  AuthState,
    http_client: Mutex<reqwest::Client>,
}

static SERVER: OnceCell<Harness> = OnceCell::const_new();

async fn run_test_harness() -> Harness {
    let temp_dir = tempdir().unwrap();
    let transcript = temp_dir.path().join("transcript.json");
    let transcript_wip = temp_dir.path().join("transcript.json.next");
    let mut options = test_options();
    options.transcript_file = transcript;
    options.transcript_in_progress_file = transcript_wip;
    let server_options = options.clone();
    let (app_start_sender, app_start_receiver) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let server = start_server(server_options).await.unwrap();
        app_start_sender.send(()).unwrap();
        server.await.unwrap();
    });
    app_start_receiver.await.unwrap();
    let (auth_start_sender, auth_start_receiver) = oneshot::channel::<()>();
    let auth_state = AuthState::new();
    let auth_state_for_server = auth_state.clone();
    tokio::spawn(async move {
        let server = mock_auth_service::start_server(auth_state_for_server);
        auth_start_sender.send(()).unwrap();
        server.await.unwrap();
    });
    auth_start_receiver.await.unwrap();
    Harness {
        options: options.clone(),
        auth_state,
        http_client: Mutex::new(
            reqwest::Client::builder()
                .pool_max_idle_per_host(0)
                .build()
                .unwrap(),
        ),
    }
}

async fn global_test_harness() -> &'static Harness {
    SERVER
        .get_or_init(|| async { run_test_harness().await })
        .await
}

/// This function acts both as a test and a utility. This way, we'll test the
/// behavior in a variety of different app states.
async fn get_and_validate_csrf_token() -> String {
    let harness = global_test_harness().await;

    let client = harness.http_client.lock().await;

    let response = client
        .get(harness.options.server.join("auth/request_link").unwrap())
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    let csrf_for_gh = Url::parse(
        response
            .get("github_auth_url")
            .expect("/auth/request_link response must contain a github_auth_url")
            .as_str()
            .expect("github_auth_url must be a string")
            .clone(),
    )
    .expect("github_auth_url must be a valid Url")
    .query_pairs()
    .into_owned()
    .collect::<HashMap<_, _>>()
    .remove("state")
    .expect("github_auth_url must contain an url-encoded CSRF token");

    let csrf_for_eth = Url::parse(
        response
            .get("eth_auth_url")
            .expect("/auth/request_link response must contain an eth_auth_url")
            .as_str()
            .expect("eth_auth_url must be a string")
            .clone(),
    )
    .expect("eth_auth_url must be a valid Url")
    .query_pairs()
    .into_owned()
    .collect::<HashMap<_, _>>()
    .remove("state")
    .expect("eth_auth_url must contain an url-encoded CSRF token");

    assert_eq!(
        csrf_for_eth, csrf_for_gh,
        "CSRF tokens must be the same for all providers but got {} and {}",
        csrf_for_eth, csrf_for_gh
    );

    csrf_for_eth
}

#[tokio::test]
async fn test_auth_request_link() {
    get_and_validate_csrf_token().await;
}

#[tokio::test]
async fn test_gh_auth_happy_path() {
    let harness = global_test_harness().await;

    harness
        .auth_state
        .clone()
        .register_user(1234, GhUser {
            created_at: "2022-01-01T00:00:00Z".to_string(),
            name:       "kustosz".to_string(),
        })
        .await;

    let csrf = get_and_validate_csrf_token().await;

    let client = harness.http_client.lock().await;

    let callback_result = client
        .get(harness.options.server.join("auth/callback/github").unwrap())
        .query(&[("state", csrf), ("code", "1234".to_string())])
        .send()
        .await
        .expect("Could not call the endpoint");

    assert_eq!(callback_result.status(), StatusCode::OK);
}

// #[tokio::test]
// async fn integration_test() {
//     test_auth_request_link().await;
//     test_gh_auth_happy_path().await;
// }
