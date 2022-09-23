#![cfg(test)]

use crate::mock_auth_service::{AuthState, GhUser};
use clap::Parser;
use http::StatusCode;
use kzg_ceremony_crypto::{Arkworks, BatchContribution, BatchTranscript};
use kzg_ceremony_sequencer::{io::read_json_file, start_server, Options};
use serde_json::Value;
use std::collections::HashMap;
use tempfile::{tempdir, TempDir};
use tokio::sync::{broadcast, oneshot, Mutex, MutexGuard, OnceCell};
use url::Url;

mod mock_auth_service;

fn test_options() -> Options {
    let args: Vec<&str> = vec![
        "kzg-ceremony-sequencer",
        "--ceremony-sizes",
        "4,3:8,3:16,3",
        "--server",
        "http://127.0.0.1:3000",
        "--gh-token-url",
        "http://127.0.0.1:3001/github/oauth/token",
        "--gh-userinfo-url",
        "http://127.0.0.1:3001/github/user",
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
        "sqlite::memory:",
    ];
    Options::parse_from(args)
}

struct Harness {
    options:         Options,
    auth_state:      AuthState,
    shutdown_sender: broadcast::Sender<()>,
    /// Needed to keep the lock on the server port for the duration of a test.
    #[allow(dead_code)]
    lock:            MutexGuard<'static, ()>,
    /// Needed to keep the temp directory alive throughout the test.
    #[allow(dead_code)]
    temp_dir:        TempDir,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown_sender.send(()).unwrap();
    }
}

static SERVER_LOCK: OnceCell<Mutex<()>> = OnceCell::const_new();

async fn server_lock() -> &'static Mutex<()> {
    SERVER_LOCK.get_or_init(|| async { Mutex::new(()) }).await
}

async fn run_test_harness() -> Harness {
    let lock = server_lock().await.lock().await;
    let temp_dir = tempdir().unwrap();
    let transcript = temp_dir.path().join("transcript.json");
    let transcript_wip = temp_dir.path().join("transcript.json.next");
    let mut options = test_options();
    options.transcript_file = transcript;
    options.transcript_in_progress_file = transcript_wip;
    let server_options = options.clone();
    let (shutdown_sender, mut app_shutdown_receiver) = broadcast::channel::<()>(1);
    let mut auth_shutdown_receiver = shutdown_sender.subscribe();
    let (app_start_sender, app_start_receiver) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let server = start_server(server_options).await.unwrap();
        app_start_sender.send(()).unwrap();
        server
            .with_graceful_shutdown(async move { app_shutdown_receiver.recv().await.unwrap() })
            .await
            .unwrap();
    });
    app_start_receiver.await.unwrap();
    let (auth_start_sender, auth_start_receiver) = oneshot::channel::<()>();
    let auth_state = AuthState::new();
    let auth_state_for_server = auth_state.clone();
    tokio::spawn(async move {
        let server = mock_auth_service::start_server(auth_state_for_server);
        auth_start_sender.send(()).unwrap();
        server
            .with_graceful_shutdown(async move { auth_shutdown_receiver.recv().await.unwrap() })
            .await
            .unwrap();
    });
    auth_start_receiver.await.unwrap();
    Harness {
        options: options.clone(),
        auth_state,
        shutdown_sender,
        lock,
        temp_dir,
    }
}

/// This function acts both as a test and a utility. This way, we'll test the
/// behavior in a variety of different app states.
async fn get_and_validate_csrf_token(harness: &Harness) -> String {
    let client = reqwest::Client::new();

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
            .expect("github_auth_url must be a string"),
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
            .expect("eth_auth_url must be a string"),
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

async fn login_gh_user(harness: &Harness, http_client: &reqwest::Client, name: String) -> String {
    // This code will normally be returned from the auth provider, through a
    // redirect to the frontend. Here we just get it when registering our fake user,
    // because it has nothing to do with this backend.
    let code = harness
        .auth_state
        .register_user(GhUser {
            created_at: "2022-01-01T00:00:00Z".to_string(),
            name,
        })
        .await;

    let csrf = get_and_validate_csrf_token(&harness).await;

    let callback_result = http_client
        .get(harness.options.server.join("auth/callback/github").unwrap())
        .query(&[("state", csrf), ("code", code.to_string())])
        .send()
        .await
        .expect("Could not call the endpoint");

    assert_eq!(callback_result.status(), StatusCode::OK);

    let session_id = callback_result
        .json::<Value>()
        .await
        .expect("Response must be valid JSON.")
        .get("session_id")
        .expect("Response must contain session_id")
        .as_str()
        .expect("session_id must be a string")
        .to_string();

    session_id
}

async fn try_contribute(
    harness: &Harness,
    http_client: &reqwest::Client,
    session_id: &str,
) -> BatchContribution {
    let response = http_client
        .post(harness.options.server.join("lobby/try_contribute").unwrap())
        .header("Authorization", format!("Bearer {session_id}"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Response must be successful"
    );

    let result = response
        .json::<BatchContribution>()
        .await
        .expect("Successful response must be a contribution");
    result
}

async fn contribute(
    harness: &Harness,
    http_client: &reqwest::Client,
    session_id: &str,
    contribution: &BatchContribution,
) {
    let response = http_client
        .post(harness.options.server.join("contribute").unwrap())
        .header("Authorization", format!("Bearer {session_id}"))
        .json(contribution)
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Response must be successful"
    );

    // TODO verify the receipt signature, after we switch to ETH sign.
}

#[tokio::test]
async fn test_auth_request_link() {
    let harness = run_test_harness().await;
    get_and_validate_csrf_token(&harness).await;
}

#[tokio::test]
async fn test_gh_auth_happy_path() {
    let harness = run_test_harness().await;
    let http_client = reqwest::Client::new();
    login_gh_user(&harness, &http_client, "kustosz".to_string()).await;
}

#[tokio::test]
async fn test_contribution_happy_path() {
    let harness = run_test_harness().await;
    let http_client = reqwest::Client::new();

    let session_id = login_gh_user(&harness, &http_client, "kustosz".to_string()).await;

    let mut contribution = try_contribute(&harness, &http_client, &session_id).await;

    // not only is it unguessable, it is also 32 characters long and we depend on
    // this.
    let entropy = "such an unguessable string, wow!"
        .bytes()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    contribution
        .add_entropy::<Arkworks>(entropy)
        .expect("Adding entropy must be possible");

    contribute(&harness, &http_client, &session_id, &contribution).await;

    let transcript =
        read_json_file::<BatchTranscript>(harness.options.transcript_file.clone()).await;

    let num_contributions = transcript
        .transcripts
        .iter()
        .map(|t| t.num_contributions())
        .collect::<Vec<_>>();
    assert_eq!(
        num_contributions,
        vec![1, 1, 1],
        "a new contribution must be registered"
    );

    let contrib_pubkeys = contribution
        .contributions
        .iter()
        .map(|contribution| contribution.pubkey)
        .collect::<Vec<_>>();
    let transcript_pubkeys = transcript
        .transcripts
        .iter()
        .map(|t| {
            t.witness
                .pubkeys
                .last()
                .expect("must have pubkeys for accepted contributions")
                .clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        contrib_pubkeys, transcript_pubkeys,
        "the pubkeys recorded in transcript must be the ones submitted"
    )
}
