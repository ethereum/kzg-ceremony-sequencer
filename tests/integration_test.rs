#![cfg(test)]

use clap::Parser;
use kzg_ceremony_sequencer::{async_main, start_server, Options};
use std::collections::HashMap;
use tempfile::tempdir;
use tokio::sync::oneshot;
use url::Url;

pub fn test_options() -> Options {
    let args: Vec<&str> = vec![
        "kzg-ceremony-sequencer",
        "--github-token-url",
        "http://127.0.0.1:3001/oauth/token",
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

#[tokio::test]
async fn auth_test() {
    let temp_dir = tempdir().unwrap();
    let transcript = temp_dir.path().join("transcript.json");
    let transcript_wip = temp_dir.path().join("transcript.json.next");
    let mut options = test_options();
    options.transcript_file = transcript;
    options.transcript_in_progress_file = transcript_wip;

    let (start_sender, start_receiver) = oneshot::channel::<()>();
    let (shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();
    let addr = options.server.clone();

    tokio::spawn(async move {
        let server = start_server(options).await.unwrap();
        start_sender.send(()).unwrap();
        server
            .with_graceful_shutdown(async { shutdown_receiver.await.unwrap() })
            .await
            .unwrap();
    });
    start_receiver.await.unwrap();

    let http_client = reqwest::Client::new();

    let response = http_client
        .get(addr.join("auth/request_link").unwrap())
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    let csrf = Url::parse(
        response
            .get("github_auth_url")
            .unwrap()
            .as_str()
            .unwrap()
            .clone(),
    )
    .unwrap()
    .query_pairs()
    .into_owned()
    .collect::<HashMap<_, _>>()
    .remove("state")
    .unwrap();

    let callback_result = http_client
        .get(addr.join("auth/callback/github").unwrap())
        .query(&[("state", csrf), ("code", "1234".to_string())])
        .send().await;

    println!("{:?}", callback_result.unwrap().bytes().await.unwrap());

    assert_eq!(1, 1);
    shutdown_sender.send(()).unwrap();
}
