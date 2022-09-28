#![cfg(test)]

use ethers_core::types::{Address, Signature};
use std::{collections::HashMap, io::Read, sync::Arc, time::Duration};

use http::StatusCode;
use oauth2::reqwest::http_client;
use serde_json::Value;
use tokio::{sync::RwLock, task::JoinHandle};
use url::Url;

use kzg_ceremony_crypto::{Arkworks, BatchContribution, BatchTranscript, G2};

use crate::common::harness::{run_test_harness, Harness};

mod common;

/// This function acts both as a test and a utility. This way, we'll test the
/// behavior in a variety of different app states.
async fn get_and_validate_csrf_token(harness: &Harness) -> String {
    let client = reqwest::Client::new();

    let response = client
        .get(harness.options.server.join("auth/request_link").unwrap())
        .send()
        .await
        .unwrap()
        .json::<Value>()
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

async fn request_gh_callback(
    harness: &Harness,
    http_client: &reqwest::Client,
    code: u64,
    csrf: &str,
) -> reqwest::Response {
    http_client
        .get(harness.options.server.join("auth/callback/github").unwrap())
        .query(&[("state", csrf), ("code", &code.to_string())])
        .send()
        .await
        .expect("Could not call the endpoint")
}

async fn extract_session_id_from_auth_response(response: reqwest::Response) -> String {
    response
        .json::<Value>()
        .await
        .expect("Response must be valid JSON.")
        .get("session_id")
        .expect("Response must contain session_id")
        .as_str()
        .expect("session_id must be a string")
        .to_string()
}

async fn login_gh_user(harness: &Harness, http_client: &reqwest::Client, name: String) -> String {
    // This code will normally be returned from the auth provider, through a
    // redirect to the frontend. Here we just get it when registering our fake user,
    // because it has nothing to do with this backend.
    let code = harness.create_valid_user(name).await;

    let csrf = get_and_validate_csrf_token(harness).await;

    let callback_result = request_gh_callback(harness, http_client, code, &csrf).await;

    assert_eq!(callback_result.status(), StatusCode::OK);
    extract_session_id_from_auth_response(callback_result).await
}

async fn request_try_contribute(
    harness: &Harness,
    http_client: &reqwest::Client,
    session_id: &str,
) -> reqwest::Response {
    http_client
        .post(harness.options.server.join("lobby/try_contribute").unwrap())
        .header("Authorization", format!("Bearer {session_id}"))
        .send()
        .await
        .unwrap()
}

async fn try_contribute(
    harness: &Harness,
    http_client: &reqwest::Client,
    session_id: &str,
) -> BatchContribution {
    let response = request_try_contribute(harness, http_client, session_id).await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Response must be successful"
    );

    response
        .json::<BatchContribution>()
        .await
        .expect("Successful response must be a contribution")
}

async fn request_contribute(
    harness: &Harness,
    http_client: &reqwest::Client,
    session_id: &str,
    contribution: &BatchContribution,
) -> reqwest::Response {
    http_client
        .post(harness.options.server.join("contribute").unwrap())
        .header("Authorization", format!("Bearer {session_id}"))
        .json(contribution)
        .send()
        .await
        .unwrap()
}

async fn get_sequencer_eth_address(harness: &Harness, http_client: &reqwest::Client) -> String {
    http_client
        .get(harness.app_path("/info/status"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()
        .get("sequencer_address")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

async fn contribute_successfully(
    harness: &Harness,
    http_client: &reqwest::Client,
    session_id: &str,
    contribution: &BatchContribution,
    username: &str,
) {
    let response = request_contribute(harness, http_client, session_id, contribution).await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Response must be successful"
    );

    let response_json = response
        .json::<Value>()
        .await
        .expect("Must return valid JSON");

    let receipt = response_json
        .get("receipt")
        .expect("must contain the receipt field")
        .as_str()
        .expect("receipt field must be a string");

    let signature: Signature = response_json
        .get("signature")
        .expect("must contain signature")
        .as_str()
        .expect("signature must be a string")
        .parse()
        .expect("must be a valid signature");

    let address: Address = get_sequencer_eth_address(harness, http_client)
        .await
        .parse()
        .unwrap();

    signature
        .verify(receipt, address)
        .expect("must be valid signature");

    let receipt_contents =
        serde_json::from_str::<Value>(receipt).expect("receipt must be a JSON-encoded string");
    let id_token = receipt_contents
        .get("id_token")
        .expect("must contain id_token");

    assert_eq!(
        id_token
            .get("nickname")
            .expect("must contain nickname")
            .as_str()
            .expect("nickname must be a string"),
        username
    );

    assert_eq!(
        id_token
            .get("provider")
            .expect("must contain provider")
            .as_str()
            .expect("provider must be a string"),
        "Github"
    );

    let witness: Vec<G2> = serde_json::from_value(
        receipt_contents
            .get("witness")
            .expect("must contain witness")
            .clone(),
    )
    .expect("witness must be a vector of G2 points");

    assert_eq!(
        witness,
        contribution
            .contributions
            .iter()
            .map(|c| c.pubkey)
            .collect::<Vec<_>>()
    )
}

fn assert_includes_contribution(transcript: &BatchTranscript, contribution: &BatchContribution) {
    transcript
        .transcripts
        .iter()
        .zip(contribution.contributions.iter())
        .for_each(|(t, c)| {
            assert!(t.witness.products.contains(&c.powers.g1[0]));
            assert!(t.witness.pubkeys.contains(&c.pubkey));
        })
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

    contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        "kustosz",
    )
    .await;

    let transcript = harness.read_transcript_file().await;

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
            *t.witness
                .pubkeys
                .last()
                .expect("must have pubkeys for accepted contributions")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        contrib_pubkeys, transcript_pubkeys,
        "the pubkeys recorded in transcript must be the ones submitted"
    )
}

#[tokio::test]
async fn test_double_contribution() {
    let harness = run_test_harness().await;
    let http_client = reqwest::Client::new();
    let auth_code = harness.create_valid_user("kustosz".to_string()).await;
    let csrf = get_and_validate_csrf_token(&harness).await;
    let session_id = extract_session_id_from_auth_response(
        request_gh_callback(&harness, &http_client, auth_code, &csrf).await,
    )
    .await;

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

    // First, successful contribution;
    contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        "kustosz",
    )
    .await;
    let transcript_with_first_contrib = harness.read_transcript_file().await;
    assert_includes_contribution(&transcript_with_first_contrib, &contribution);

    // Try contributing again right away – fails because the contribution spot is
    // emptied
    let second_contribute_response =
        request_contribute(&harness, &http_client, &session_id, &contribution).await;
    assert_eq!(second_contribute_response.status(), StatusCode::BAD_REQUEST);

    // Try pinging the lobby again – fails because the user got logged out
    let second_try_contribute_response =
        request_try_contribute(&harness, &http_client, &session_id).await;
    assert_eq!(
        second_try_contribute_response.status(),
        StatusCode::UNAUTHORIZED
    );

    // Try logging in again – fails because the user is banned from further use of
    // the app.
    let new_csrf = get_and_validate_csrf_token(&harness).await;
    let gh_login_response = request_gh_callback(&harness, &http_client, auth_code, &new_csrf).await;
    assert_eq!(gh_login_response.status(), StatusCode::BAD_REQUEST);

    let transcript_after_attempts = harness.read_transcript_file().await;
    assert_eq!(
        transcript_with_first_contrib, transcript_after_attempts,
        "must not change the transcript again"
    )
}

async fn well_behaved_participant(
    harness: &Harness,
    client: &reqwest::Client,
    name: String,
) -> BatchContribution {
    let session_id = login_gh_user(harness, client, name.clone()).await;
    let mut contribution = loop {
        let try_contribute_response = request_try_contribute(harness, client, &session_id).await;
        assert_eq!(try_contribute_response.status(), StatusCode::OK);
        let maybe_contribution = try_contribute_response
            .json::<BatchContribution>()
            .await
            .ok();
        if let Some(contrib) = maybe_contribution {
            break contrib;
        }

        tokio::time::sleep(
            harness.options.lobby.lobby_checkin_frequency
                - harness.options.lobby.lobby_checkin_tolerance,
        )
        .await;
    };

    let entropy = format!("{} such an unguessable string, wow!", name)
        .bytes()
        .take(32)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    contribution
        .add_entropy::<Arkworks>(entropy)
        .expect("Adding entropy must be possible");
    contribute_successfully(harness, client, &session_id, &contribution, &name).await;
    contribution
}

#[tokio::test]
async fn test_large_lobby() {
    let harness = Arc::new(run_test_harness().await);
    let client = Arc::new(reqwest::Client::new());
    tokio::time::pause();

    let handles = (0..10)
        .into_iter()
        .map(|i| {
            let h = harness.clone();
            let c = client.clone();
            tokio::spawn(async move {
                well_behaved_participant(h.as_ref(), c.as_ref(), format!("user {i}")).await
            })
        })
        .collect::<Vec<_>>();

    let mut contribs = vec![];

    for handle in handles {
        contribs.push(handle.await.unwrap());
    }

    let final_transcript = harness.read_transcript_file().await;
    contribs
        .iter()
        .for_each(|c| assert_includes_contribution(&final_transcript, c));
}
