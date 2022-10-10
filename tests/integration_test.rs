#![cfg(test)]

use crate::common::{
    harness,
    harness::{run_test_harness, Harness},
};
use ethers_core::types::{Address, Signature};
use http::StatusCode;
use kzg_ceremony_crypto::{Arkworks, BatchContribution, BatchTranscript, G2};
use secrecy::Secret;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc, time::Duration};
use url::Url;

mod common;

/// This function acts both as a test and a utility. This way, we'll test the
/// behavior in a variety of different app states.
async fn get_and_validate_csrf_token(harness: &Harness, redirect_url: Option<&str>) -> String {
    let client = reqwest::Client::new();

    let mut url = harness.app_path("auth/request_link");
    redirect_url.into_iter().for_each(|redirect| {
        url.query_pairs_mut().append_pair("redirect_to", redirect);
    });

    let response = client
        .get(url)
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

fn entropy_from_str(seed: &str) -> Secret<[u8; 32]> {
    let padding = "padding".repeat(5);
    let entropy = format!("{seed}{padding}")
        .bytes()
        .take(32)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    Secret::new(entropy)
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

    let csrf = get_and_validate_csrf_token(harness, None).await;

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
            .map(|c| c.pot_pubkey)
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
            assert!(t.witness.pubkeys.contains(&c.pot_pubkey));
        })
}

#[tokio::test]
async fn test_auth_request_link() {
    let harness = run_test_harness().await;
    get_and_validate_csrf_token(&harness, None).await;
}

#[tokio::test]
async fn test_gh_auth_happy_path() {
    let harness = run_test_harness().await;
    let http_client = reqwest::Client::new();
    login_gh_user(&harness, &http_client, "kustosz".to_string()).await;
}

#[tokio::test]
async fn test_gh_auth_with_custom_frontend_redirect() {
    let harness = run_test_harness().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let csrf =
        get_and_validate_csrf_token(&harness, Some("https://my.magical.frontend/post-sign-in"))
            .await;
    let code = harness.create_valid_user("kustosz".to_string()).await;
    let auth_response = request_gh_callback(&harness, &client, code, &csrf).await;
    assert_eq!(auth_response.status(), StatusCode::SEE_OTHER);
    let location_header = auth_response
        .headers()
        .get("location")
        .expect("must carry the location header")
        .to_str()
        .expect("location must be a string");
    let redirected_to = Url::parse(location_header).expect("location must be a valid url");
    assert_eq!(redirected_to.host_str(), Some("my.magical.frontend"));
    assert_eq!(redirected_to.path(), "/post-sign-in");
    let params: HashMap<_, _> = redirected_to.query_pairs().into_owned().collect();
    assert_eq!(params["sub"], "github | kustosz");
    assert_eq!(params["nickname"], "kustosz");
    assert_eq!(params["provider"], "Github");
    assert!(params.get("session_id").is_some());
    assert!(params.get("exp").is_some());
    assert!(params.get("error").is_none());
}

#[tokio::test]
async fn test_gh_auth_errors_with_custom_frontend_redirect() {
    let harness = run_test_harness().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let csrf =
        get_and_validate_csrf_token(&harness, Some("https://my.magical.frontend/post-sign-in"))
            .await;
    let auth_response = request_gh_callback(&harness, &client, 12345, &csrf).await;
    assert_eq!(auth_response.status(), StatusCode::SEE_OTHER);
    let location_header = auth_response
        .headers()
        .get("location")
        .expect("must carry the location header")
        .to_str()
        .expect("location must be a string");
    let redirected_to = Url::parse(location_header).expect("location must be a valid url");
    assert_eq!(redirected_to.host_str(), Some("my.magical.frontend"));
    assert_eq!(redirected_to.path(), "/post-sign-in");
    let params: HashMap<_, _> = redirected_to.query_pairs().into_owned().collect();
    assert!(params.get("error").is_some());
    assert!(params.get("message").is_some());
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
    let entropy = Secret::new(entropy);
    contribution
        .add_entropy::<Arkworks>(&entropy)
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
        .map(|contribution| contribution.pot_pubkey)
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
    let csrf = get_and_validate_csrf_token(&harness, None).await;
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
    let entropy = Secret::new(entropy);
    contribution
        .add_entropy::<Arkworks>(&entropy)
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
    let new_csrf = get_and_validate_csrf_token(&harness, None).await;
    let gh_login_response = request_gh_callback(&harness, &http_client, auth_code, &new_csrf).await;
    assert_eq!(gh_login_response.status(), StatusCode::BAD_REQUEST);

    let transcript_after_attempts = harness.read_transcript_file().await;
    assert_eq!(
        transcript_with_first_contrib, transcript_after_attempts,
        "must not change the transcript again"
    )
}

#[tokio::test]
async fn test_double_contribution_when_allowed() {
    let harness = harness::Builder::new().allow_multi_contribution().run().await;
    let http_client = reqwest::Client::new();
    let auth_code = harness.create_valid_user("kustosz".to_string()).await;

    let csrf = get_and_validate_csrf_token(&harness, None).await;
    let session_id = extract_session_id_from_auth_response(
        request_gh_callback(&harness, &http_client, auth_code, &csrf).await,
    )
    .await;

    let mut contribution1 = try_contribute(&harness, &http_client, &session_id).await;

    contribution1
        .add_entropy::<Arkworks>(&entropy_from_str("such an unguessable string, wow!"))
        .expect("Adding entropy must be possible");

    contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution1,
        "kustosz",
    )
    .await;

    let new_csrf = get_and_validate_csrf_token(&harness, None).await;
    let session_id = extract_session_id_from_auth_response(
        request_gh_callback(&harness, &http_client, auth_code, &new_csrf).await,
    )
    .await;

    let mut contribution2 = try_contribute(&harness, &http_client, &session_id).await;
    contribution2
        .add_entropy::<Arkworks>(&entropy_from_str("another unguessable string, wow!"))
        .expect("Adding entropy must be possible");

    contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution2,
        "kustosz",
    )
        .await;
    let transcript = harness.read_transcript_file().await;
    assert_includes_contribution(&transcript, &contribution1);
    assert_includes_contribution(&transcript, &contribution2);
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
    let entropy = Secret::new(entropy);
    contribution
        .add_entropy::<Arkworks>(&entropy)
        .expect("Adding entropy must be possible");
    contribute_successfully(harness, client, &session_id, &contribution, &name).await;
    contribution
}

async fn slow_compute_participant(harness: &Harness, client: &reqwest::Client, name: String) {
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
    let entropy = Secret::new(entropy);

    tokio::time::sleep(harness.options.lobby.compute_deadline).await;

    contribution
        .add_entropy::<Arkworks>(&entropy)
        .expect("Adding entropy must be possible");

    let response = request_contribute(harness, client, &session_id, &contribution).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_large_lobby() {
    let harness = Arc::new(run_test_harness().await);
    let client = Arc::new(reqwest::Client::new());

    let handles = (0..20).into_iter().map(|i| {
        let h = harness.clone();
        let c = client.clone();
        tokio::spawn(async move {
            well_behaved_participant(h.as_ref(), c.as_ref(), format!("user {i}")).await
        })
    });

    let contributions: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("must terminate successfully"))
        .collect();

    let final_transcript = harness.read_transcript_file().await;
    contributions
        .iter()
        .for_each(|c| assert_includes_contribution(&final_transcript, c));
}

#[tokio::test]
async fn test_large_lobby_with_misbehaving_users() {
    let harness = Arc::new(run_test_harness().await);
    let client = Arc::new(reqwest::Client::new());

    let handles = (0..20).into_iter().map(|i| {
        let h = harness.clone();
        let c = client.clone();
        let u = format!("user {i}");
        tokio::spawn(async move {
            if i % 2 == 0 {
                Some(well_behaved_participant(h.as_ref(), c.as_ref(), u).await)
            } else {
                slow_compute_participant(h.as_ref(), c.as_ref(), u).await;
                None
            }
        })
    });

    let contributions: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("must terminate successfully"))
        .collect();

    let final_transcript = harness.read_transcript_file().await;
    contributions.iter().for_each(|oc| {
        oc.iter()
            .for_each(|c| assert_includes_contribution(&final_transcript, c))
    });

    let should_accept_count = contributions.iter().filter(|e| e.is_some()).count();
    assert!(
        final_transcript.transcripts[..]
            .windows(2)
            .all(|w| w[0].num_contributions() == w[1].num_contributions()),
        "all ceremonies should have the same number of contributions"
    );
    assert!(!final_transcript.transcripts.is_empty());
    let actual_count = final_transcript.transcripts[0].num_contributions();
    assert_eq!(should_accept_count, actual_count);
}

#[tokio::test]
async fn test_contribution_after_lobby_cleanup() {
    let harness = harness::Builder::new()
        .set_compute_deadline(Duration::from_millis(2000))
        .set_lobby_checkin_frequency(Duration::from_millis(50))
        .set_lobby_checkin_tolerance(Duration::from_millis(50))
        .set_lobby_flush_interval(Duration::from_millis(100))
        .run()
        .await;
    let http_client = reqwest::Client::new();

    let session_id = login_gh_user(&harness, &http_client, "kustosz".to_string()).await;

    let mut contribution = try_contribute(&harness, &http_client, &session_id).await;

    let entropy = "such an unguessable string, wow!"
        .bytes()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let entropy = Secret::new(entropy);
    contribution
        .add_entropy::<Arkworks>(&entropy)
        .expect("Adding entropy must be possible");

    tokio::time::sleep(Duration::from_millis(300)).await;

    contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        "kustosz",
    )
    .await;
}
