use crate::{
    common::mock_auth_service::{AnyTestUser, TestUser},
    Address, Harness,
};
use ethers_core::types::Signature;
use http::StatusCode;
use kzg_ceremony_crypto::{BatchContribution, BatchTranscript, G2};
use secrecy::Secret;
use serde_json::Value;
use std::collections::HashMap;
use url::Url;

/// This function acts both as a test and a utility. This way, we'll test the
/// behavior in a variety of different app states.
pub async fn get_and_validate_csrf_token(harness: &Harness, redirect_url: Option<&str>) -> String {
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

pub fn entropy_from_str(seed: &str) -> Secret<[u8; 32]> {
    let padding = "padding".repeat(5);
    let entropy = format!("{seed}{padding}")
        .bytes()
        .take(32)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    Secret::new(entropy)
}

pub async fn request_auth_callback(
    harness: &Harness,
    http_client: &reqwest::Client,
    user: &TestUser,
    csrf: &str,
) -> reqwest::Response {
    let url_ext = match user.user {
        AnyTestUser::Eth(_) => "auth/callback/eth",
        AnyTestUser::Gh(_) => "auth/callback/github",
    };
    http_client
        .get(harness.options.server.join(url_ext).unwrap())
        .query(&[("state", csrf), ("code", &user.id.to_string())])
        .send()
        .await
        .expect("Could not call the endpoint")
}

pub async fn extract_session_id_from_auth_response(response: reqwest::Response) -> String {
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

pub async fn login(harness: &Harness, http_client: &reqwest::Client, user: &TestUser) -> String {
    let csrf = get_and_validate_csrf_token(harness, None).await;
    let callback_result = request_auth_callback(harness, http_client, user, &csrf).await;
    assert_eq!(callback_result.status(), StatusCode::OK);
    extract_session_id_from_auth_response(callback_result).await
}

pub async fn create_and_login_gh_user(
    harness: &Harness,
    http_client: &reqwest::Client,
    name: String,
) -> (TestUser, String) {
    let user = harness.create_gh_user(name.clone()).await;
    let session_id = login(harness, http_client, &user).await;
    (user, session_id)
}

pub async fn request_try_contribute(
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

pub async fn try_contribute(
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

pub async fn request_contribute(
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

pub async fn contribute_successfully(
    harness: &Harness,
    http_client: &reqwest::Client,
    session_id: &str,
    contribution: &BatchContribution,
    user_id: &str,
) {
    let response = request_contribute(harness, http_client, session_id, contribution).await;

    if response.status() != StatusCode::OK {
        println!("Response: {:?}", response.text().await);
        panic!("Response must be successful");
    }

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
    assert_eq!(
        receipt_contents
            .get("identity")
            .expect("must contain identity"),
        user_id
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

pub fn assert_includes_contribution(
    transcript: &BatchTranscript,
    contribution: &BatchContribution,
    user: &TestUser,
    expect_ecdsa_signed: bool,
    expect_bls_signed: bool,
) {
    let first_contrib_pubkey = contribution.contributions[0].pot_pubkey;
    let index_in_transcripts = transcript.transcripts[0]
        .witness
        .pubkeys
        .iter()
        .position(|pk| pk == &first_contrib_pubkey)
        .expect("Transcript does not include contribution.");
    assert_eq!(
        transcript.participant_ids[index_in_transcripts],
        user.identity()
    );

    match &transcript.participant_ecdsa_signatures[index_in_transcripts].0 {
        Some(_) if !expect_ecdsa_signed => {
            panic!("Expected no ECDSA signature, but signature is present")
        }
        None if expect_ecdsa_signed => panic!("Expected an ECDSA signature, but none found"),
        _ => (),
    }

    transcript
        .transcripts
        .iter()
        .zip(contribution.contributions.iter())
        .for_each(|(t, c)| {
            assert_eq!(t.witness.products[index_in_transcripts], c.powers.g1[1]);
            assert_eq!(t.witness.pubkeys[index_in_transcripts], c.pot_pubkey);
            match t.witness.signatures[index_in_transcripts].0 {
                Some(_) if !expect_bls_signed => {
                    panic!("Expected no BLS signature, but signature is present");
                }
                None if expect_bls_signed => {
                    panic!("Expected a BLS signature, but none found");
                }
                _ => (),
            }
        })
}

pub async fn get_transcript(harness: &Harness, client: &reqwest::Client) -> BatchTranscript {
    let response = client
        .get(harness.app_path("info/current_state"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let from_app = response
        .json::<BatchTranscript>()
        .await
        .expect("must be a valid transcript");
    let from_file = harness.read_transcript_file().await;
    assert_eq!(from_app, from_file);
    from_app
}
