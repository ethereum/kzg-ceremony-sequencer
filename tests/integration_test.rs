#![cfg(test)]

use crate::common::{
    actions, harness,
    harness::{run_test_harness, Harness},
    mock_auth_service::{AnyTestUser, GhUser, TestUser},
};
use ethers_core::types::Address;
use http::StatusCode;
use kzg_ceremony_crypto::{Arkworks, BatchContribution};
use secrecy::Secret;
use std::{collections::HashMap, sync::Arc, time::Duration};
use url::Url;

mod common;

#[tokio::test]
async fn test_auth_request_link() {
    let harness = run_test_harness().await;
    actions::get_and_validate_csrf_token(&harness, None).await;
}

#[tokio::test]
async fn test_gh_auth_happy_path() {
    let harness = run_test_harness().await;
    let http_client = reqwest::Client::new();
    actions::create_and_login_gh_user(&harness, &http_client, "kustosz".to_string()).await;
}

#[tokio::test]
async fn test_eth_auth_happy_path() {
    let harness = run_test_harness().await;
    let http_client = reqwest::Client::new();
    let user = harness.create_eth_user().await;
    actions::login(&harness, &http_client, &user).await;
}

#[tokio::test]
async fn test_gh_auth_with_custom_frontend_redirect() {
    let harness = run_test_harness().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let csrf = actions::get_and_validate_csrf_token(
        &harness,
        Some("https://my.magical.frontend/post-sign-in"),
    )
    .await;
    let user = harness.create_gh_user("kustosz".to_string()).await;
    let auth_response = actions::request_auth_callback(&harness, &client, &user, &csrf).await;
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
    assert_eq!(params["sub"], user.identity());
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
    let csrf = actions::get_and_validate_csrf_token(
        &harness,
        Some("https://my.magical.frontend/post-sign-in"),
    )
    .await;
    let invalid_user = TestUser {
        id:   12344,
        user: AnyTestUser::Gh(GhUser {
            name:       "foo".to_string(),
            created_at: "2022-01-01T00:00:00Z".to_string(),
        }),
    };
    let auth_response =
        actions::request_auth_callback(&harness, &client, &invalid_user, &csrf).await;
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
async fn test_gh_contribution_happy_path() {
    let harness = run_test_harness().await;
    let http_client = reqwest::Client::new();

    let (user, session_id) =
        actions::create_and_login_gh_user(&harness, &http_client, "kustosz".to_string()).await;

    let mut contribution = actions::try_contribute(&harness, &http_client, &session_id).await;

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

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        &user.identity(),
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
    let user = harness.create_gh_user("kustosz".to_string()).await;
    let csrf = actions::get_and_validate_csrf_token(&harness, None).await;
    let user_id = user.identity();
    let session_id = actions::extract_session_id_from_auth_response(
        actions::request_auth_callback(&harness, &http_client, &user, &csrf).await,
    )
    .await;

    let mut contribution = actions::try_contribute(&harness, &http_client, &session_id).await;

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
    actions::contribute_successfully(&harness, &http_client, &session_id, &contribution, &user_id)
        .await;
    let transcript_with_first_contrib = harness.read_transcript_file().await;
    actions::assert_includes_contribution(&transcript_with_first_contrib, &contribution, &user_id);

    // Try contributing again right away – fails because the contribution spot is
    // emptied
    let second_contribute_response =
        actions::request_contribute(&harness, &http_client, &session_id, &contribution).await;
    assert_eq!(second_contribute_response.status(), StatusCode::BAD_REQUEST);

    // Try pinging the lobby again – fails because the user got logged out
    let second_try_contribute_response =
        actions::request_try_contribute(&harness, &http_client, &session_id).await;
    assert_eq!(
        second_try_contribute_response.status(),
        StatusCode::UNAUTHORIZED
    );

    // Try logging in again – fails because the user is banned from further use of
    // the app.
    let new_csrf = actions::get_and_validate_csrf_token(&harness, None).await;
    let gh_login_response =
        actions::request_auth_callback(&harness, &http_client, &user, &new_csrf).await;
    assert_eq!(gh_login_response.status(), StatusCode::BAD_REQUEST);

    let transcript_after_attempts = harness.read_transcript_file().await;
    assert_eq!(
        transcript_with_first_contrib, transcript_after_attempts,
        "must not change the transcript again"
    )
}

#[tokio::test]
async fn test_double_contribution_when_allowed() {
    let harness = harness::Builder::new()
        .allow_multi_contribution()
        .run()
        .await;
    let http_client = reqwest::Client::new();
    let user = harness.create_gh_user("kustosz".to_string()).await;
    let user_id = user.identity();
    let csrf = actions::get_and_validate_csrf_token(&harness, None).await;
    let session_id = actions::extract_session_id_from_auth_response(
        actions::request_auth_callback(&harness, &http_client, &user, &csrf).await,
    )
    .await;

    let mut contribution1 = actions::try_contribute(&harness, &http_client, &session_id).await;

    contribution1
        .add_entropy::<Arkworks>(&actions::entropy_from_str(
            "such an unguessable string, wow!",
        ))
        .expect("Adding entropy must be possible");

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution1,
        &user_id,
    )
    .await;

    let new_csrf = actions::get_and_validate_csrf_token(&harness, None).await;
    let session_id = actions::extract_session_id_from_auth_response(
        actions::request_auth_callback(&harness, &http_client, &user, &new_csrf).await,
    )
    .await;

    let mut contribution2 = actions::try_contribute(&harness, &http_client, &session_id).await;
    contribution2
        .add_entropy::<Arkworks>(&actions::entropy_from_str(
            "another unguessable string, wow!",
        ))
        .expect("Adding entropy must be possible");

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution2,
        &user_id,
    )
    .await;
    let transcript = harness.read_transcript_file().await;
    actions::assert_includes_contribution(&transcript, &contribution1, &user_id);
    actions::assert_includes_contribution(&transcript, &contribution2, &user_id);
}

async fn well_behaved_participant(
    harness: &Harness,
    client: &reqwest::Client,
    name: String,
) -> (BatchContribution, TestUser) {
    let (user, session_id) = actions::create_and_login_gh_user(harness, client, name.clone()).await;
    let mut contribution = loop {
        let try_contribute_response =
            actions::request_try_contribute(harness, client, &session_id).await;
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
    actions::contribute_successfully(
        harness,
        client,
        &session_id,
        &contribution,
        &user.identity(),
    )
    .await;
    (contribution, user)
}

async fn slow_compute_participant(harness: &Harness, client: &reqwest::Client, name: String) {
    let (_, session_id) = actions::create_and_login_gh_user(harness, client, name.clone()).await;
    let mut contribution = loop {
        let try_contribute_response =
            actions::request_try_contribute(harness, client, &session_id).await;
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

    let response = actions::request_contribute(harness, client, &session_id, &contribution).await;
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
    contributions.iter().for_each(|(c, user)| {
        actions::assert_includes_contribution(&final_transcript, c, &user.identity())
    });
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
        oc.iter().for_each(|(c, user_id)| {
            actions::assert_includes_contribution(&final_transcript, c, &user_id.identity())
        })
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

    let (user, session_id) =
        actions::create_and_login_gh_user(&harness, &http_client, "kustosz".to_string()).await;

    let mut contribution = actions::try_contribute(&harness, &http_client, &session_id).await;

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

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        &user.identity(),
    )
    .await;
}
