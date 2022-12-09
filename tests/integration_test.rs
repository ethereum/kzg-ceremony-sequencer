#![cfg(test)]

use crate::common::{
    actions, harness,
    harness::{run_test_harness, Builder, Harness},
    mock_auth_service::{AnyTestUser, GhUser, TestUser},
};
use common::participants;
use ethers_core::types::Address;
use ethers_signers::{LocalWallet, Signer};
use http::StatusCode;
use kzg_ceremony_crypto::{
    signature::{BlsSignature, ContributionTypedData, EcdsaSignature},
    Arkworks, DefaultEngine, G1,
};
use rand::thread_rng;
use secrecy::Secret;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
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
    assert_eq!(params["sub"], user.identity().to_string());
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
    assert!(params.get("code").is_some());
    assert!(params.get("error").is_some());
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
        .add_entropy::<Arkworks>(&entropy, &user.identity())
        .expect("Adding entropy must be possible");

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        &user.identity().to_string(),
    )
    .await;

    let transcript = harness.read_transcript_file().await;

    let num_contributions = transcript
        .transcripts
        .iter()
        .map(|t| t.num_participants())
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
        .add_entropy::<DefaultEngine>(&entropy, &user_id)
        .expect("Adding entropy must be possible");

    // First, successful contribution;
    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        &user_id.to_string(),
    )
    .await;
    let transcript_with_first_contrib = harness.read_transcript_file().await;
    actions::assert_includes_contribution(
        &transcript_with_first_contrib,
        &contribution,
        &user,
        false,
        true,
    );

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
        .add_entropy::<DefaultEngine>(
            &actions::entropy_from_str("such an unguessable string, wow!"),
            &user_id,
        )
        .expect("Adding entropy must be possible");

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution1,
        &user_id.to_string(),
    )
    .await;

    let new_csrf = actions::get_and_validate_csrf_token(&harness, None).await;
    let session_id = actions::extract_session_id_from_auth_response(
        actions::request_auth_callback(&harness, &http_client, &user, &new_csrf).await,
    )
    .await;

    let mut contribution2 = actions::try_contribute(&harness, &http_client, &session_id).await;
    contribution2
        .add_entropy::<DefaultEngine>(
            &actions::entropy_from_str("another unguessable string, wow!"),
            &user_id,
        )
        .expect("Adding entropy must be possible");

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution2,
        &user_id.to_string(),
    )
    .await;
    let transcript = harness.read_transcript_file().await;
    actions::assert_includes_contribution(&transcript, &contribution1, &user, false, true);
    actions::assert_includes_contribution(&transcript, &contribution2, &user, false, true);
}

#[tokio::test]
async fn test_large_lobby() {
    let harness = Arc::new(run_test_harness().await);
    let client = Arc::new(reqwest::Client::new());

    let handles = (0..20).into_iter().map(|i| {
        let h = harness.clone();
        let c = client.clone();
        tokio::spawn(async move {
            let user = if i % 2 == 0 {
                h.create_gh_user(format!("user {i}")).await
            } else {
                h.create_eth_user().await
            };
            participants::well_behaved(h.as_ref(), c.as_ref(), user).await
        })
    });

    let post_conditions = futures::future::join_all(handles).await;
    let final_transcript = harness.read_transcript_file().await;
    post_conditions
        .into_iter()
        .map(|r| r.expect("must terminate successfully"))
        .for_each(|check| check(&final_transcript));
}

#[tokio::test]
async fn test_large_lobby_with_slow_compute_users() {
    let harness = Arc::new(run_test_harness().await);
    let client = Arc::new(reqwest::Client::new());
    let n = 20;
    let handles = (0..n).into_iter().map(|i| {
        let h = harness.clone();
        let c = client.clone();
        tokio::spawn(async move {
            let user = h.create_gh_user(format!("user {i}")).await;
            if i % 2 == 0 {
                participants::well_behaved(h.as_ref(), c.as_ref(), user).await
            } else {
                participants::slow_compute(h.as_ref(), c.as_ref(), user).await
            }
        })
    });

    let post_conditions = futures::future::join_all(handles).await;
    let final_transcript = harness.read_transcript_file().await;
    post_conditions
        .into_iter()
        .map(|r| r.expect("must terminate successfully"))
        .for_each(|cond| cond(&final_transcript));

    let should_accept_count = n / 2;
    assert!(
        final_transcript.transcripts[..]
            .windows(2)
            .all(|w| w[0].num_participants() == w[1].num_participants()),
        "all ceremonies should have the same number of contributions"
    );
    assert!(!final_transcript.transcripts.is_empty());
    let actual_count = final_transcript.transcripts[0].num_participants();
    assert_eq!(should_accept_count, actual_count);
}

#[tokio::test]
async fn test_various_contributors() {
    let harness = Arc::new(
        Builder::new()
            .set_compute_deadline(Duration::from_millis(4000))
            .set_lobby_checkin_frequency(Duration::from_millis(2000))
            .set_lobby_checkin_tolerance(Duration::from_millis(2000))
            .run(),
    );
    let client = Arc::new(reqwest::Client::new());
    let n = 40;
    let handles = (0..n).into_iter().map(|i| {
        let h = harness.clone();
        let c = client.clone();
        tokio::spawn(async move {
            let user = if i % 2 == 0 {
                h.create_gh_user(format!("user {i}")).await
            } else {
                h.create_eth_user().await
            };
            // modulus here must be odd to test the full user / participant matrix.
            match i % 5 {
                0 => participants::wrong_ecdsa(h.as_ref(), c.as_ref(), user).await,
                1 => participants::slow_compute(h.as_ref(), c.as_ref(), user).await,
                2 => participants::wrong_bls(h.as_ref(), c.as_ref(), user).await,
                _ => participants::well_behaved(h.as_ref(), c.as_ref(), user).await,
            }
        })
    });

    let post_conditions = futures::future::join_all(handles).await;
    let final_transcript = harness.read_transcript_file().await;
    post_conditions
        .into_iter()
        .map(|r| r.expect("must terminate successfully"))
        .for_each(|check| check(&final_transcript));
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
        .add_entropy::<Arkworks>(&entropy, &user.identity())
        .expect("Adding entropy must be possible");

    tokio::time::sleep(Duration::from_millis(300)).await;

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        &user.identity().to_string(),
    )
    .await;
}

#[tokio::test]
async fn test_wrong_ecdsa_signature() {
    let other_wallet = LocalWallet::new(&mut thread_rng());
    let harness = run_test_harness().await;
    let http_client = reqwest::Client::new();
    let user = harness.create_eth_user().await;
    let session_id = actions::login(&harness, &http_client, &user).await;
    let mut contribution = actions::try_contribute(&harness, &http_client, &session_id).await;
    let entropy = actions::entropy_from_str("foo bar baz");
    contribution
        .add_entropy::<DefaultEngine>(&entropy, &user.identity())
        .expect("Adding entropy must be possible");
    contribution.ecdsa_signature = EcdsaSignature(Some(
        other_wallet
            .sign_typed_data(&ContributionTypedData::from(&contribution))
            .await
            .unwrap(),
    ));

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        &user.identity().to_string(),
    )
    .await;

    let transcript = harness.read_transcript_file().await;

    actions::assert_includes_contribution(&transcript, &contribution, &user, false, true)
}

#[tokio::test]
async fn test_wrong_bls_signature() {
    let harness = run_test_harness().await;
    let http_client = reqwest::Client::new();
    let user = harness.create_eth_user().await;
    let session_id = actions::login(&harness, &http_client, &user).await;
    let mut contribution = actions::try_contribute(&harness, &http_client, &session_id).await;
    let entropy = actions::entropy_from_str("foo bar baz");
    contribution
        .add_entropy::<DefaultEngine>(&entropy, &user.identity())
        .expect("Adding entropy must be possible");

    contribution.contributions.iter_mut().for_each(|c| {
        c.bls_signature = BlsSignature(Some(G1::one()));
    });

    actions::contribute_successfully(
        &harness,
        &http_client,
        &session_id,
        &contribution,
        &user.identity().to_string(),
    )
    .await;

    let transcript = harness.read_transcript_file().await;

    actions::assert_includes_contribution(&transcript, &contribution, &user, false, false)
}

#[tokio::test]
async fn test_graceful_restart() {
    let harness = Arc::new(RwLock::new(run_test_harness().await));
    let client = Arc::new(reqwest::Client::new());
    let n = 10;
    let handles = (0..n).into_iter().map(|i| {
        let h = harness.clone();
        let c = client.clone();
        tokio::spawn(async move {
            let h = h.read().await;
            let user = if i % 2 == 0 {
                h.create_gh_user(format!("user {i}")).await
            } else {
                h.create_eth_user().await
            };
            // modulus here must be odd to test the full user / participant matrix.
            match i % 5 {
                0 => participants::wrong_ecdsa(&h, c.as_ref(), user).await,
                1 => participants::slow_compute(&h, c.as_ref(), user).await,
                2 => participants::wrong_bls(&h, c.as_ref(), user).await,
                _ => participants::well_behaved(&h, c.as_ref(), user).await,
            }
        })
    });

    let post_conditions_pre_restart = futures::future::join_all(handles).await;

    {
        let mut h = harness.write().await;
        h.stop().await;
        h.start().await;
    }

    let handles = (0..n).into_iter().map(|i| {
        let h = harness.clone();
        let c = client.clone();
        tokio::spawn(async move {
            let h = h.read().await;
            let user = if i % 2 == 0 {
                h.create_gh_user(format!("user restarted {i}")).await
            } else {
                h.create_eth_user().await
            };
            // modulus here must be odd to test the full user / participant matrix.
            match i % 5 {
                0 => participants::wrong_ecdsa(&h, c.as_ref(), user).await,
                1 => participants::slow_compute(&h, c.as_ref(), user).await,
                2 => participants::wrong_bls(&h, c.as_ref(), user).await,
                _ => participants::well_behaved(&h, c.as_ref(), user).await,
            }
        })
    });

    let post_conditions_post_restart = futures::future::join_all(handles).await;

    let final_transcript = harness.read().await.read_transcript_file().await;
    post_conditions_pre_restart
        .into_iter()
        .chain(post_conditions_post_restart.into_iter())
        .map(|r| r.expect("must terminate successfully"))
        .for_each(|check| check(&final_transcript));
}
