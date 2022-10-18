use crate::{actions, Harness, TestUser};
use http::StatusCode;
use kzg_ceremony_crypto::{Arkworks, BatchContribution, BatchTranscript};
use secrecy::Secret;

type PostConditionCheck = Box<dyn FnOnce(&BatchTranscript) -> () + Send + Sync>;

pub async fn well_behaved(
    harness: &Harness,
    client: &reqwest::Client,
    user: TestUser,
) -> PostConditionCheck {
    let session_id = actions::login(harness, client, &user).await;
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

    let entropy = format!("{} such an unguessable string, wow!", user.identity())
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

    Box::new(move |transcript| {
        actions::assert_includes_contribution(transcript, &contribution, &user.identity());
    })
}

pub async fn slow_compute(
    harness: &Harness,
    client: &reqwest::Client,
    user: TestUser,
) -> PostConditionCheck {
    let session_id = actions::login(harness, client, &user).await;
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

    let entropy = format!("{} such an unguessable string, wow!", user.identity())
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
    Box::new(|_| {})
}
