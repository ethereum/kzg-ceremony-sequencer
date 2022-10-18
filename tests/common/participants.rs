use crate::{actions, actions::entropy_from_str, AnyTestUser, Harness, TestUser};
use ethers_core::types::Signature;
use ethers_signers::Signer;
use http::StatusCode;
use kzg_ceremony_crypto::{
    signature, signature::EcdsaSignature, Arkworks, BatchContribution, BatchTranscript,
};
use rand::{thread_rng, Rng};

type PostConditionCheck = Box<dyn FnOnce(&BatchTranscript) -> () + Send + Sync>;

async fn await_contribution_slot(
    harness: &Harness,
    client: &reqwest::Client,
    session_id: &str,
) -> BatchContribution {
    loop {
        let try_contribute_response =
            actions::request_try_contribute(harness, client, &session_id).await;
        assert_eq!(try_contribute_response.status(), StatusCode::OK);
        let maybe_contribution = try_contribute_response
            .json::<BatchContribution>()
            .await
            .ok();
        if let Some(contrib) = maybe_contribution {
            return contrib;
        }

        tokio::time::sleep(
            harness.options.lobby.lobby_checkin_frequency
                - harness.options.lobby.lobby_checkin_tolerance,
        )
        .await;
    }
}

pub async fn well_behaved(
    harness: &Harness,
    client: &reqwest::Client,
    user: TestUser,
) -> PostConditionCheck {
    let session_id = actions::login(harness, client, &user).await;
    let mut contribution = await_contribution_slot(harness, client, &session_id).await;
    contribution
        .add_entropy::<Arkworks>(&entropy_from_str(&user.identity()))
        .expect("Adding entropy must be possible");

    if let AnyTestUser::Eth(wallet) = &user.user {
        contribution.ecdsa_signature = EcdsaSignature(Some(
            wallet
                .sign_typed_data(&signature::ContributionTypedData::from(&contribution))
                .await
                .unwrap(),
        ));
    }

    actions::contribute_successfully(
        harness,
        client,
        &session_id,
        &contribution,
        &user.identity(),
    )
    .await;

    Box::new(move |transcript| {
        actions::assert_includes_contribution(transcript, &contribution, &user, user.is_eth());
    })
}

pub async fn wrong_ecdsa(
    harness: &Harness,
    client: &reqwest::Client,
    user: TestUser,
) -> PostConditionCheck {
    let session_id = actions::login(harness, client, &user).await;
    let mut contribution = await_contribution_slot(harness, client, &session_id).await;
    contribution
        .add_entropy::<Arkworks>(&entropy_from_str(&user.identity()))
        .expect("Adding entropy must be possible");

    let mut random_bytes = [0 as u8; 65];
    (0..65).for_each(|i| {
        random_bytes[i] = thread_rng().gen();
    });

    contribution.ecdsa_signature =
        EcdsaSignature(Some(Signature::try_from(&random_bytes[..]).unwrap()));

    actions::contribute_successfully(
        harness,
        client,
        &session_id,
        &contribution,
        &user.identity(),
    )
    .await;

    Box::new(move |transcript| {
        actions::assert_includes_contribution(transcript, &contribution, &user, false);
    })
}

pub async fn slow_compute(
    harness: &Harness,
    client: &reqwest::Client,
    user: TestUser,
) -> PostConditionCheck {
    let session_id = actions::login(harness, client, &user).await;
    let mut contribution = await_contribution_slot(harness, client, &session_id).await;
    tokio::time::sleep(harness.options.lobby.compute_deadline).await;
    contribution
        .add_entropy::<Arkworks>(&entropy_from_str(&user.identity()))
        .expect("Adding entropy must be possible");
    let response = actions::request_contribute(harness, client, &session_id, &contribution).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Box::new(|_| {})
}
