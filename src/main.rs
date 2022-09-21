#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
#![cfg_attr(any(test, feature = "bench"), allow(clippy::wildcard_imports))]
// TODO: These lints
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::module_name_repetitions)]

use crate::{
    api::v1::{
        auth::{auth_client_link, github_callback, siwe_callback},
        contribute::contribute,
        info::{current_state, jwt_info, status},
        lobby::try_contribute,
    },
    io::{read_json_file, write_json_file},
    keys::Keys,
    lobby::{clear_lobby_on_interval, SharedContributorState, SharedLobbyState},
    oauth::{
        github_oauth_client, siwe_oauth_client, EthAuthOptions, GithubAuthOptions, SharedAuthState,
    },
    sessions::{SessionId, SessionInfo},
    storage::storage_client,
    util::parse_url,
};
use axum::{
    extract::Extension,
    response::Html,
    routing::{get, post},
    Router, Server,
};
use clap::Parser;
use cli_batteries::{await_shutdown, version};
use eyre::Result as EyreResult;
use std::{
    env,
    sync::{atomic::AtomicUsize, Arc},
};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::info;
use url::Url;

mod api;
mod io;
mod jwt;
mod keys;
mod lobby;
mod oauth;
mod sessions;
mod storage;
mod test_transcript;
#[cfg(test)]
mod test_util;
mod util;

pub type SharedTranscript<T> = Arc<RwLock<T>>;
pub type SharedCeremonyStatus = Arc<AtomicUsize>;

pub const SIZES: [(usize, usize); 4] = [(4096, 65), (8192, 65), (16384, 65), (32768, 65)];

pub type Engine = kzg_ceremony_crypto::Arkworks;

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct Options {
    /// API Server url to bind
    #[clap(long, env, default_value = "http://127.0.0.1:3000/")]
    pub server: Url,

    #[clap(flatten)]
    pub keys: keys::Options,

    #[clap(flatten)]
    pub github: GithubAuthOptions,

    #[clap(flatten)]
    pub ethereum: EthAuthOptions,

    #[clap(flatten)]
    pub transcript: transcript::Options,

    #[clap(flatten)]
    pub lobby: lobby::Options,

    #[clap(flatten)]
    pub storage: storage::Options,
}

#[allow(dead_code)] // Entry point
fn main() {
    cli_batteries::run(version!(crypto, small_powers_of_tau), async_main);
}

async fn async_main(options: Options) -> EyreResult<()> {
    let keys = Arc::new(Keys::new(&options.keys).await?);

    let transcript_data =
        read_json_file::<BatchTranscript>(options.transcript.transcript_file.clone()).await;
    let transcript = Arc::new(RwLock::new(transcript_data));

    let active_contributor_state = SharedContributorState::default();

    // TODO: figure it out from the transcript
    let ceremony_status = Arc::new(AtomicUsize::new(0));
    let lobby_state = SharedLobbyState::default();
    let auth_state = SharedAuthState::default();

    // Spawn automatic queue flusher -- flushes those in the lobby whom have not
    // pinged in a considerable amount of time
    tokio::spawn(clear_lobby_on_interval(
        lobby_state.clone(),
        options.lobby.clone(),
    ));

    let app = Router::new()
        .layer(TraceLayer::new_for_http())
        .route("/hello_world", get(hello_world))
        .route("/auth/request_link", get(auth_client_link))
        .route("/auth/callback/github", get(github_callback))
        .route("/auth/callback/siwe", get(siwe_callback))
        .route("/lobby/try_contribute", post(try_contribute))
        .route("/contribute", post(contribute))
        .route("/info/status", get(status))
        .route("/info/jwt", get(jwt_info))
        .route("/info/current_state", get(current_state))
        .layer(Extension(active_contributor_state))
        .layer(Extension(lobby_state))
        .layer(Extension(auth_state))
        .layer(Extension(ceremony_status))
        .layer(Extension(keys))
        .layer(Extension(siwe_oauth_client(&options.ethereum)))
        .layer(Extension(github_oauth_client(&options.github)))
        .layer(Extension(reqwest::Client::new()))
        .layer(Extension(storage_client(&options.storage).await))
        .layer(Extension(transcript))
        .layer(Extension(options.clone()));

    // Run the server
    let (addr, prefix) = parse_url(&options.server)?;
    let app = Router::new().nest(prefix, app);
    let server = Server::try_bind(&addr)?.serve(app.into_make_service());
    info!("Listening on http://{}{}", server.local_addr(), prefix);
    server.with_graceful_shutdown(await_shutdown()).await?;

    Ok(())
}

#[allow(clippy::unused_async)] // Required for axum function signature
async fn hello_world() -> Html<&'static str> {
    Html("<h1>Server is Running</h1>")
}
