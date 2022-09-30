#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
#![cfg_attr(any(test, feature = "bench"), allow(clippy::wildcard_imports))]
// TODO: These lints
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::module_name_repetitions)]

use crate::{
    api::v1::{
        auth::{auth_client_link, eth_callback, github_callback},
        contribute::{contribute, contribute_abort},
        info::{current_state, status},
        lobby::try_contribute,
    },
    io::{read_or_create_transcript, CeremonySizes},
    keys::Keys,
    lobby::{clear_lobby_on_interval, SharedContributorState, SharedLobbyState},
    oauth::{
        eth_oauth_client, github_oauth_client, EthAuthOptions, GithubAuthOptions, SharedAuthState,
    },
    sessions::{SessionId, SessionInfo},
    storage::storage_client,
    util::parse_url,
};
use axum::{
    extract::Extension,
    response::Html,
    routing::{get, post, IntoMakeService},
    Router, Server,
};
use clap::Parser;
use cli_batteries::await_shutdown;
use eyre::Result as EyreResult;
use hyper::server::conn::AddrIncoming;
use kzg_ceremony_crypto::BatchTranscript;
use std::{
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
};
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use url::Url;

mod api;
pub mod io;
mod keys;
mod lobby;
mod oauth;
mod receipt;
mod sessions;
mod storage;
#[cfg(test)]
pub mod test_util;
mod util;

pub type Engine = kzg_ceremony_crypto::Arkworks;
pub type SharedTranscript = Arc<RwLock<BatchTranscript>>;
pub type SharedCeremonyStatus = Arc<AtomicUsize>;

pub const DEFAULT_CEREMONY_SIZES: &str = "4096,65:8192,65:16384,65:32768,65";

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

    #[clap(long, env, default_value = "./transcript.json")]
    pub transcript_file: PathBuf,

    #[clap(long, env, default_value = "./transcript.json.next")]
    pub transcript_in_progress_file: PathBuf,

    #[clap(long, env, value_parser=CeremonySizes::parse_from_cmd, default_value=DEFAULT_CEREMONY_SIZES, multiple(false))]
    pub ceremony_sizes: CeremonySizes,

    #[clap(flatten)]
    pub lobby: lobby::Options,

    #[clap(flatten)]
    pub storage: storage::Options,
}

#[allow(clippy::missing_errors_doc)]
pub async fn async_main(options: Options) -> EyreResult<()> {
    let addr = options.server.clone();
    let server = start_server(options).await?;
    info!("Listening on http://{}{}", server.local_addr(), addr.path());
    server.with_graceful_shutdown(await_shutdown()).await?;
    Ok(())
}

#[allow(clippy::missing_errors_doc)]
pub async fn start_server(
    options: Options,
) -> EyreResult<Server<AddrIncoming, IntoMakeService<Router>>> {
    info!(size=?options.ceremony_sizes, "Starting sequencer for KZG ceremony.");

    let keys = Arc::new(Keys::new(&options.keys)?);

    let transcript = read_or_create_transcript(
        options.transcript_file.clone(),
        options.transcript_in_progress_file.clone(),
        &options.ceremony_sizes,
    )
    .await?;

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
        .route("/auth/callback/eth", get(eth_callback))
        .route("/lobby/try_contribute", post(try_contribute))
        .route("/contribute", post(contribute))
        .route("/contribute/abort", post(contribute_abort))
        .route("/info/status", get(status))
        .route("/info/current_state", get(current_state))
        .layer(CorsLayer::permissive())
        .layer(Extension(active_contributor_state))
        .layer(Extension(lobby_state))
        .layer(Extension(auth_state))
        .layer(Extension(ceremony_status))
        .layer(Extension(keys))
        .layer(Extension(eth_oauth_client(&options.ethereum)))
        .layer(Extension(github_oauth_client(&options.github)))
        .layer(Extension(reqwest::Client::new()))
        .layer(Extension(storage_client(&options.storage).await?))
        .layer(Extension(transcript))
        .layer(Extension(options.clone()));

    // Run the server
    let (addr, prefix) = parse_url(&options.server)?;
    let app = Router::new().nest(prefix, app);
    let server = Server::try_bind(&addr)?.serve(app.into_make_service());
    Ok(server)
}

#[allow(clippy::unused_async)] // Required for axum function signature
async fn hello_world() -> Html<&'static str> {
    Html("<h1>Server is Running</h1>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kzg_ceremony_crypto::{BatchContribution, BatchTranscript, G2};

    pub fn test_transcript() -> BatchTranscript {
        BatchTranscript::new(&[(4, 2)])
    }

    pub fn valid_contribution(transcript: &BatchTranscript, no: u8) -> BatchContribution {
        let mut contribution = transcript.contribution();
        contribution.add_entropy::<Engine>([no; 32]).unwrap();
        contribution
    }

    pub fn invalid_contribution(transcript: &BatchTranscript, no: u8) -> BatchContribution {
        let mut contribution = valid_contribution(transcript, no);
        contribution.contributions[0].pot_pubkey = G2::zero();
        contribution
    }
}
