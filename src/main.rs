#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
#![cfg_attr(any(test, feature = "bench"), allow(clippy::wildcard_imports))]
// TODO: These lints
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::module_name_repetitions)]

use std::{
    env,
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
    time::Duration,
};

use crate::{
    api::v1::{
        auth::{auth_client_link, github_callback, siwe_callback},
        contribute::contribute,
        info::{current_state, jwt_info, status},
        lobby::try_contribute,
    },
    constants::LOBBY_FLUSH_INTERVAL,
    io::transcript::read_transcript_file,
    keys::Keys,
    lobby::{clear_lobby_on_interval, SharedContributorState},
    oauth::{github_oauth_client, siwe_oauth_client, SharedAuthState},
    util::parse_url,
};
use axum::{
    extract::Extension,
    response::Html,
    routing::{get, post},
    Router, Server,
};
use chrono::{DateTime, FixedOffset};
use clap::Parser;
use cli_batteries::{await_shutdown, version};
use eyre::{eyre, Result as EyreResult};
use lobby::SharedLobbyState;
use sessions::{SessionId, SessionInfo};
use storage::persistent_storage_client;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::info;
use url::Url;

mod api;
mod constants;
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

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct Options {
    /// API Server url to bind
    #[clap(long, env, default_value = "http://127.0.0.1:8080/")]
    pub server: Url,

    #[clap(flatten)]
    pub keys: keys::Options,
}

#[allow(dead_code)] // Entry point
fn main() {
    cli_batteries::run(
        version!(crypto, small_powers_of_tau),
        async_main::<kzg_ceremony_crypto::contribution::Transcript>,
    );
}

async fn async_main<T>(options: Options) -> EyreResult<()>
where
    T: kzg_ceremony_crypto::interface::Transcript + Send + Sync + 'static,
    T::ContributionType: Send,
    <<T as kzg_ceremony_crypto::interface::Transcript>::ContributionType as kzg_ceremony_crypto::interface::Contribution>::Receipt:
        Send + Sync,
{
    // Load JWT keys
    keys::KEYS
        .set(Keys::new(options.keys).await?)
        .map_err(|_e| eyre!("KEYS was already set."))?;

    let config = AppConfig::default();
    let transcript_data = read_transcript_file::<T>(config.transcript_file.clone()).await;
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
        Duration::from_secs(LOBBY_FLUSH_INTERVAL as u64),
    ));

    let app = Router::new()
        .layer(TraceLayer::new_for_http())
        .route("/hello_world", get(hello_world))
        .route("/auth/request_link", get(auth_client_link))
        .route("/auth/callback/github", get(github_callback))
        .route("/auth/callback/siwe", get(siwe_callback))
        .route("/lobby/try_contribute", post(try_contribute::<T>))
        .route("/contribute", post(contribute::<T>))
        .route("/info/status", get(status))
        .route("/info/jwt", get(jwt_info))
        .route("/info/current_state", get(current_state))
        .layer(Extension(active_contributor_state))
        .layer(Extension(lobby_state))
        .layer(Extension(auth_state))
        .layer(Extension(ceremony_status))
        .layer(Extension(siwe_oauth_client()))
        .layer(Extension(github_oauth_client()))
        .layer(Extension(reqwest::Client::new()))
        .layer(Extension(persistent_storage_client().await))
        .layer(Extension(config))
        .layer(Extension(transcript));

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

#[derive(Clone)]
pub struct AppConfig {
    github_max_creation_time:    DateTime<FixedOffset>,
    eth_check_nonce_at_block:    String,
    eth_min_nonce:               i64,
    eth_rpc_url:                 String,
    transcript_file:             PathBuf,
    transcript_in_progress_file: PathBuf,
}

impl Default for AppConfig {
    fn default() -> Self {
        let transcript =
            env::var("TRANSCRIPT_FILE").unwrap_or_else(|_| "./transcript.json".to_string());
        let transcript_progress = format!("{}.new", transcript);
        Self {
            github_max_creation_time:    DateTime::parse_from_rfc3339(
                constants::GITHUB_ACCOUNT_CREATION_DEADLINE,
            )
            .unwrap(),
            eth_check_nonce_at_block:    constants::ETH_CHECK_NONCE_AT_BLOCK.to_string(),
            eth_min_nonce:               constants::ETH_MIN_NONCE,
            eth_rpc_url:                 env::var("ETH_RPC_URL").expect("Missing ETH_RPC_URL"),
            transcript_file:             PathBuf::from(transcript),
            transcript_in_progress_file: PathBuf::from(transcript_progress),
        }
    }
}
