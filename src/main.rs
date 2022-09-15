#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
#![cfg_attr(any(test, feature = "bench"), allow(clippy::wildcard_imports))]
// TODO: These lints
#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::module_name_repetitions)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use crate::data::transcript::read_transcript_file;
use axum::{
    extract::Extension,
    response::Html,
    routing::{get, post},
    Router, Server,
};
use chrono::{DateTime, FixedOffset};
use clap::Parser;
use cli_batteries::{await_shutdown, version};
use eyre::{bail, ensure, eyre, Result as EyreResult};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use sessions::{SessionId, SessionInfo};
use storage::persistent_storage_client;
use tokio::{
    sync::RwLock,
    time::{Instant, Interval},
};
use tower_http::trace::TraceLayer;
use tracing::info;
use url::{Host, Url};

use crate::{
    api::v1::{
        auth::{auth_client_link, github_callback, siwe_callback},
        contribute::contribute,
        info::{current_state, jwt_info, status},
        lobby::try_contribute,
    },
    constants::{
        GITHUB_OAUTH_AUTH_URL, GITHUB_OAUTH_REDIRECT_URL, GITHUB_OAUTH_TOKEN_URL,
        LOBBY_CHECKIN_FREQUENCY_SEC, LOBBY_CHECKIN_TOLERANCE_SEC, LOBBY_FLUSH_INTERVAL,
        SIWE_OAUTH_AUTH_URL, SIWE_OAUTH_REDIRECT_URL, SIWE_OAUTH_TOKEN_URL,
    },
    data::transcript::{Contribution, Transcript},
    keys::Keys,
    test_transcript::TestTranscript,
};

mod api;
mod constants;
mod data;
mod jwt;
mod keys;
mod sessions;
mod storage;
mod test_transcript;
#[cfg(test)]
mod test_util;

pub type SharedTranscript<T> = Arc<RwLock<T>>;
pub(crate) type SharedState = Arc<RwLock<AppState>>;

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
        async_main::<TestTranscript>,
    );
}

async fn async_main<T>(options: Options) -> EyreResult<()>
where
    T: Transcript + Send + Sync + 'static,
    T::ContributionType: Send,
    <<T as Transcript>::ContributionType as Contribution>::Receipt: Send,
{
    // Load JWT keys
    keys::KEYS
        .set(Keys::new(options.keys).await?)
        .map_err(|_e| eyre!("KEYS was already set."))?;

    let shared_state = SharedState::default();
    let config = AppConfig::default();
    let transcript_data = read_transcript_file::<T>(config.transcript_file.clone()).await;
    let transcript = Arc::new(RwLock::new(transcript_data));

    let shared_state_clone = shared_state.clone();

    // Spawn automatic queue flusher -- flushes those in the lobby whom have not
    // pinged in a considerable amount of time
    let interval = tokio::time::interval(Duration::from_secs(LOBBY_FLUSH_INTERVAL as u64));
    tokio::spawn(clear_lobby_on_interval(shared_state_clone, interval));

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
        .layer(Extension(shared_state))
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

#[derive(Clone)]
pub struct SiweOAuthClient {
    client: BasicClient,
}

impl Deref for SiweOAuthClient {
    type Target = BasicClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

fn siwe_oauth_client() -> SiweOAuthClient {
    let client_id = env::var("SIWE_CLIENT_ID").expect("Missing SIWE_CLIENT_ID!");
    let client_secret = env::var("SIWE_CLIENT_SECRET").expect("Missing SIWE_CLIENT_SECRET!");

    let redirect_url =
        env::var("SIWE_REDIRECT_URL").unwrap_or_else(|_| SIWE_OAUTH_REDIRECT_URL.to_string());
    let auth_url = env::var("SIWE_AUTH_URL").unwrap_or_else(|_| SIWE_OAUTH_AUTH_URL.to_string());
    let token_url = env::var("SIWE_TOKEN_URL").unwrap_or_else(|_| SIWE_OAUTH_TOKEN_URL.to_string());

    SiweOAuthClient {
        client: BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(auth_url).unwrap(),
            Some(TokenUrl::new(token_url).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap()),
    }
}

#[derive(Clone)]
pub struct GithubOAuthClient {
    client: BasicClient,
}

impl Deref for GithubOAuthClient {
    type Target = BasicClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

fn github_oauth_client() -> GithubOAuthClient {
    let client_id = env::var("GITHUB_CLIENT_ID").expect("Missing GITHUB_CLIENT_ID!");
    let client_secret = env::var("GITHUB_CLIENT_SECRET").expect("Missing GITHUB_CLIENT_SECRET!");
    let redirect_url =
        env::var("GITHUB_REDIRECT_URL").unwrap_or_else(|_| GITHUB_OAUTH_REDIRECT_URL.to_string());
    let auth_url =
        env::var("GITHUB_AUTH_URL").unwrap_or_else(|_| GITHUB_OAUTH_AUTH_URL.to_string());
    let token_url =
        env::var("GITHUB_TOKEN_URL").unwrap_or_else(|_| GITHUB_OAUTH_TOKEN_URL.to_string());
    GithubOAuthClient {
        client: BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(auth_url).unwrap(),
            Some(TokenUrl::new(token_url).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap()),
    }
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

type IdTokenSub = String;
type CsrfToken = String;

#[derive(Default)]
pub struct AppState {
    // Use can now be in the lobby and only those who are in
    // the lobby can ping to start participating
    lobby: BTreeMap<SessionId, SessionInfo>,

    // CSRF tokens for oAUTH
    csrf_tokens: BTreeSet<CsrfToken>,

    // A map between a users unique social id
    // and their session.
    // We use this to check if a user has already entered the lobby
    unique_id_session: BTreeMap<IdTokenSub, SessionId>,

    num_contributions: usize,

    // This is the Id of the current participant
    // Only they are allowed to call /contribute
    participant: Option<(SessionId, SessionInfo)>,

    // List of all users who have finished contributing, we store them using the
    // unique id, we attain from the social provider
    // This is their `sub`
    // TODO: we also need to save the blacklist of those
    // TODO who went over three minutes
    finished_contribution: BTreeSet<IdTokenSub>,
}

impl AppState {
    pub fn clear_current_contributor(&mut self) {
        // Note: when reserving a contribution spot
        // we remove the user from the lobby
        // So simply setting this to None, will forget them
        self.participant = None;
    }

    /// # Panics
    ///
    /// Panics if the user is not in the lobby.
    pub fn set_current_contributor(&mut self, session_id: SessionId) {
        let session_info = self.lobby.remove(&session_id).unwrap();

        self.participant = Some((session_id, session_info));
    }
}

pub async fn clear_lobby_on_interval(state: SharedState, mut interval: Interval) {
    let max_diff =
        Duration::from_secs((LOBBY_CHECKIN_FREQUENCY_SEC + LOBBY_CHECKIN_TOLERANCE_SEC) as u64);
    loop {
        interval.tick().await;

        let now = Instant::now();
        // Predicate that returns true whenever users go over the ping deadline
        let predicate = |session_info: &SessionInfo| -> bool {
            let time_diff = now - session_info.last_ping_time;
            time_diff > max_diff
        };

        let clone = state.clone();
        clear_lobby(clone, predicate).await;
    }
}

async fn clear_lobby(state: SharedState, predicate: impl Fn(&SessionInfo) -> bool + Send) {
    let mut app_state = state.write().await;

    // Iterate top `MAX_LOBBY_SIZE` participants and check if they have
    let participants = app_state.lobby.keys().cloned();
    let mut sessions_to_kick = Vec::new();

    for participant in participants {
        // Check if they are over their ping deadline
        app_state.lobby.get(&participant).map_or_else(
            ||
                // This should not be possible
                tracing::debug!("session id in queue but not a valid session"),
            |session_info| {
                if predicate(session_info) {
                    sessions_to_kick.push(participant);
                }
            },
        );
    }
    for session_id in sessions_to_kick {
        app_state.lobby.remove(&session_id);
    }
}

#[tokio::test]
async fn flush_on_predicate() {
    use crate::test_util::create_test_session_info;

    // We want to test that the clear_lobby_on_interval function works as expected.
    //
    // It uses time which can get a bit messy to test correctly
    // However, the clear_lobby function which is a sub procedure takes
    // in a predicate function
    //
    // We can test this instead to ensure that if the predicate fails
    // users get kicked. We will use the predicate on the `exp` field
    // instead of the ping-time

    let to_add = 100;

    let arc_state = SharedState::default();

    {
        let mut state = arc_state.write().await;

        for i in 0..to_add {
            let id = SessionId::new();
            let session_info = create_test_session_info(i as u64);
            state.lobby.insert(id, session_info);
        }
    }

    // Now we are going to kick all of the participants whom have an
    // expiry which is an even number
    let predicate = |session_info: &SessionInfo| -> bool { session_info.token.exp % 2 == 0 };

    clear_lobby(arc_state.clone(), predicate).await;

    // Now we expect that half of the lobby should be
    // kicked
    let state = arc_state.write().await;
    assert_eq!(state.lobby.len(), to_add / 2);

    let session_ids = state.lobby.keys().cloned();
    for id in session_ids {
        let info = state.lobby.get(&id).unwrap();
        // We should just be left with `exp` numbers which are odd
        assert_eq!(info.token.exp % 2, 1);
    }
}

fn parse_url(url: &Url) -> EyreResult<(SocketAddr, &str)> {
    ensure!(
        url.scheme() == "http",
        "Only http:// is supported in {}",
        url
    );
    let prefix = url.path();
    let ip: IpAddr = match url.host() {
        Some(Host::Ipv4(ip)) => ip.into(),
        Some(Host::Ipv6(ip)) => ip.into(),
        Some(_) => bail!("Cannot bind {}", url),
        None => Ipv4Addr::LOCALHOST.into(),
    };
    let port = url.port().unwrap_or(8080);
    let addr = SocketAddr::new(ip, port);
    Ok((addr, prefix))
}
