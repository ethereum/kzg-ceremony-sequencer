mod api;
mod constants;
mod jwt;
mod keys;
mod sessions;

use crate::api::v1::{
    auth::{auth_client_string, authorised},
    contribute::contribute,
    info::{current_state, jwt_info, status},
    slot::slot_join,
};
use axum::{
    extract::Extension,
    response::Html,
    routing::{get, post},
    Router,
};
use constants::{
    LOBBY_CHECKIN_DEADLINE, LOBBY_FLUSH_INTERVAL, OAUTH_AUTH_URL, OAUTH_REDIRECT_URL,
    OAUTH_TOKEN_URL,
};
use jwt::Receipt;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use sessions::{SessionId, SessionInfo};
use small_powers_of_tau::sdk::Transcript;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::RwLock, time::Interval};

pub type SharedTranscript = Arc<RwLock<Transcript>>;
pub(crate) type SharedState = Arc<RwLock<AppState>>;

#[tokio::main]
async fn main() {
    let transcript = SharedTranscript::default();
    let shared_state = SharedState::default();

    let shared_state_clone = shared_state.clone();

    // Spawn automatic queue flusher -- flushes those in the lobby whom have not pinged in a
    // considerable amount of time
    let interval = tokio::time::interval(Duration::from_secs(LOBBY_FLUSH_INTERVAL as u64));
    tokio::spawn(clear_lobby_on_interval(shared_state_clone, interval));

    let oauth_client = oauth_client();

    let app = Router::new()
        .route("/hello_world", get(hello_world))
        .route("/auth/request_link", get(auth_client_string))
        .route("/auth/authorised", get(authorised))
        .route("/slot/join", post(slot_join))
        .route("/contribute", post(contribute))
        .route("/info/status", get(status))
        .route("/info/jwt", get(jwt_info))
        .route("/info/current_state", get(current_state))
        .layer(Extension(shared_state))
        .layer(Extension(oauth_client))
        .layer(Extension(transcript));

    let addr = "[::]:3000".parse().unwrap();

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn oauth_client() -> BasicClient {
    let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID!");
    let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!");

    let redirect_url = env::var("REDIRECT_URL").unwrap_or_else(|_| OAUTH_REDIRECT_URL.to_string());
    let auth_url = env::var("AUTH_URL").unwrap_or_else(|_| OAUTH_AUTH_URL.to_string());
    let token_url = env::var("TOKEN_URL").unwrap_or_else(|_| OAUTH_TOKEN_URL.to_string());

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

async fn hello_world() -> Html<&'static str> {
    Html("<h1>Server is Running</h1>")
}

type IdTokenSub = String;
type CsrfToken = String;

// TODO This is currently in memory as its easier to test.
// TODO We can add a trait to describe what we need adn make storage persistent
// TODO we only need to Save
#[derive(Default)]
pub(crate) struct AppState {
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

    receipts: Vec<Receipt>,

    // List of all users who have finished contributing, we store them using the
    // unique id, we attain from the social provider
    // This is their `sub`
    // TODO: we also need to save the blacklist of those
    // TODO who went over three minutes
    //
    finished_contribution: BTreeSet<IdTokenSub>,
}

impl AppState {
    pub fn clear_contribution_spot(&mut self) {
        // Note: when reserving a contribution spot
        // we remove the user from the lobby
        // So simply setting this to None, will forget them
        self.participant = None;
    }
    pub fn reserve_contribution_spot(&mut self, session_id: SessionId) {
        let session_info = self.lobby.remove(&session_id).unwrap();

        self.participant = Some((session_id, session_info));
    }
}

pub(crate) async fn clear_lobby_on_interval(state: SharedState, mut interval: Interval) {
    loop {
        interval.tick().await;

        let now = Instant::now();
        // Predicate that returns true whenever users go over the ping deadline
        let predicate = |session_info: &SessionInfo| -> bool {
            let time_diff = now - session_info.last_ping_time;
            time_diff > Duration::from_secs(LOBBY_CHECKIN_DEADLINE as u64)
        };

        let clone = state.clone();
        clear_lobby(clone, predicate).await
    }
}

async fn clear_lobby(state: SharedState, predicate: impl Fn(&SessionInfo) -> bool) {
    let mut app_state = state.write().await;

    // Iterate top `MAX_LOBBY_SIZE` participants and check if they have
    let participants = app_state.lobby.keys().cloned();
    let mut sessions_to_kick = Vec::new();

    for participant in participants {
        // Check if they are over their ping deadline
        match app_state.lobby.get(&participant) {
            Some(session_info) => {
                if predicate(session_info) {
                    sessions_to_kick.push(participant)
                }
            }
            None => {
                // This should not be possible
                tracing::debug!("session id in queue but not a valid session")
            }
        }
    }
    for session_id in sessions_to_kick {
        app_state.lobby.remove(&session_id);
    }
}

#[tokio::test]
async fn flush_on_predicate() {
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

        fn test_jwt(exp: u64) -> jwt::IdToken {
            jwt::IdToken {
                sub: String::from("foo"),
                nickname: String::from("foo"),
                provider: String::from("foo"),
                exp,
            }
        }

        for i in 0..to_add {
            let id = SessionId::new();

            let session_info = SessionInfo {
                token: test_jwt(i as u64),
                last_ping_time: Instant::now(),
            };

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
        assert!(info.token.exp % 2 == 1)
    }
}
