#![allow(dead_code)]

mod api;
mod constants;
mod jwt;
mod keys;
mod queue_simple;
mod sessions;

use axum::{
    extract::Extension,
    response::Html,
    routing::{get, post},
    Router,
};
use constants::{
    ACTIVE_ZONE_CHECKIN_DEADLINE, MAX_QUEUE_SIZE, OAUTH_AUTH_URL, OAUTH_REDIRECT_URL,
    OAUTH_TOKEN_URL, QUEUE_FLUSH_INTERVAL,
};
use jwt::Receipt;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use queue_simple::Queue;
use sessions::{SessionId, SessionInfo};
use small_powers_of_tau::sdk::Transcript;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::RwLock, time::Interval};

// TODO Add CSRF validation for oauth CsrfToken (right now we ignore it)

use crate::api::v1::{
    auth::{auth_client_string, authorized},
    contribute::contribute,
    info::{current_transcript, history, status},
    ping::online_ping,
    queue::queue_join,
};

pub type SharedTranscript = Arc<RwLock<Transcript>>;
pub(crate) type SharedState = Arc<RwLock<AppState>>;

#[tokio::main]
async fn main() {
    let transcript = SharedTranscript::default();
    let shared_state = SharedState::default();

    let shared_state_clone = shared_state.clone();

    // Spawn automatic queue flusher
    let interval = tokio::time::interval(Duration::from_secs(QUEUE_FLUSH_INTERVAL as u64));
    tokio::spawn(clear_queue_on_interval(shared_state_clone, interval));

    let oauth_client = oauth_client();

    let app = Router::new()
        .route("/hello_world", get(hello_world))
        .route("/auth/request_link", get(auth_client_string))
        .route("/auth/authorized", get(authorized))
        .route("/queue/join", post(queue_join))
        .route("/status", post(status))
        // Probably remove
        .route("/history", post(history))
        .route("/current_transcript", get(current_transcript))
        .route("/contribute", post(contribute))
        .route("/ping", post(online_ping))
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

// TODO This is currently in memory as its easier to test.
// TODO We can add a trait to describe what we need adn make storage persistent
// TODO we only need to Save
#[derive(Default)]
pub(crate) struct AppState {
    // The queue object which stores the Id of all participants
    //
    // N.B. We cannot do Queue<SessionId, SessionInfo>
    // Because a user can have a SessionId but not be in the Queue
    queue: Queue<SessionId>,
    sessions: BTreeMap<SessionId, SessionInfo>,

    receipts: Vec<Receipt>,

    // List of all users who have finished contributing, we store them using the
    // unique id, we attain from the social provider
    // This is their `sub`
    finished_contribution: BTreeSet<String>,
}

impl AppState {
    pub fn advance_queue(&mut self) {
        if let Some(session_id) = self.queue.remove_participant_at_front() {
            self.sessions.remove(&session_id);
        };
    }
}

pub(crate) async fn clear_queue_on_interval(state: SharedState, mut interval: Interval) {
    loop {
        interval.tick().await;

        let now = Instant::now();
        // Predicate that returns true whenever users go over the ping deadline
        let predicate = |session_info: &SessionInfo| -> bool {
            let time_diff = now - session_info.last_ping_time;
            time_diff > Duration::from_secs(ACTIVE_ZONE_CHECKIN_DEADLINE as u64)
        };

        let clone = state.clone();
        clear_queue(clone, predicate).await
    }
}

async fn clear_queue(state: SharedState, predicate: impl Fn(&SessionInfo) -> bool) {
    let mut app_state = state.write().await;

    // Iterate top `MAX_QUEUE_SIZE` participants and check if they have
    let participants = app_state.queue.get_first_n(MAX_QUEUE_SIZE);
    let mut sessions_to_kick = Vec::new();

    for participant in participants {
        // Check if they are over their ping deadline
        match app_state.sessions.get(&participant) {
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
        app_state.sessions.remove(&session_id);
        app_state.queue.remove(&session_id);
    }
}

#[tokio::test]
async fn flush_on_predicate() {
    // We want to test that the clear_queue_on_interval function works as expected.
    //
    // It uses time which can get a bit messy to test correctly
    // However, the clear_queue function which is a sub procedure takes
    // in a predicate function
    //
    // We can test this instead to ensure that if the predicate fails
    // users get kicked. We will use the predicate on the `exp` field
    // instead of the ping-time

    let to_add = 100;

    let arc_state = SharedState::default();
    // Put it in this block so the lock on state
    // gets dropped when block finishes
    {
        let mut state = arc_state.write().await;
        // We could move the max queue size condition to the queue object

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

            state.queue.add_participant(id.clone());

            let session_info = SessionInfo {
                token: test_jwt(i as u64),
                last_ping_time: Instant::now(),
            };

            state.sessions.insert(id, session_info);
        }
    }

    // Now we are going to kick all of the participants whom have an
    // expiry which is an even number
    let predicate = |session_info: &SessionInfo| -> bool { session_info.token.exp % 2 == 0 };

    clear_queue(arc_state.clone(), predicate).await;

    // Now we expect that half of the queue should be
    // kicked
    let state = arc_state.write().await;
    assert_eq!(state.queue.num_participants(), to_add / 2);

    let session_ids = state.queue.get_first_n(to_add / 2);
    for id in session_ids {
        let info = state.sessions.get(&id).unwrap();
        // We should just be left with `exp` numbers which are odd
        assert!(info.token.exp % 2 == 1)
    }
}
