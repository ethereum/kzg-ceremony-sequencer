use crate::{sessions::{SessionId, SessionInfo}, storage::PersistentStorage};
use clap::Parser;
use std::{collections::BTreeMap, num::ParseIntError, str::FromStr, sync::Arc, time::Duration};
use tokio::{
    sync::{RwLock, Mutex},
    time::Instant,
};

fn duration_from_str(value: &str) -> Result<Duration, ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(value)?))
}

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct Options {
    #[clap(long, env, value_parser=duration_from_str, default_value="180")]
    pub compute_deadline: Duration,

    #[clap(long, env, value_parser=duration_from_str, default_value="30")]
    pub lobby_checkin_frequency: Duration,

    #[clap(long, env, value_parser=duration_from_str, default_value="2")]
    pub lobby_checkin_tolerance: Duration,

    #[clap(long, env, value_parser=duration_from_str, default_value="5")]
    pub lobby_flush_interval: Duration,

    #[clap(long, env, default_value = "1000")]
    pub max_lobby_size: usize,
}

#[derive(Default)]
pub struct LobbyState {
    pub participants: BTreeMap<SessionId, SessionInfo>,
}

type Deadline = Instant;

pub enum ActiveContributor {
    None,
    AwaitingContribution(SessionId, Deadline),
    Contributing(SessionId, Deadline),
}

impl Default for ActiveContributor {
    fn default() -> Self {
        ActiveContributor::None
    }
}

#[derive(Debug)]
pub enum ActiveContributorError {
    AnotherContributionInProgress,
    NotUsersTurn,
}

#[derive(Clone, Default)]
pub struct SharedContributorState {
    inner: Arc<Mutex<ActiveContributor>>,
}

impl SharedContributorState {
    pub async fn set_current_contributor(&self, participant: &SessionId, compute_deadline: Duration, storage: PersistentStorage) -> Result<(), ActiveContributorError> {
        let mut state = self.inner.lock().await;
        if matches!(*state, ActiveContributor::None) {
            let deadline = Instant::now() + Duration::from_secs(10);
            *state = ActiveContributor::AwaitingContribution(participant.clone(), deadline);
            
            let inner = self.inner.clone();
            let participant = participant.clone();

            tokio::spawn(SharedContributorState::expire_current_contributor(inner, participant, compute_deadline, storage));

            return Ok(())
        }

        Err(ActiveContributorError::AnotherContributionInProgress)
    }

    pub async fn begin_contributing(&self, participant: &SessionId) -> Result<(), ActiveContributorError> {
        let mut state = self.inner.lock().await;

        if !matches!(&*state, ActiveContributor::AwaitingContribution(x, _) if x == participant) {
            return Err(ActiveContributorError::NotUsersTurn)
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        *state = ActiveContributor::Contributing(participant.clone(), deadline);

        Ok(())
    }

    pub async fn clear(&self) {
        let mut state = self.inner.lock().await;
        *state = ActiveContributor::None;
    }

    async fn expire_current_contributor(
        inner: Arc<Mutex<ActiveContributor>>,
        participant: SessionId,
        compute_deadline: Duration,
        storage: PersistentStorage,
    ) {
        println!(
            "{:?} starting timer for session id {}",
            Instant::now(), &participant.to_string()
        );

        tokio::time::sleep(compute_deadline).await;

        let mut state = inner.lock().await;

        if matches!(&*state, ActiveContributor::AwaitingContribution(x, _) if x == &participant) {
            println!(
                "{:?} User with session id {} took too long to contribute",
                Instant::now(), participant.to_string()
            );
            *state = ActiveContributor::None;
            
            drop(state);
            storage.expire_contribution(&participant.0).await.unwrap();
        }
    }
}

pub type SharedLobbyState = Arc<RwLock<LobbyState>>;

pub async fn clear_lobby_on_interval(state: SharedLobbyState, options: Options) {
    let max_diff = 100 * (options.lobby_checkin_frequency + options.lobby_checkin_tolerance);

    let mut interval = tokio::time::interval(options.lobby_flush_interval);

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

async fn clear_lobby(state: SharedLobbyState, predicate: impl Fn(&SessionInfo) -> bool + Send) {
    let mut lobby_state = state.write().await;

    // Iterate top `MAX_LOBBY_SIZE` participants and check if they have
    let participants = lobby_state.participants.keys().cloned();
    let mut sessions_to_kick = Vec::new();

    for participant in participants {
        // Check if they are over their ping deadline
        lobby_state.participants.get(&participant).map_or_else(
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
        println!("removing participant session {}", session_id);
        lobby_state.participants.remove(&session_id);
    }
}

#[tokio::test]
async fn flush_on_predicate() {
    use crate::{sessions::SessionId, test_util::create_test_session_info};

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

    let arc_state = SharedLobbyState::default();

    {
        let mut state = arc_state.write().await;

        for i in 0..to_add {
            let id = SessionId::new();
            let session_info = create_test_session_info(i as u64);
            state.participants.insert(id, session_info);
        }
    }

    // Now we are going to kick all of the participants whom have an
    // expiry which is an even number
    let predicate = |session_info: &SessionInfo| -> bool { session_info.token.exp % 2 == 0 };

    clear_lobby(arc_state.clone(), predicate).await;

    // Now we expect that half of the lobby should be
    // kicked
    let state = arc_state.write().await;
    assert_eq!(state.participants.len(), to_add / 2);

    let session_ids = state.participants.keys().cloned();
    for id in session_ids {
        let info = state.participants.get(&id).unwrap();
        // We should just be left with `exp` numbers which are odd
        assert_eq!(info.token.exp % 2, 1);
    }
}
