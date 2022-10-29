use crate::{
    sessions::{SessionId, SessionInfo, self},
    storage::PersistentStorage, api::v1::lobby,
};
use async_session::Session;
use clap::Parser;
use std::{
    collections::{BTreeMap, BTreeSet}, mem, num::ParseIntError, str::FromStr, sync::Arc, time::Duration,
};
use thiserror::Error;
use tokio::{sync::Mutex, time::Instant};

fn duration_from_str(value: &str) -> Result<Duration, ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(value)?))
}

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
#[group(skip)]
pub struct Options {
    /// Timeout for participants to contribute to the ceremony in seconds.
    #[clap(long, env, value_parser=duration_from_str, default_value="180")]
    pub compute_deadline: Duration,

    /// How often participants should ping the server to keep their session
    /// alive in seconds.
    #[clap(long, env, value_parser=duration_from_str, default_value="30")]
    pub lobby_checkin_frequency: Duration,

    /// How much the ping can be late in seconds
    #[clap(long, env, value_parser=duration_from_str, default_value="2")]
    pub lobby_checkin_tolerance: Duration,

    /// How often the server should check for dead sessions in seconds.
    #[clap(long, env, value_parser=duration_from_str, default_value="5")]
    pub lobby_flush_interval: Duration,

    /// Maximum number of participants in the lobby.
    #[clap(long, env, default_value = "1000")]
    pub max_lobby_size: usize,

    /// How long the session is valid if user doesn't take any actions, in seconds.
    /// Default: 24 hours
    #[clap(long, env, value_parser=duration_from_str, default_value="86400")]
    pub session_expiration: Duration,

    /// Maximum number of active sessions.
    #[clap(long, env, default_value = "100000")]
    pub max_num_sessions: usize
}

#[derive(Default)]
pub struct LobbyState {
    pub sessions:           BTreeMap<SessionId, SessionInfo>,
    pub lobby_participants: BTreeSet<SessionId>,
    pub active_contributor: ActiveContributor,
}

#[derive(Clone, Debug)]
pub struct SessionInfoWithId {
    id:   SessionId,
    info: SessionInfo,
}

pub enum ActiveContributor {
    None,
    AwaitingContribution(SessionInfoWithId),
    Contributing(SessionInfoWithId),
}

impl Default for ActiveContributor {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Error)]
pub enum ActiveContributorError {
    #[error("another contribution in progress")]
    AnotherContributionInProgress,
    #[error("not user's turn")]
    NotUsersTurn,
    #[error("user not in the lobby")]
    UserNotInLobby,
}

#[derive(Clone, Default)]
pub struct SharedLobbyState {
    inner: Arc<Mutex<LobbyState>>,
}

impl SharedLobbyState {
    pub async fn set_current_contributor(
        &self,
        participant: &SessionId,
        compute_deadline: Duration,
        storage: PersistentStorage,
    ) -> Result<(), ActiveContributorError> {
        let mut state = self.inner.lock().await;

        if matches!(state.active_contributor, ActiveContributor::None) {
            if !state.lobby_participants.contains(participant) {
                return Err(ActiveContributorError::UserNotInLobby);
            }
            let session_info = state
                .sessions
                .remove(participant)
                .ok_or(ActiveContributorError::UserNotInLobby)?;

            state.active_contributor = ActiveContributor::AwaitingContribution(SessionInfoWithId {
                id:   participant.clone(),
                info: session_info,
            });

            let inner = self.inner.clone();
            let participant = participant.clone();

            tokio::spawn(Self::expire_current_contributor(
                inner,
                participant,
                compute_deadline,
                storage,
            ));

            return Ok(());
        }

        Err(ActiveContributorError::AnotherContributionInProgress)
    }

    pub async fn begin_contributing(
        &self,
        participant: &SessionId,
    ) -> Result<SessionInfo, ActiveContributorError> {
        let mut state = self.inner.lock().await;

        match mem::replace(&mut state.active_contributor, ActiveContributor::None) {
            ActiveContributor::AwaitingContribution(info) if &info.id == participant => {
                state.active_contributor = ActiveContributor::Contributing(info.clone());
                Ok(info.info)
            }
            other => {
                state.active_contributor = other;
                Err(ActiveContributorError::NotUsersTurn)
            }
        }
    }

    pub async fn abort_contribution(
        &self,
        participant: &SessionId,
    ) -> Result<(), ActiveContributorError> {
        let mut state = self.inner.lock().await;

        if !matches!(&state.active_contributor, ActiveContributor::AwaitingContribution(x) if &x.id == participant)
        {
            return Err(ActiveContributorError::NotUsersTurn);
        }

        state.active_contributor = ActiveContributor::None;

        Ok(())
    }

    pub async fn clear_current_contributor(&self) {
        let mut state = self.inner.lock().await;
        state.active_contributor = ActiveContributor::None;
    }

    pub async fn clear_lobby(&self, predicate: impl Fn(&SessionInfo) -> bool + Copy + Send) {
        let mut lobby_state = self.inner.lock().await;
        let mut remove_participants: Vec<SessionId> = vec![];
        for id in &lobby_state.lobby_participants {
            let should_delete = lobby_state.sessions.get(id).map(predicate).unwrap_or(true);
            if should_delete {
                remove_participants.push(id.clone());
            }
        }
        for participant in &remove_participants {
            lobby_state.lobby_participants.remove(participant);
        }
    }

    pub async fn clear_session(&self, predicate: impl Fn(&SessionInfo) -> bool + Send) {
        let mut lobby_state = self.inner.lock().await;
        lobby_state.sessions.retain(|_, info| !predicate(info));
    }

    pub async fn modify_participant<R>(
        &self,
        session_id: &SessionId,
        fun: impl FnOnce(&mut SessionInfo) -> R + Send,
    ) -> Option<R> {
        let mut lobby_state = self.inner.lock().await;
        lobby_state.sessions.get_mut(session_id).map(fun)
    }

    pub async fn get_lobby_size(&self) -> usize {
        self.inner.lock().await.lobby_participants.len()
    }

    pub async fn insert_session(&self, session_id: SessionId, session_info: SessionInfo) {
        // TODO: check in num of sessions not exceeded
        self.inner
            .lock()
            .await
            .sessions
            .insert(session_id, session_info);
    }

    pub async fn enter_lobby(&self, session_id: &SessionId) -> bool {
        // TODO: check if lobby size not exceeded
        self.inner
            .lock()
            .await
            .lobby_participants
            .insert(session_id.clone());
        true
    }

    #[cfg(test)]
    pub async fn get_all_participants(&self) -> Vec<SessionInfoWithId> {
        let state = self.inner.lock().await;

        state
            .lobby_participants
            .iter()
            .map(|id| SessionInfoWithId {
                id:   id.clone(),
                info: state.sessions.get(id).unwrap().clone(),
            })
            .collect()
    }

    async fn expire_current_contributor(
        inner: Arc<Mutex<LobbyState>>,
        participant: SessionId,
        compute_deadline: Duration,
        storage: PersistentStorage,
    ) {
        tokio::time::sleep(compute_deadline).await;

        let mut state = inner.lock().await;

        if matches!(&state.active_contributor, ActiveContributor::AwaitingContribution(x) if x.id == participant)
        {
            state.active_contributor = ActiveContributor::None;

            drop(state);
            storage.expire_contribution(&participant.0).await.unwrap();
        }
    }
}

pub async fn clear_lobby_on_interval(state: SharedLobbyState, options: Options) {
    let max_lobby_diff = options.lobby_checkin_frequency + options.lobby_checkin_tolerance;
    let max_session_diff = options.session_expiration;

    let mut interval = tokio::time::interval(options.lobby_flush_interval);

    loop {
        interval.tick().await;

        let now = Instant::now();
        // Predicate that returns true whenever users go over the ping deadline
        let lobby_predicate = |session_info: &SessionInfo| -> bool {
            let time_diff = now - session_info.last_ping_time;
            time_diff > max_lobby_diff
        };
        state.clear_lobby(lobby_predicate).await;

        let session_predicate = |session_info: &SessionInfo| -> bool {
            let time_diff = now - session_info.last_ping_time;
            time_diff > max_session_diff
        };
        state.clear_session(session_predicate).await;
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
        for i in 0..to_add {
            let id = SessionId::new();
            let session_info = create_test_session_info(i as u64);
            arc_state.insert_session(id.clone(), session_info).await;
            arc_state.enter_lobby(&id).await;
        }
    }

    // Now we are going to kick all of the participants whom have an
    // expiry which is an even number
    let predicate = |session_info: &SessionInfo| -> bool { session_info.token.exp % 2 == 0 };

    arc_state.clear_lobby(predicate).await;

    // Now we expect that half of the lobby should be
    // kicked
    let participants = arc_state.get_all_participants().await;
    assert_eq!(participants.len(), to_add / 2);

    for participant in participants {
        // We should just be left with `exp` numbers which are odd
        assert_eq!(participant.info.token.exp % 2, 1);
    }
}
