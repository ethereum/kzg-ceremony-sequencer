use crate::{
    sessions::{SessionId, SessionInfo},
    storage::PersistentStorage,
};
use clap::Parser;
use std::{
    collections::BTreeMap, mem, num::ParseIntError, str::FromStr, sync::Arc, time::Duration,
};
use thiserror::Error;
use tokio::{sync::Mutex, time::Instant};

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
    pub participants:       BTreeMap<SessionId, SessionInfo>,
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
            let session_info = state
                .participants
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

    pub async fn clear_lobby(&self, predicate: impl Fn(&SessionInfo) -> bool + Send) {
        let mut lobby_state = self.inner.lock().await;

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
            lobby_state.participants.remove(&session_id);
        }
    }

    pub async fn modify_participant<R>(
        &self,
        session_id: &SessionId,
        fun: impl FnOnce(&mut SessionInfo) -> R,
    ) -> Option<R> {
        let mut lobby_state = self.inner.lock().await;
        lobby_state.participants.get_mut(session_id).map(fun)
    }

    pub async fn get_lobby_size(&self) -> usize {
        self.inner.lock().await.participants.len()
    }

    pub async fn insert_participant(&self, session_id: SessionId, session_info: SessionInfo) {
        self.inner
            .lock()
            .await
            .participants
            .insert(session_id, session_info);
    }

    #[cfg(test)]
    pub async fn get_all_participants(&self) -> Vec<SessionInfoWithId> {
        self.inner
            .lock()
            .await
            .participants
            .iter()
            .map(|(id, info)| SessionInfoWithId {
                id:   id.clone(),
                info: info.clone(),
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

        if matches!(&state.active_contributor, ActiveContributor::AwaitingContribution(x) if &x.id == &participant)
        {
            state.active_contributor = ActiveContributor::None;

            drop(state);
            storage.expire_contribution(&participant.0).await.unwrap();
        }
    }
}

pub async fn clear_lobby_on_interval(state: SharedLobbyState, options: Options) {
    let max_diff = options.lobby_checkin_frequency + options.lobby_checkin_tolerance;

    let mut interval = tokio::time::interval(options.lobby_flush_interval);

    loop {
        interval.tick().await;

        let now = Instant::now();
        // Predicate that returns true whenever users go over the ping deadline
        let predicate = |session_info: &SessionInfo| -> bool {
            let time_diff = now - session_info.last_ping_time;
            time_diff > max_diff
        };

        state.clear_lobby(predicate).await;
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
            arc_state.insert_participant(id, session_info).await;
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
