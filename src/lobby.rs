use std::time::Duration;

use tokio::time::{Interval, Instant};

use crate::{SharedState, constants::{LOBBY_CHECKIN_FREQUENCY_SEC, LOBBY_CHECKIN_TOLERANCE_SEC}, sessions::SessionInfo};

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
    use crate::sessions::SessionId;

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
