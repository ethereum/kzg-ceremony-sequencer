use crate::common::{
    mock_auth_service,
    mock_auth_service::{AuthState, GhUser, TestUser},
};
use clap::Parser;
use kzg_ceremony_crypto::BatchTranscript;
use kzg_ceremony_sequencer::{io::read_json_file, start_server, Options};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::{broadcast, oneshot, Mutex, MutexGuard, OnceCell};
use url::Url;

fn test_options() -> Options {
    let args: Vec<&str> = vec![
        "kzg-ceremony-sequencer",
        "--ceremony-sizes",
        "4,3:8,3:16,3",
        "--server",
        "http://127.0.0.1:3000",
        "--gh-token-url",
        "http://127.0.0.1:3001/github/oauth/token",
        "--gh-userinfo-url",
        "http://127.0.0.1:3001/github/user",
        "--gh-client-secret",
        "INVALID",
        "--gh-client-id",
        "INVALID",
        "--eth-token-url",
        "http://127.0.0.1:3001/eth/oauth/token",
        "--eth-userinfo-url",
        "http://127.0.0.1:3001/eth/user",
        "--eth-rpc-url",
        "http://127.0.0.1:3001/eth/rpc",
        "--eth-client-secret",
        "INVALID",
        "--eth-client-id",
        "INVALID",
        "--database-url",
        "sqlite::memory:",
    ];
    Options::parse_from(args)
}

pub struct Harness {
    pub options:     Options,
    pub auth_state:  AuthState,
    shutdown_sender: broadcast::Sender<()>,
    /// Needed to keep the lock on the server port for the duration of a test.
    #[allow(dead_code)]
    lock:            MutexGuard<'static, ()>,
    /// Needed to keep the temp directory alive throughout the test.
    #[allow(dead_code)]
    temp_dir:        TempDir,
}

impl Harness {
    pub async fn read_transcript_file(&self) -> BatchTranscript {
        read_json_file(self.options.transcript_file.clone()).await
    }

    pub async fn create_gh_user(&self, name: String) -> TestUser {
        self.auth_state
            .register_gh_user(GhUser {
                created_at: "2022-01-01T00:00:00Z".to_string(),
                name,
            })
            .await
    }

    pub async fn create_eth_user(&self) -> TestUser {
        self.auth_state.register_eth_user().await
    }

    pub fn app_path(&self, path: &str) -> Url {
        self.options
            .server
            .join(path)
            .expect("must be a valid path")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown_sender.send(()).unwrap();
    }
}

impl Harness {
    pub async fn run(mut options: Options) -> Harness {
        let lock = server_lock().await.lock().await;
        let temp_dir = tempdir().unwrap();
        let transcript = temp_dir.path().join("transcript.json");
        let transcript_wip = temp_dir.path().join("transcript.json.next");
        options.transcript_file = transcript;
        options.transcript_in_progress_file = transcript_wip;
        let server_options = options.clone();
        let (shutdown_sender, mut app_shutdown_receiver) = broadcast::channel::<()>(1);
        let mut auth_shutdown_receiver = shutdown_sender.subscribe();
        let (app_start_sender, app_start_receiver) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let server = start_server(server_options).await.unwrap();
            app_start_sender.send(()).unwrap();
            server
                .with_graceful_shutdown(async move { app_shutdown_receiver.recv().await.unwrap() })
                .await
                .unwrap();
        });
        app_start_receiver.await.unwrap();
        let (auth_start_sender, auth_start_receiver) = oneshot::channel::<()>();
        let auth_state = AuthState::default();
        let auth_state_for_server = auth_state.clone();
        tokio::spawn(async move {
            let server = mock_auth_service::start_server(auth_state_for_server);
            auth_start_sender.send(()).unwrap();
            server
                .with_graceful_shutdown(async move { auth_shutdown_receiver.recv().await.unwrap() })
                .await
                .unwrap();
        });
        auth_start_receiver.await.unwrap();
        Harness {
            options: options.clone(),
            auth_state,
            shutdown_sender,
            lock,
            temp_dir,
        }
    }
}

static SERVER_LOCK: OnceCell<Mutex<()>> = OnceCell::const_new();

async fn server_lock() -> &'static Mutex<()> {
    SERVER_LOCK.get_or_init(|| async { Mutex::new(()) }).await
}

pub async fn run_test_harness() -> Harness {
    Builder::new().run().await
}

pub struct Builder {
    options: Options,
}

impl Builder {
    pub fn new() -> Builder {
        let mut options = test_options();
        options.lobby.lobby_checkin_frequency = Duration::from_millis(2000);
        options.lobby.lobby_checkin_tolerance = Duration::from_millis(2000);
        options.lobby.compute_deadline = Duration::from_millis(800);
        Self { options }
    }

    pub fn set_lobby_checkin_frequency(mut self, duration: Duration) -> Self {
        self.options.lobby.lobby_checkin_frequency = duration;
        self
    }

    pub fn set_lobby_checkin_tolerance(mut self, duration: Duration) -> Self {
        self.options.lobby.lobby_checkin_tolerance = duration;
        self
    }

    pub fn set_compute_deadline(mut self, duration: Duration) -> Self {
        self.options.lobby.compute_deadline = duration;
        self
    }

    pub fn set_lobby_flush_interval(mut self, duration: Duration) -> Self {
        self.options.lobby.lobby_flush_interval = duration;
        self
    }

    pub fn allow_multi_contribution(mut self) -> Self {
        self.options.multi_contribution = true;
        self
    }

    #[allow(dead_code)]
    pub fn set_db_url(mut self, db_url: String) -> Self {
        self.options.storage.database_url = db_url;
        self
    }

    pub async fn run(self) -> Harness {
        Harness::run(self.options).await
    }
}
