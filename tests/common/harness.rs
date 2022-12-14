use crate::common::{
    mock_auth_service,
    mock_auth_service::{AuthState, EthUser, GhUser, TestUser},
};
use chrono::{DateTime, FixedOffset};
use clap::Parser;
use ethers_signers::LocalWallet;
use kzg_ceremony_crypto::BatchTranscript;
use kzg_ceremony_sequencer::{io::read_json_file, start_server, Options};
use rand::thread_rng;
use std::{path::PathBuf, time::Duration};
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
    pub options:          Options,
    pub auth_state:       AuthState,
    app_shutdown_sender:  broadcast::Sender<()>,
    auth_shutdown_sender: broadcast::Sender<()>,
    /// Needed to keep the lock on the server port for the duration of a test.
    #[allow(dead_code)]
    lock:                 MutexGuard<'static, ()>,
    /// Needed to keep the temp directory alive throughout the test.
    #[allow(dead_code)]
    temp_dir:             TempDir,
    app_handle:           Option<tokio::task::JoinHandle<()>>,
    auth_handle:          Option<tokio::task::JoinHandle<()>>,
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

    pub async fn create_gh_user_with_time(&self, name: String, created_at: String) -> TestUser {
        self.auth_state
            .register_gh_user(GhUser { created_at, name })
            .await
    }

    pub async fn create_eth_user(&self) -> TestUser {
        let wallet = LocalWallet::new(&mut thread_rng());
        let nonce = 42;
        self.auth_state
            .register_eth_user(EthUser { wallet, nonce })
            .await
    }

    pub async fn create_eth_user_with_nonce(&self, nonce: usize) -> TestUser {
        let wallet = LocalWallet::new(&mut thread_rng());
        self.auth_state
            .register_eth_user(EthUser { wallet, nonce })
            .await
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
        self.app_shutdown_sender.send(()).unwrap();
        self.auth_shutdown_sender.send(()).unwrap();
    }
}

impl Harness {
    pub async fn stop(&mut self) {
        self.app_shutdown_sender.send(()).unwrap();
        self.auth_shutdown_sender.send(()).unwrap();

        if let Some(handle) = self.app_handle.take() {
            handle.await.unwrap();
        }

        if let Some(handle) = self.auth_handle.take() {
            handle.await.unwrap();
        }
    }

    pub async fn start(&mut self) {
        assert!(self.app_handle.is_none());
        assert!(self.auth_handle.is_none());
        self.start_app().await;
        self.start_auth().await;
    }

    async fn start_app(&mut self) {
        let options = self.options.clone();
        let mut app_shutdown_receiver = self.app_shutdown_sender.subscribe();
        let (app_start_sender, app_start_receiver) = oneshot::channel::<()>();
        let app_handle = tokio::spawn(async move {
            let server = start_server(options).await.unwrap();
            app_start_sender.send(()).unwrap();
            server
                .with_graceful_shutdown(async move { app_shutdown_receiver.recv().await.unwrap() })
                .await
                .unwrap();
        });
        app_start_receiver.await.unwrap();
        self.app_handle = Some(app_handle);
    }

    async fn start_auth(&mut self) {
        let (auth_start_sender, auth_start_receiver) = oneshot::channel::<()>();
        let mut auth_shutdown_receiver = self.auth_shutdown_sender.subscribe();
        let auth_state = self.auth_state.clone();
        let auth_handle = tokio::spawn(async move {
            let server = mock_auth_service::start_server(auth_state);
            auth_start_sender.send(()).unwrap();
            server
                .with_graceful_shutdown(async move { auth_shutdown_receiver.recv().await.unwrap() })
                .await
                .unwrap();
        });
        auth_start_receiver.await.unwrap();
        self.auth_handle = Some(auth_handle);
    }

    pub async fn run(mut options: Options) -> Harness {
        let lock = server_lock().await.lock().await;
        let temp_dir = tempdir().unwrap();
        let transcript = temp_dir.path().join("transcript.json");
        let transcript_wip = temp_dir.path().join("transcript.json.next");
        options.transcript_file = transcript;
        options.transcript_in_progress_file = transcript_wip;
        let (app_shutdown_sender, _) = broadcast::channel::<()>(1);
        let (auth_shutdown_sender, _) = broadcast::channel::<()>(1);
        let auth_state = AuthState::default();
        let mut harness = Harness {
            options: options.clone(),
            auth_state,
            app_shutdown_sender,
            auth_shutdown_sender,
            lock,
            temp_dir,
            app_handle: None,
            auth_handle: None,
        };
        harness.start_app().await;
        harness.start_auth().await;
        harness
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

    pub fn set_max_sessions_count(mut self, size: usize) -> Self {
        self.options.lobby.max_sessions_count = size;
        self
    }

    pub fn set_gh_max_account_creation_time(mut self, time: DateTime<FixedOffset>) -> Self {
        self.options.github.gh_max_account_creation_time = time;
        self
    }

    pub fn set_eth_min_nonce(mut self, min_nonce: u64) -> Self {
        self.options.ethereum.eth_min_nonce = min_nonce;
        self
    }

    #[allow(dead_code)]
    pub fn set_transcript_file(mut self, path: PathBuf) -> Self {
        self.options.transcript_file = path;
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
