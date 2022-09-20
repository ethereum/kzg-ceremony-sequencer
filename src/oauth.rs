use chrono::{DateTime, FixedOffset};
use clap::Parser;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::ParseIntError,
    ops::Deref,
    sync::Arc,
};
use tokio::sync::RwLock;

use crate::{sessions::SessionId, util::Secret};

#[derive(Default)]
pub struct AuthState {
    // CSRF tokens for oAUTH
    pub csrf_tokens: BTreeSet<CsrfToken>,

    // A map between a users unique social id
    // and their session.
    // We use this to check if a user has already entered the lobby
    pub unique_id_session: BTreeMap<IdTokenSub, SessionId>,
}

pub type SharedAuthState = Arc<RwLock<AuthState>>;

fn dec_to_hex(input: &str) -> Result<String, ParseIntError> {
    Ok(format!("0x{:x}", input.parse::<u64>()?))
}

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct EthAuthOptions {
    #[clap(
        long = "eth-nonce-verification-block",
        env = "ETH_NONCE_VERIFICATION_BLOCK",
        name = "ETH_NONCE_VERIFICATION_BLOCK",
        value_parser = dec_to_hex,
        default_value = "15565180",
    )]
    pub eth_nonce_verification_block: String,

    #[clap(
        long = "eth-min-nonce",
        env = "ETH_MIN_NONCE",
        name = "ETH_MIN_NONCE",
        default_value = "4"
    )]
    pub min_nonce: u64,

    #[clap(long = "eth-rpc-url", env = "ETH_RPC_URL", name = "ETH_RPC_URL")]
    pub rpc_url: Secret,

    #[clap(
        long = "eth-client-secret",
        env = "ETH_CLIENT_SECRET",
        name = "ETH_CLIENT_SECRET"
    )]
    pub client_secret: Secret,

    #[clap(long = "eth-client-id", env = "ETH_CLIENT_ID", name = "ETH_CLIENT_ID")]
    pub client_id: Secret,

    #[clap(
        long = "eth-redirect-url",
        env = "ETH_REDIRECT_URL",
        name = "ETH_REDIRECT_URL",
        default_value = "http://127.0.0.1:3000/auth/callback/github"
    )]
    pub redirect_url: String,

    #[clap(
        long = "eth-auth-url",
        env = "ETH_AUTH_URL",
        name = "ETH_AUTH_URL",
        default_value = "https://github.com/login/oauth/authorize"
    )]
    pub auth_url: String,

    #[clap(
        long = "eth-token-url",
        env = "ETH_TOKEN_URL",
        name = "ETH_TOKEN_URL",
        default_value = "https://github.com/login/oauth/access_token"
    )]
    pub token_url: String,
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

pub fn siwe_oauth_client(options: &EthAuthOptions) -> SiweOAuthClient {
    SiweOAuthClient {
        client: BasicClient::new(
            ClientId::new(options.client_id.get_secret().to_owned()),
            Some(ClientSecret::new(
                options.client_secret.get_secret().to_owned(),
            )),
            AuthUrl::new(options.auth_url.clone()).unwrap(),
            Some(TokenUrl::new(options.token_url.clone()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(options.token_url.clone()).unwrap()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct GithubAuthOptions {
    #[clap(
        long = "github-max-account-creation-time",
        env = "GITHUB_MAX_ACCOUNT_CREATION_TIME",
        name = "GITHUB_MAX_ACCOUNT_CREATION_TIME",
        default_value = "2022-08-01T00:00:00Z"
    )]
    pub max_account_creation_time: DateTime<FixedOffset>,

    #[clap(
        long = "github-client-secret",
        env = "GITHUB_CLIENT_SECRET",
        name = "GITHUB_CLIENT_SECRET"
    )]
    pub client_secret: Secret,

    #[clap(
        long = "github-client-id",
        env = "GITHUB_CLIENT_ID",
        name = "GITHUB_CLIENT_ID"
    )]
    pub client_id: Secret,

    #[clap(
        long = "github-redirect-url",
        env = "GITHUB_REDIRECT_URL",
        name = "GITHUB_REDIRECT_URL",
        default_value = "http://127.0.0.1:3000/auth/callback/github"
    )]
    pub redirect_url: String,

    #[clap(
        long = "github-auth-url",
        env = "GITHUB_AUTH_URL",
        name = "GITHUB_AUTH_URL",
        default_value = "https://github.com/login/oauth/authorize"
    )]
    pub auth_url: String,

    #[clap(
        long = "github-token-url",
        env = "GITHUB_TOKEN_URL",
        name = "GITHUB_TOKEN_URL",
        default_value = "https://github.com/login/oauth/access_token"
    )]
    pub token_url: String,
}

#[derive(Clone)]
pub struct GithubOAuthClient {
    pub client: BasicClient,
}

impl Deref for GithubOAuthClient {
    type Target = BasicClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

pub fn github_oauth_client(options: &GithubAuthOptions) -> GithubOAuthClient {
    GithubOAuthClient {
        client: BasicClient::new(
            ClientId::new(options.client_id.get_secret().to_owned()),
            Some(ClientSecret::new(
                options.client_secret.get_secret().to_owned(),
            )),
            AuthUrl::new(options.auth_url.clone()).unwrap(),
            Some(TokenUrl::new(options.token_url.clone()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(options.redirect_url.clone()).unwrap()),
    }
}

pub type IdTokenSub = String;
pub type CsrfToken = String;
