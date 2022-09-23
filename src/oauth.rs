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
    /// The block height where the users nonce is fetched from.
    #[clap(long, env, value_parser = dec_to_hex, default_value = "15565180")]
    pub eth_nonce_verification_block: String,

    /// The minimum nonce required at the specified block height in order to
    /// participate.
    #[clap(long, env, default_value = "4")]
    pub eth_min_nonce: u64,

    /// The Ethereum JSON-RPC endpoint to use.
    /// Defaults to the AllThatNode public node for testing.
    #[clap(
        long,
        env,
        default_value = "https://ethereum-mainnet-rpc.allthatnode.com"
    )]
    pub eth_rpc_url: Secret,

    //// Sign-in-with-Ethereum OAuth2 authorization url.
    #[clap(
        long,
        env,
        default_value = "https://oidc.signinwithethereum.org/authorize"
    )]
    pub eth_auth_url: String,

    //// Sign-in-with-Ethereum OAuth2 token url.
    #[clap(long, env, default_value = "https://oidc.signinwithethereum.org/token")]
    pub eth_token_url: String,

    //// Sign-in-with-Ethereum OAuth2 user info url.
    #[clap(
        long,
        env,
        default_value = "https://oidc.signinwithethereum.org/userinfo"
    )]
    pub eth_userinfo_url: String,

    //// Sign-in-with-Ethereum OAuth2 callback redirect url.
    #[clap(long, env, default_value = "http://127.0.0.1:3000/auth/callback/siwe")]
    pub eth_redirect_url: String,

    //// Sign-in-with-Ethereum OAuth2 client access id.
    #[clap(long, env)]
    pub eth_client_id: Secret,

    //// Sign-in-with-Ethereum OAuth2 client access key.
    #[clap(long, env)]
    pub eth_client_secret: Secret,
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
            ClientId::new(options.eth_client_id.get_secret().to_owned()),
            Some(ClientSecret::new(
                options.eth_client_secret.get_secret().to_owned(),
            )),
            AuthUrl::new(options.eth_auth_url.clone()).unwrap(),
            Some(TokenUrl::new(options.eth_token_url.clone()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(options.eth_redirect_url.clone()).unwrap()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Parser)]
pub struct GithubAuthOptions {
    /// The latest date a Github account can have been created in order to
    /// participate.
    #[clap(long, env, default_value = "2022-08-01T00:00:00Z")]
    pub gh_max_account_creation_time: DateTime<FixedOffset>,

    /// Github OAuth2 authorization url.
    #[clap(long, env, default_value = "https://github.com/login/oauth/authorize")]
    pub gh_auth_url: String,

    /// Github OAuth2 token url.
    #[clap(
        long,
        env,
        default_value = "https://github.com/login/oauth/access_token"
    )]
    pub gh_token_url: String,

    /// Github OAuth2 user info url.
    #[clap(long, env, default_value = "https://api.github.com/user")]
    pub gh_userinfo_url: String,

    /// Github OAuth2 callback redirect url.
    #[clap(
        long,
        env,
        default_value = "http://127.0.0.1:3000/auth/callback/github"
    )]
    pub gh_redirect_url: String,

    /// Github OAuth2 client access id.
    #[clap(long, env)]
    pub gh_client_id: Secret,

    /// Github OAuth2 client access key.
    #[clap(long, env)]
    pub gh_client_secret: Secret,
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
            ClientId::new(options.gh_client_id.get_secret().to_owned()),
            Some(ClientSecret::new(
                options.gh_client_secret.get_secret().to_owned(),
            )),
            AuthUrl::new(options.gh_auth_url.clone()).unwrap(),
            Some(TokenUrl::new(options.gh_token_url.clone()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(options.gh_redirect_url.clone()).unwrap()),
    }
}

pub type IdTokenSub = String;
pub type CsrfToken = String;
