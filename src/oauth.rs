use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ops::Deref,
    sync::Arc,
};
use tokio::sync::RwLock;

use crate::{
    constants::{
        GITHUB_OAUTH_AUTH_URL, GITHUB_OAUTH_REDIRECT_URL, GITHUB_OAUTH_TOKEN_URL,
        SIWE_OAUTH_AUTH_URL, SIWE_OAUTH_REDIRECT_URL, SIWE_OAUTH_TOKEN_URL,
    },
    sessions::SessionId,
};

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

pub fn siwe_oauth_client() -> SiweOAuthClient {
    let client_id = env::var("SIWE_CLIENT_ID").expect("Missing SIWE_CLIENT_ID!");
    let client_secret = env::var("SIWE_CLIENT_SECRET").expect("Missing SIWE_CLIENT_SECRET!");

    let redirect_url =
        env::var("SIWE_REDIRECT_URL").unwrap_or_else(|_| SIWE_OAUTH_REDIRECT_URL.to_string());
    let auth_url = env::var("SIWE_AUTH_URL").unwrap_or_else(|_| SIWE_OAUTH_AUTH_URL.to_string());
    let token_url = env::var("SIWE_TOKEN_URL").unwrap_or_else(|_| SIWE_OAUTH_TOKEN_URL.to_string());

    SiweOAuthClient {
        client: BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(auth_url).unwrap(),
            Some(TokenUrl::new(token_url).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap()),
    }
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

pub fn github_oauth_client() -> GithubOAuthClient {
    let client_id = env::var("GITHUB_CLIENT_ID").expect("Missing GITHUB_CLIENT_ID!");
    let client_secret = env::var("GITHUB_CLIENT_SECRET").expect("Missing GITHUB_CLIENT_SECRET!");
    let redirect_url =
        env::var("GITHUB_REDIRECT_URL").unwrap_or_else(|_| GITHUB_OAUTH_REDIRECT_URL.to_string());
    let auth_url =
        env::var("GITHUB_AUTH_URL").unwrap_or_else(|_| GITHUB_OAUTH_AUTH_URL.to_string());
    let token_url =
        env::var("GITHUB_TOKEN_URL").unwrap_or_else(|_| GITHUB_OAUTH_TOKEN_URL.to_string());
    GithubOAuthClient {
        client: BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(auth_url).unwrap(),
            Some(TokenUrl::new(token_url).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap()),
    }
}

pub type IdTokenSub = String;
pub type CsrfToken = String;
