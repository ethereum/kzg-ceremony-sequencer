mod ethereum;
mod github;

use crate::sessions::SessionId;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tokio::sync::RwLock;

pub use self::{
    ethereum::{siwe_oauth_client, EthAuthOptions, SiweOAuthClient},
    github::{github_oauth_client, GithubAuthOptions, GithubOAuthClient},
};

pub type SharedAuthState = Arc<RwLock<AuthState>>;
pub type IdTokenSub = String;
pub type CsrfToken = String;

#[derive(Default)]
pub struct AuthState {
    // CSRF tokens for oAUTH
    pub csrf_tokens: BTreeSet<CsrfToken>,

    // A map between a users unique social id
    // and their session.
    // We use this to check if a user has already entered the lobby
    pub unique_id_session: BTreeMap<IdTokenSub, SessionId>,
}
