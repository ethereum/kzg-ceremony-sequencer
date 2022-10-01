mod ethereum;
mod github;

use crate::sessions::SessionId;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::RwLock;

pub use self::{
    ethereum::{eth_oauth_client, EthAuthOptions, EthOAuthClient},
    github::{github_oauth_client, GithubAuthOptions, GithubOAuthClient},
};

pub type SharedAuthState = Arc<RwLock<AuthState>>;
pub type IdTokenSub = String;

#[derive(Default)]
pub struct AuthState {
    // A map between a users unique social id
    // and their session.
    // We use this to check if a user has already entered the lobby
    pub unique_id_session: BTreeMap<IdTokenSub, SessionId>,
}
