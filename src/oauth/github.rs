use crate::util::Secret;
use chrono::{DateTime, FixedOffset};
use clap::Parser;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use std::ops::Deref;

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
