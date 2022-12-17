use crate::util::Secret;
use clap::Parser;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use std::{num::ParseIntError, ops::Deref};

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

    /// Sign-in-with-Ethereum OAuth2 authorization url.
    #[clap(
        long,
        env,
        default_value = "https://oidc.signinwithethereum.org/authorize"
    )]
    pub eth_auth_url: String,

    /// Sign-in-with-Ethereum OAuth2 token url.
    #[clap(long, env, default_value = "https://oidc.signinwithethereum.org/token")]
    pub eth_token_url: String,

    /// Sign-in-with-Ethereum OAuth2 user info url.
    #[clap(
        long,
        env,
        default_value = "https://oidc.signinwithethereum.org/userinfo"
    )]
    pub eth_userinfo_url: String,

    /// Sign-in-with-Ethereum OAuth2 callback redirect url.
    #[clap(long, env, default_value = "http://127.0.0.1:3000/auth/callback/eth")]
    pub eth_redirect_url: String,

    /// Sign-in-with-Ethereum OAuth2 client access id.
    #[clap(long, env)]
    pub eth_client_id: Secret,

    /// Sign-in-with-Ethereum OAuth2 client access key.
    #[clap(long, env)]
    pub eth_client_secret: Secret,
}

#[derive(Clone)]
pub struct EthOAuthClient {
    client: BasicClient,
}

impl Deref for EthOAuthClient {
    type Target = BasicClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

pub fn eth_oauth_client(options: &EthAuthOptions) -> EthOAuthClient {
    EthOAuthClient {
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

fn dec_to_hex(input: &str) -> Result<String, ParseIntError> {
    Ok(format!("0x{:x}", input.parse::<u64>()?))
}
