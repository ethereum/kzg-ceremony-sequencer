pub mod errors;
pub mod tokens;

use std::time::Instant;

use axum::{extract::Query, response::IntoResponse, Extension, Json};
use http::StatusCode;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{api::v2::auth::tokens::IdToken, auth::AuthBody, SessionId, SessionInfo, SharedState};

use self::errors::AuthError;

pub enum Providers {
    Google,
    Github,
    Twitter,
    Ethereum,
    Unknown(String),
}

impl Providers {
    pub fn auth0_string(&self) -> &str {
        match self {
            Providers::Google => "google-oauth2",
            Providers::Github => "github",
            Providers::Twitter => "twitter",
            Providers::Ethereum => "siwe",
            Providers::Unknown(_) => unreachable!("auth0 providers need to be known"),
        }
    }
    pub fn to_string(&self) -> &str {
        match self {
            Providers::Google => "Google",
            Providers::Github => "Github",
            Providers::Twitter => "Twitter",
            Providers::Ethereum => "Ethereum",
            Providers::Unknown(sub) => &sub,
        }
    }
    pub fn from_auth0_sub(sub: &String) -> Self {
        if sub.contains("google") {
            return Providers::Google;
        } else if sub.contains("github") {
            return Providers::Github;
        } else if sub.contains("siwe") {
            return Providers::Ethereum;
        } else {
            return Providers::Unknown(sub.to_owned());
        }
    }
}

// Returns the url that the user needs to call in order to get an auth code
pub async fn auth_client_string(Extension(client): Extension<BasicClient>) -> impl IntoResponse {
    // csrf token is not being check!
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    println!("auth url: {}", auth_url.to_string());

    Json(json!({
        "auth_url": auth_url.to_string(),
    }))
}

// This is the payload that the client will send
// to the coordinator, that wll be used to generate a JWT token
// Since we are using oAUTH, this will contain the information
// that we need to check that the user did indeed login with
// an identity provider
#[derive(Debug, Deserialize)]
pub(crate) struct AuthPayload {
    code: String,
    state: String,
}

// Auth0 user
#[derive(Debug, Serialize, Deserialize)]
struct Auth0User {
    sub: String,
    nickname: Option<String>,
}

// This endpoint allows one to consume an oAUTH authorisation code
//  and produce a JWT token
// So Coordinator could give out fake identities, we are trusting the coordinator
// to not do that.
//
// Now this is catchable by the client. They will clearly see that the coordinator
// was malicious. What can happen is coordinator can claim that someone
// participated when they did not. Is this Okay? Maybe that person can then just say
// they did not
pub(crate) async fn authorized(
    // TODO: use this when we switch to POST request
    // Json(payload): Json<AuthPayload>,
    Query(payload): Query<AuthPayload>,
    // TODO: we do not need this middleware, can we remove it
    // TODO or do all functions need to be homogenous?
    Extension(store): Extension<SharedState>,
    Extension(oauth_client): Extension<BasicClient>,
) -> impl IntoResponse {
    // Check if the user sent the credentials
    if payload.code.is_empty() || payload.state.is_empty() {
        return AuthError::MissingCredentials.into_response();
    }
    println!("auth code: {}", payload.code);
    // Swap authorization code for access token
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(payload.code.clone()))
        .request_async(async_http_client)
        .await
        .unwrap();

    println!("{:?}", token);

    // Fetch user data from oauth provider
    let client = reqwest::Client::new();
    let response = client
        .get("https://kev-kzg-ceremony.eu.auth0.com/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .unwrap();

    println!("{:?}", response);

    let user_data: Auth0User = response.json::<Auth0User>().await.unwrap();

    println!("{:?}", user_data);

    let mut app_state = store.write().await;

    let sub_segments: Vec<&str> = user_data.sub.split("|").collect();
    // TODO: we can probably get this from the authorisation server somehow
    let provider = Providers::from_auth0_sub(&user_data.sub);

    let nickname = match user_data.nickname {
        Some(oauth_nickname) => oauth_nickname,
        None => String::from("Unknown"),
    };

    let id_token = IdToken {
        sub: user_data.sub,
        provider: provider.to_string().to_owned(),
        nickname,
        exp: 200000000000,
    };
    let id_token_encoded = match id_token.encode() {
        Ok(encoded) => encoded,
        Err(err) => return err.into_response(),
    };

    let session_id = SessionId::new();
    app_state.sessions.insert(
        session_id.clone(),
        SessionInfo {
            token: id_token,
            last_ping_time: Instant::now(),
        },
    );
    // Create the id token
    Json(AuthBody::new(id_token_encoded, session_id)).into_response()
}
