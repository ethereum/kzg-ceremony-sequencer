use crate::{
    constants::MAX_LOBBY_SIZE,
    jwt::{errors::JwtError, IdToken},
    SessionId, SessionInfo, SharedState,
};
use axum::{extract::Query, response::IntoResponse, Extension, Json};
use http::StatusCode;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Instant;

// These are the providers that are supported
// via oauth
pub enum Providers {
    Google,
    Github,
    Ethereum,
}

impl Providers {
    pub fn to_string(&self) -> &str {
        match self {
            Providers::Google => "Google",
            Providers::Github => "Github",
            Providers::Ethereum => "Ethereum",
        }
    }
    pub fn from_auth0_sub(sub: &String) -> Option<Self> {
        if sub.contains("google") {
            return Some(Providers::Google);
        } else if sub.contains("github") {
            return Some(Providers::Github);
        } else if sub.contains("siwe") {
            return Some(Providers::Ethereum);
        } else {
            return None;
        }
    }
}

pub(crate) enum AuthResponse {
    AuthUrl(String),
    LobbyIsFull,
    UserAlreadyContributed,
    InvalidCsrf,
    Jwt(JwtError),
    UnknownIdProvider,
    InvalidAuthCode,
    FetchUserDataError,
    CouldNotExtractUserData,
    UserVerified {
        id_token: String,
        session_id: String,
    },
}

impl IntoResponse for AuthResponse {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match self {
            AuthResponse::AuthUrl(url) => {
                let body = Json(json!({
                    "auth_url": url.to_string(),
                }));
                (StatusCode::OK, body)
            }
            AuthResponse::InvalidAuthCode => {
                let body = Json(json!({
                    "error": "invalid authorisation code",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            AuthResponse::FetchUserDataError => {
                let body = Json(json!({
                    "error": "could not fetch user data from auth server",
                }));
                (StatusCode::INTERNAL_SERVER_ERROR, body)
            }
            AuthResponse::CouldNotExtractUserData => {
                let body = Json(json!({
                    "error": "could not extract user data from auth server response",
                }));
                (StatusCode::INTERNAL_SERVER_ERROR, body)
            }
            AuthResponse::UnknownIdProvider => {
                let body = Json(json!({
                    "error": "unknown identity provider",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            AuthResponse::Jwt(jwt_err) => return jwt_err.into_response(),
            AuthResponse::UserVerified {
                id_token,
                session_id,
            } => {
                return Json(json!({
                    "id_token" : id_token,
                    "session_id" : session_id,
                }))
                .into_response()
            }
            AuthResponse::LobbyIsFull => {
                let body = Json(json!({
                    "error": "lobby is full",
                }));
                (StatusCode::SERVICE_UNAVAILABLE, body)
            }
            AuthResponse::InvalidCsrf => {
                let body = Json(json!({
                    "error": "invalid csrf token",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            AuthResponse::UserAlreadyContributed => {
                let body = Json(json!({ "error": "user has already contributed" }));
                (StatusCode::BAD_REQUEST, body)
            }
        };
        (status, body).into_response()
    }
}

// Returns the url that the user needs to call
// in order to get an authorisation code
pub(crate) async fn auth_client_string(
    Extension(client): Extension<BasicClient>,
    Extension(store): Extension<SharedState>,
) -> AuthResponse {
    // Fist check if the lobby is full before giving users an auth link
    // Note: we use CSRF tokens, so just copying the url will not work either
    //
    {
        let lobby_size = store.read().await.lobby.len();
        if lobby_size >= MAX_LOBBY_SIZE {
            return AuthResponse::LobbyIsFull;
        }
    }

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    // Store CSRF token
    store
        .write()
        .await
        .csrf_tokens
        .insert(csrf_token.secret().to_owned());

    AuthResponse::AuthUrl(auth_url.to_string())
}

// This is the payload that the client will send
// to the coordinator, that will be used to generate a JWT token.
// Since we are using oAUTH, this will contain the information
// that we need to check that the user did indeed login with
// an identity provider
#[derive(Debug, Deserialize)]
pub(crate) struct AuthPayload {
    code: String,
    state: String,
}

// We are using Auth0 as the service layer
// for identity providers. They create a user
// profile that homogenises each identity provider
#[derive(Debug, Serialize, Deserialize)]
struct Auth0User {
    // Unique string identifying each user
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
pub(crate) async fn authorised(
    // TODO: switch to POST request
    Query(payload): Query<AuthPayload>,
    Extension(store): Extension<SharedState>,
    Extension(oauth_client): Extension<BasicClient>,
) -> AuthResponse {
    // N.B. Its possible that the client gets an error during oAUTH
    // It is their responsibility to ensure that this is checked

    // Check CSRF
    {
        let app_state = store.read().await;
        if !app_state.csrf_tokens.contains(&payload.state) {
            return AuthResponse::InvalidCsrf;
        }
    }

    // Swap authorization code for access token
    let token = match oauth_client
        .exchange_code(AuthorizationCode::new(payload.code.clone()))
        .request_async(async_http_client)
        .await
    {
        Ok(token) => token,
        Err(_) => return AuthResponse::InvalidAuthCode,
    };

    // Fetch user data from oauth provider
    let client = reqwest::Client::new();
    let response = match client
        .get("https://kev-kzg-ceremony.eu.auth0.com/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return AuthResponse::FetchUserDataError,
    };

    let user_data: Auth0User = match response.json::<Auth0User>().await {
        Ok(user_data) => user_data,
        Err(_) => return AuthResponse::CouldNotExtractUserData,
    };

    // Check if they have already contributed
    {
        let app_state = store.read().await;
        // Check if they've already contributed
        if let Some(_) = app_state.finished_contribution.get(&user_data.sub) {
            return AuthResponse::UserAlreadyContributed;
        }
    }

    let mut app_state = store.write().await;

    // Check if this user is already in the lobby
    // If so, we send them back their session id
    let session_id = if let Some(session_id) = app_state.unique_id_session.get(&user_data.sub) {
        session_id.clone()
    } else {
        SessionId::new()
    };

    let provider = match Providers::from_auth0_sub(&user_data.sub) {
        Some(provider) => provider,
        None => return AuthResponse::UnknownIdProvider,
    };

    let nickname = match user_data.nickname {
        Some(oauth_nickname) => oauth_nickname,
        None => String::from("Unknown"),
    };

    let id_token = IdToken {
        sub: user_data.sub,
        provider: provider.to_string().to_owned(),
        nickname,
        exp: u64::MAX,
    };
    let id_token_encoded = match id_token.encode() {
        Ok(encoded) => encoded,
        Err(err) => return AuthResponse::Jwt(err),
    };

    app_state.lobby.insert(
        session_id.clone(),
        SessionInfo {
            token: id_token,
            last_ping_time: Instant::now(),
        },
    );

    return AuthResponse::UserVerified {
        id_token: id_token_encoded,
        session_id: session_id.to_string(),
    };
}
