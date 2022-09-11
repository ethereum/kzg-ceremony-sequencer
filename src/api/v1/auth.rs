use crate::{
    constants::MAX_LOBBY_SIZE,
    jwt::{errors::JwtError, IdToken},
    AppConfig, GithubOAuthClient, SessionId, SessionInfo, SharedState,
};
use axum::response::Response;
use axum::{extract::Query, response::IntoResponse, Extension, Json};
use chrono::DateTime;
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
pub enum AuthProvider {
    Github,
    Ethereum,
}

impl AuthProvider {
    pub fn to_string(&self) -> &str {
        match self {
            AuthProvider::Github => "Github",
            AuthProvider::Ethereum => "Ethereum",
        }
    }
}

pub(crate) enum AuthError {
    LobbyIsFull,
    UserAlreadyContributed,
    InvalidCsrf,
    Jwt(JwtError),
    UnknownIdProvider,
    InvalidAuthCode,
    FetchUserDataError,
    CouldNotExtractUserData,
    UserCreatedAfterDeadline,
}

pub(crate) struct UserVerified {
    id_token: String,
    session_id: String,
}

pub(crate) struct AuthUrl {
    auth_url: String,
    github_auth_url: String,
}

impl IntoResponse for AuthUrl {
    fn into_response(self) -> Response {
        Json(json!({
            "auth_url": self.auth_url.to_string(),
            "github_auth_url": self.github_auth_url.to_string(),
        }))
        .into_response()
    }
}

impl IntoResponse for UserVerified {
    fn into_response(self) -> Response {
        Json(json!({
            "id_token" : self.id_token,
            "session_id" : self.session_id,
        }))
        .into_response()
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match self {
            AuthError::InvalidAuthCode => {
                let body = Json(json!({
                    "error": "invalid authorisation code",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            AuthError::FetchUserDataError => {
                let body = Json(json!({
                    "error": "could not fetch user data from auth server",
                }));
                (StatusCode::INTERNAL_SERVER_ERROR, body)
            }
            AuthError::CouldNotExtractUserData => {
                let body = Json(json!({
                    "error": "could not extract user data from auth server response",
                }));
                (StatusCode::INTERNAL_SERVER_ERROR, body)
            }
            AuthError::UnknownIdProvider => {
                let body = Json(json!({
                    "error": "unknown identity provider",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            AuthError::Jwt(jwt_err) => return jwt_err.into_response(),

            AuthError::LobbyIsFull => {
                let body = Json(json!({
                    "error": "lobby is full",
                }));
                (StatusCode::SERVICE_UNAVAILABLE, body)
            }
            AuthError::InvalidCsrf => {
                let body = Json(json!({
                    "error": "invalid csrf token",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            AuthError::UserAlreadyContributed => {
                let body = Json(json!({ "error": "user has already contributed" }));
                (StatusCode::BAD_REQUEST, body)
            }
            AuthError::UserCreatedAfterDeadline => {
                let body = Json(json!({ "error": "user account was created after the deadline"}));
                (StatusCode::UNAUTHORIZED, body)
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
    Extension(gh_client): Extension<GithubOAuthClient>,
) -> Result<AuthUrl, AuthError> {
    // Fist check if the lobby is full before giving users an auth link
    // Note: we use CSRF tokens, so just copying the url will not work either
    //
    {
        let lobby_size = store.read().await.lobby.len();
        if lobby_size >= MAX_LOBBY_SIZE {
            return Err(AuthError::LobbyIsFull);
        }
    }

    let csrf_token = CsrfToken::new_random();

    let (auth_url, csrf_token) = client
        .authorize_url(|| csrf_token)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    let (gh_url, csrf_token) = gh_client
        .client
        .authorize_url(|| csrf_token)
        .add_scope(Scope::new("email".to_string()))
        .url();

    // Store CSRF token
    // TODO[MK] These should be cleaned periodically
    store
        .write()
        .await
        .csrf_tokens
        .insert(csrf_token.secret().to_owned());

    Ok(AuthUrl {
        auth_url: auth_url.to_string(),
        github_auth_url: gh_url.to_string(),
    })
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

#[derive(Debug, Serialize, Deserialize)]
struct AuthenticatedUser {
    uid: String,
    nickname: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhUserInfo {
    login: String,
    created_at: String,
}

pub(crate) async fn github_callback(
    Query(payload): Query<AuthPayload>,
    Extension(config): Extension<AppConfig>,
    Extension(store): Extension<SharedState>,
    Extension(gh_oauth_client): Extension<GithubOAuthClient>,
) -> Result<UserVerified, AuthError> {
    verify_csrf(&payload, &store).await?;
    let token = gh_oauth_client
        .exchange_code(AuthorizationCode::new(payload.code))
        .request_async(async_http_client)
        .await
        .map_err(|_| AuthError::InvalidAuthCode)?;

    let client = reqwest::Client::new();
    let response = client
        .get("https://api.github.com/user")
        .bearer_auth(token.access_token().secret())
        .header("User-Agent", "ethereum-kzg-ceremony-sequencer")
        .send()
        .await
        .map_err(|_| AuthError::FetchUserDataError)?;
    let gh_user_info = response
        .json::<GhUserInfo>()
        .await
        .map_err(|_| AuthError::CouldNotExtractUserData)?;
    let creation_time = DateTime::parse_from_rfc3339(&gh_user_info.created_at)
        .map_err(|_| AuthError::CouldNotExtractUserData)?;
    if creation_time > config.github_max_creation_time {
        return Err(AuthError::UserCreatedAfterDeadline);
    }
    let user = AuthenticatedUser {
        uid: format!("gh::{}", gh_user_info.login),
        nickname: Some(gh_user_info.login),
    };
    post_authenticate(store, user, AuthProvider::Github).await
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
) -> Result<UserVerified, AuthError> {
    // N.B. Its possible that the client gets an error during oAUTH
    // It is their responsibility to ensure that this is checked
    //
    verify_csrf(&payload, &store).await?;

    // Swap authorization code for access token
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(payload.code.clone()))
        .request_async(async_http_client)
        .await
        .map_err(|_| AuthError::InvalidAuthCode)?;

    // Fetch user data from oauth provider
    let client = reqwest::Client::new();
    let response = client
        .get("https://kev-kzg-ceremony.eu.auth0.com/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|_| AuthError::FetchUserDataError)?;

    let user_data: AuthenticatedUser = response
        .json::<AuthenticatedUser>()
        .await
        .map_err(|_| AuthError::CouldNotExtractUserData)?;

    post_authenticate(store, user_data, AuthProvider::Ethereum).await
}

async fn verify_csrf(payload: &AuthPayload, store: &SharedState) -> Result<(), AuthError> {
    let app_state = store.read().await;
    if !app_state.csrf_tokens.contains(&payload.state) {
        Err(AuthError::InvalidCsrf)
    } else {
        Ok(())
    }
}

async fn post_authenticate(
    store: SharedState,
    user_data: AuthenticatedUser,
    auth_provider: AuthProvider,
) -> Result<UserVerified, AuthError> {
    // Check if they have already contributed
    {
        let app_state = store.read().await;
        // Check if they've already contributed
        if let Some(_) = app_state.finished_contribution.get(&user_data.uid) {
            return Err(AuthError::UserAlreadyContributed);
        }
    }

    let mut app_state = store.write().await;

    // Check if this user is already in the lobby
    // If so, we send them back their session id
    let session_id = if let Some(session_id) = app_state.unique_id_session.get(&user_data.uid) {
        session_id.clone()
    } else {
        SessionId::new()
    };

    let nickname = match user_data.nickname {
        Some(oauth_nickname) => oauth_nickname,
        None => String::from("Unknown"),
    };

    let id_token = IdToken {
        sub: user_data.uid,
        provider: auth_provider.to_string().to_owned(),
        nickname,
        exp: u64::MAX,
    };

    let id_token_encoded = id_token.encode().map_err(AuthError::Jwt)?;

    app_state.lobby.insert(
        session_id.clone(),
        SessionInfo {
            token: id_token,
            last_ping_time: Instant::now(),
        },
    );

    Ok(UserVerified {
        id_token: id_token_encoded,
        session_id: session_id.to_string(),
    })
}
