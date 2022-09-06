use crate::{
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
    Twitter,
    Ethereum,
}

impl Providers {
    pub fn auth0_string(&self) -> &str {
        match self {
            Providers::Google => "google-oauth2",
            Providers::Github => "github",
            Providers::Twitter => "twitter",
            Providers::Ethereum => "siwe",
        }
    }
    pub fn to_string(&self) -> &str {
        match self {
            Providers::Google => "Google",
            Providers::Github => "Github",
            Providers::Twitter => "Twitter",
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
    Jwt(JwtError),
    UnknownIdProvider,
    InvalidAuthCode,
    FetchUserDataError,
    CouldNotExtractUserData,
    UserVerified(AuthBody),
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
                (StatusCode::BAD_REQUEST, body)
            }
            AuthResponse::CouldNotExtractUserData => {
                let body = Json(json!({
                    "error": "could not extract user data from auth server response",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            AuthResponse::UnknownIdProvider => {
                let body = Json(json!({
                    "error": "unknown identity provider",
                }));
                (StatusCode::BAD_REQUEST, body)
            }
            AuthResponse::Jwt(jwt_err) => return jwt_err.into_response(),
            AuthResponse::UserVerified(body) => return Json(body).into_response(),
        };
        (status, body).into_response()
    }
}

// Returns the url that the user needs to call
// in order to get an authorisation code
pub(crate) async fn auth_client_string(Extension(client): Extension<BasicClient>) -> AuthResponse {
    // csrf token is not being check!
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

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
pub(crate) async fn authorized(
    // TODO: switch to POST request
    Query(payload): Query<AuthPayload>,
    Extension(store): Extension<SharedState>,
    Extension(oauth_client): Extension<BasicClient>,
) -> AuthResponse {
    // N.B. Its possible that the client gets an error during oAUTH
    // It is their responsibility to ensure that this is checked

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

    let mut app_state = store.write().await;

    // TODO: we can probably get this from the authorisation server
    // TODO: than using regex
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
        exp: 200000000000,
    };
    let id_token_encoded = match id_token.encode() {
        Ok(encoded) => encoded,
        Err(err) => return AuthResponse::Jwt(err),
    };

    let session_id = SessionId::new();
    app_state.sessions.insert(
        session_id.clone(),
        SessionInfo {
            token: id_token,
            last_ping_time: Instant::now(),
        },
    );

    return AuthResponse::UserVerified(AuthBody::new(id_token_encoded, session_id));
}

// This is the information that the coordinator sends to the client
#[derive(Debug, Serialize)]
pub(crate) struct AuthBody {
    // ID token that gives a client access to some of the coordinators API
    // Some endpoints do not require an id token
    // For example; "NumPeopleInQueue"
    id_token: String,

    session_id: String,

    token_type: String,
    // TODO: do this when we switch away from HMAC JWT
    // jwt_decode_key: String,
}

impl AuthBody {
    pub fn new(id_token: String, session_id: SessionId) -> Self {
        Self {
            id_token,
            session_id: session_id.to_string(),
            token_type: "Bearer".to_string(),
        }
    }
}
