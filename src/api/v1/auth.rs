use crate::{
    lobby::SharedLobbyState,
    oauth::{EthOAuthClient, GithubOAuthClient, SharedAuthState},
    sessions::IdToken,
    storage::{PersistentStorage, StorageError},
    EthAuthOptions, Options, SessionId, SessionInfo,
};
use axum::{
    async_trait,
    extract::{FromRequest, Query, RequestParts},
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use chrono::DateTime;
use http::StatusCode;
use kzg_ceremony_crypto::{signature::identity::Identity, ErrorCode};
use oauth2::{
    reqwest::async_http_client, AuthorizationCode, CsrfToken, RequestTokenError, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use strum::IntoStaticStr;
use thiserror::Error;
use tokio::time::Instant;
use tracing::warn;
use url::Url;

#[derive(Debug, Error)]
#[error("{payload}")]
pub struct AuthError {
    pub redirect: Option<String>,
    pub payload:  AuthErrorPayload,
}

#[derive(Debug, Error, IntoStaticStr)]
pub enum AuthErrorPayload {
    #[error("lobby is full")]
    LobbyIsFull,
    #[error("user already contributed")]
    UserAlreadyContributed,
    #[error("invalid authorization code")]
    InvalidAuthCode,
    #[error("could not fetch user data from auth server")]
    FetchUserDataError,
    #[error("could not extract user data from auth server")]
    CouldNotExtractUserData,
    #[error("user created after deadline")]
    UserCreatedAfterDeadline,
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

impl ErrorCode for AuthErrorPayload {
    fn to_error_code(&self) -> String {
        format!("AuthErrorPayload::{}", <&str>::from(self))
    }
}

pub struct UserVerifiedResponse {
    id_token:       IdToken,
    session_id:     String,
    as_redirect_to: Option<String>,
}

pub struct AuthUrl {
    eth_auth_url:    String,
    github_auth_url: String,
}

impl IntoResponse for AuthUrl {
    fn into_response(self) -> Response {
        Json(json!({
            "eth_auth_url": self.eth_auth_url,
            "github_auth_url": self.github_auth_url,
        }))
        .into_response()
    }
}

impl IntoResponse for UserVerifiedResponse {
    fn into_response(self) -> Response {
        // Handling URL parse error by ignoring it and returning without redirect – we
        // have no better option here, since we don't know the frontend that called us.
        let redirect_url = self.as_redirect_to.and_then(|r| Url::parse(&r).ok());
        match redirect_url {
            Some(mut redirect_url) => {
                redirect_url
                    .query_pairs_mut()
                    .append_pair("session_id", &self.session_id)
                    .append_pair("sub", &self.id_token.identity.unique_id())
                    .append_pair("nickname", &self.id_token.identity.nickname())
                    .append_pair("provider", &self.id_token.identity.provider_name())
                    .append_pair("exp", &self.id_token.exp.to_string());
                Redirect::to(redirect_url.as_str()).into_response()
            }
            None => Json(json!({
                "id_token" : {
                    "sub": &self.id_token.identity.unique_id(),
                    "nickname": &self.id_token.identity.nickname(),
                    "provider": &self.id_token.identity.provider_name(),
                    "exp": &self.id_token.exp,
                },
                "session_id" : self.session_id,
            }))
            .into_response(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthClientLinkQueryParams {
    redirect_to: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CsrfWithRedirect {
    redirect: Option<String>,
}

impl CsrfWithRedirect {
    fn encode_into_csrf(&self) -> CsrfToken {
        let value = serde_json::to_string(self).unwrap();
        let bytes = value.as_bytes();
        CsrfToken::new(base64::encode_config(bytes, base64::URL_SAFE_NO_PAD))
    }
}

// Returns the url that the user needs to call
// in order to get an authorisation code
pub async fn auth_client_link(
    Query(params): Query<AuthClientLinkQueryParams>,
    Extension(options): Extension<Options>,
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(eth_client): Extension<EthOAuthClient>,
    Extension(gh_client): Extension<GithubOAuthClient>,
) -> Result<AuthUrl, AuthErrorPayload> {
    let lobby_size = lobby_state.get_lobby_size().await;

    if lobby_size >= options.lobby.max_lobby_size {
        return Err(AuthErrorPayload::LobbyIsFull);
    }

    let csrf_with_redirect = CsrfWithRedirect {
        redirect: params.redirect_to,
    }
    .encode_into_csrf();

    let eth_auth_request = eth_client
        .authorize_url(|| csrf_with_redirect)
        .add_scope(Scope::new("openid".to_string()));

    let (auth_url, csrf_with_redirect) = eth_auth_request.url();

    let gh_auth_request = gh_client.client.authorize_url(|| csrf_with_redirect);

    let (gh_url, _) = gh_auth_request.url();

    Ok(AuthUrl {
        eth_auth_url:    auth_url.to_string(),
        github_auth_url: gh_url.to_string(),
    })
}

// This is the payload that the client will send
// to the sequencer, that will be used to generate a JWT token.
// Since we are using oAUTH, this will contain the information
// that we need to check that the user did indeed login with
// an identity provider
#[derive(Debug, Deserialize)]
pub struct RawAuthPayload {
    code:  String,
    state: String,
}

#[derive(Debug)]
pub struct AuthPayload {
    code:        String,
    redirect_to: Option<String>,
}

#[async_trait]
impl<B> FromRequest<B> for AuthPayload
where
    B: Send,
{
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Query(raw): Query<RawAuthPayload> = Query::from_request(req)
            .await
            .map_err(IntoResponse::into_response)?;
        let decoded_state =
            base64::decode_config(raw.state, base64::URL_SAFE_NO_PAD).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(Value::Object(Map::from_iter([(
                        "message".to_string(),
                        Value::String("invalid base64 data in state parameter".to_string()),
                    )]))),
                )
                    .into_response()
            })?;
        let json_decoded_state =
            serde_json::from_slice::<CsrfWithRedirect>(decoded_state.as_slice()).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(Value::Object(Map::from_iter([(
                        "message".to_string(),
                        Value::String("invalid json in state parameter".to_string()),
                    )]))),
                )
                    .into_response()
            })?;
        Ok(Self {
            code:        raw.code,
            redirect_to: json_decoded_state.redirect,
        })
    }
}

#[derive(Debug, Deserialize)]
struct GhUserInfo {
    id:         u64,
    login:      String,
    created_at: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn github_callback(
    payload: AuthPayload,
    Extension(options): Extension<Options>,
    Extension(auth_state): Extension<SharedAuthState>,
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(storage): Extension<PersistentStorage>,
    Extension(gh_oauth_client): Extension<GithubOAuthClient>,
    Extension(http_client): Extension<reqwest::Client>,
) -> Result<UserVerifiedResponse, AuthError> {
    let token = gh_oauth_client
        .exchange_code(AuthorizationCode::new(payload.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            if let RequestTokenError::Parse(_, bytes) = e {
                let response_str = String::from_utf8(bytes);
                warn!("Unexpected Github Token Exchange response: {response_str:?}");
            } else {
                warn!("Github Token Exchange Error: {e}");
            }
            AuthError {
                redirect: payload.redirect_to.clone(),
                payload:  AuthErrorPayload::InvalidAuthCode,
            }
        })?;

    let response = http_client
        .get(options.github.gh_userinfo_url)
        .bearer_auth(token.access_token().secret())
        .header("User-Agent", "ethereum-kzg-ceremony-sequencer")
        .send()
        .await
        .map_err(|_| AuthError {
            redirect: payload.redirect_to.clone(),
            payload:  AuthErrorPayload::FetchUserDataError,
        })?;
    let gh_user_info = response.json::<GhUserInfo>().await.map_err(|_| AuthError {
        redirect: payload.redirect_to.clone(),
        payload:  AuthErrorPayload::CouldNotExtractUserData,
    })?;
    let creation_time =
        DateTime::parse_from_rfc3339(&gh_user_info.created_at).map_err(|_| AuthError {
            redirect: payload.redirect_to.clone(),
            payload:  AuthErrorPayload::CouldNotExtractUserData,
        })?;
    if creation_time > options.github.gh_max_account_creation_time {
        return Err(AuthError {
            redirect: payload.redirect_to.clone(),
            payload:  AuthErrorPayload::UserCreatedAfterDeadline,
        });
    }
    let user = Identity::Github {
        id:       gh_user_info.id,
        username: gh_user_info.login.clone(),
    };
    post_authenticate(
        auth_state,
        lobby_state,
        storage,
        user,
        payload.redirect_to,
        options.multi_contribution,
    )
    .await
}

#[derive(Debug, Deserialize)]
struct EthUserInfo {
    sub: String,
}

// This endpoint allows one to consume an oAUTH authorisation code
//  and produce a JWT token
// So Sequencer could give out fake identities, we are trusting the sequencer
// to not do that.
//
// Now this is catchable by the client. They will clearly see that the sequencer
// was malicious. What can happen is sequencer can claim that someone
// participated when they did not. Is this Okay? Maybe that person can then just
// say they did not
#[allow(clippy::too_many_arguments)]
pub async fn eth_callback(
    payload: AuthPayload,
    Extension(options): Extension<Options>,
    Extension(auth_state): Extension<SharedAuthState>,
    Extension(lobby_state): Extension<SharedLobbyState>,
    Extension(storage): Extension<PersistentStorage>,
    Extension(oauth_client): Extension<EthOAuthClient>,
    Extension(http_client): Extension<reqwest::Client>,
) -> Result<UserVerifiedResponse, AuthError> {
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(payload.code))
        .request_async(async_http_client)
        .await
        .map_err(|_| AuthError {
            redirect: payload.redirect_to.clone(),
            payload:  AuthErrorPayload::InvalidAuthCode,
        })?;

    let response = http_client
        .get(&options.ethereum.eth_userinfo_url)
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|_| AuthError {
            redirect: payload.redirect_to.clone(),
            payload:  AuthErrorPayload::FetchUserDataError,
        })?;

    let eth_user = response
        .json::<EthUserInfo>()
        .await
        .map_err(|_| AuthError {
            redirect: payload.redirect_to.clone(),
            payload:  AuthErrorPayload::CouldNotExtractUserData,
        })?;

    let addr_parts: Vec<_> = eth_user.sub.split(':').collect();
    let address = (*addr_parts.get(2).ok_or(AuthError {
        redirect: payload.redirect_to.clone(),
        payload:  AuthErrorPayload::CouldNotExtractUserData,
    })?)
    .to_string();

    let tx_count = get_tx_count(
        &address,
        &options.ethereum.eth_nonce_verification_block,
        &http_client,
        &options.ethereum,
    )
    .await
    .ok_or(AuthError {
        redirect: payload.redirect_to.clone(),
        payload:  AuthErrorPayload::CouldNotExtractUserData,
    })?;

    if tx_count < options.ethereum.eth_min_nonce {
        return Err(AuthError {
            redirect: payload.redirect_to.clone(),
            payload:  AuthErrorPayload::UserCreatedAfterDeadline,
        });
    }

    let user_data = Identity::eth_from_str(&address).map_err(|_| AuthError {
        redirect: payload.redirect_to.clone(),
        payload:  AuthErrorPayload::CouldNotExtractUserData,
    })?;

    post_authenticate(
        auth_state,
        lobby_state,
        storage,
        user_data,
        payload.redirect_to,
        options.multi_contribution,
    )
    .await
}

// TODO: This has many failure modes and should return and eyre::Result.
async fn get_tx_count(
    address: &str,
    at_block: &str,
    client: &reqwest::Client,
    options: &EthAuthOptions,
) -> Option<u64> {
    let rpc_payload = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "params": [&address, &at_block],
        "method": "eth_getTransactionCount"
    });

    let rpc_response = client
        .post(options.eth_rpc_url.get_secret())
        .json(&rpc_payload)
        .send()
        .await
        .ok()?;

    let rpc_response_json = rpc_response.json::<serde_json::Value>().await.ok()?;

    let rpc_result = rpc_response_json.get("result")?.as_str()?;

    u64::from_str_radix(rpc_result.trim_start_matches("0x"), 16).ok()
}

async fn post_authenticate(
    auth_state: SharedAuthState,
    lobby_state: SharedLobbyState,
    storage: PersistentStorage,
    user_data: Identity,
    redirect_to: Option<String>,
    multi_contribution: bool,
) -> Result<UserVerifiedResponse, AuthError> {
    // Check if they have already contributed
    match storage.has_contributed(&user_data.unique_id()).await {
        Err(error) => {
            return Err(AuthError {
                redirect: redirect_to.clone(),
                payload:  AuthErrorPayload::Storage(error),
            })
        }
        Ok(true) => {
            if multi_contribution {
                warn!(uid = %user_data, "User has already contributed, accepting multiple.");
            } else {
                return Err(AuthError {
                    redirect: redirect_to.clone(),
                    payload:  AuthErrorPayload::UserAlreadyContributed,
                });
            }
        }
        Ok(false) => (),
    }

    // Check if this user is already in the lobby
    // If so, we send them back their session id
    let session_id = {
        let mut state = auth_state.write().await;

        if let Some(session_id) = state.unique_id_session.get(&user_data.unique_id()) {
            session_id.clone()
        } else {
            let id = SessionId::new();
            state
                .unique_id_session
                .insert(user_data.unique_id(), id.clone());
            id
        }
    };

    let id_token = IdToken {
        identity: user_data,
        exp:      u64::MAX,
    };

    lobby_state
        .insert_participant(session_id.clone(), SessionInfo {
            token:                 id_token.clone(),
            last_ping_time:        Instant::now(),
            is_first_ping_attempt: true,
        })
        .await;

    Ok(UserVerifiedResponse {
        id_token,
        session_id: session_id.to_string(),
        as_redirect_to: redirect_to,
    })
}
