use axum::{
    routing::{get, post, IntoMakeService},
    Extension, Form, Json, Router, TypedHeader,
};
use headers::{authorization::Bearer, Authorization};
use http::StatusCode;
use hyper::{server::conn::AddrIncoming, Server};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::sync::RwLock;

pub fn start_server(auth_state: AuthState) -> Server<AddrIncoming, IntoMakeService<Router>> {
    let app = Router::new()
        .route("/github/oauth/token", post(exchange_gh_token))
        .route("/github/user", get(gh_userinfo))
        .layer(Extension(auth_state));
    Server::try_bind(&SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 3001))
        .unwrap()
        .serve(app.into_make_service())
}

#[derive(Clone, Debug, Serialize)]
pub struct GhUser {
    pub name:       String,
    pub created_at: String,
}

#[derive(Clone)]
pub struct AuthState {
    github_users: Arc<RwLock<HashMap<u64, GhUser>>>,
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            github_users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_user(&mut self, auth_code: u64, user: GhUser) {
        self.github_users.write().await.insert(auth_code, user);
    }

    pub async fn get_user(&self, auth_code: u64) -> Option<GhUser> {
        self.github_users
            .read()
            .await
            .get(&auth_code)
            .map(Clone::clone)
    }
}

#[derive(Debug, Deserialize)]
struct ExchangeRequest {
    code: u64,
}

async fn exchange_gh_token(
    Form(req): Form<ExchangeRequest>,
    Extension(state): Extension<AuthState>,
) -> (StatusCode, Json<Value>) {
    let user = state.get_user(req.code).await;
    match user {
        Some(_) => (
            StatusCode::OK,
            Json(json!({
                "access_token": format!("token_of::{}", req.code),
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 60
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Invalid code"})),
        ),
    }
}

async fn gh_userinfo(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Extension(state): Extension<AuthState>,
) -> (StatusCode, Json<Value>) {
    let token = auth.0.token();
    let code_str = token
        .split("::")
        .collect::<Vec<_>>()
        .get(1)
        .expect("invalid auth token")
        .clone();
    let code = u64::from_str(code_str).expect("invalid auth token");
    let user = state.get_user(code).await;
    match user {
        Some(user) => (
            StatusCode::OK,
            Json(json!({"login": user.name, "created_at": user.created_at})),
        ),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid auth token"})),
        ),
    }
}
