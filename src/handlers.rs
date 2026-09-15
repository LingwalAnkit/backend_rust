use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use axum::{Json, extract::State};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    error::AppError,
    models::{RefreshToken, User},
    state::AppState,
};

pub async fn health_check() -> &'static str {
    "ok"
}

pub async fn health_check_db(State(state): State<AppState>) -> &'static str {
    match state.db.run_command(doc! { "ping": 1 }).await {
        Ok(_) => "db ok",
        Err(_) => "db unreachable",
    }
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub username: String,
    pub message: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    let users = state.db.collection::<User>("users");

    let existing = users
        .find_one(doc! { "username": &payload.username })
        .await?;

    if existing.is_some() {
        return Err(AppError::UsernameTaken);
    }

    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes())?
        .to_string();

    let new_user = User {
        id: None,
        username: payload.username.clone(),
        password_hash,
    };

    users.insert_one(new_user).await?;

    Ok(Json(RegisterResponse {
        username: payload.username,
        message: "registered".to_string(),
    }))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<TokenPair>, AppError> {
    let users = state.db.collection::<User>("users");

    let user = users
        .find_one(doc! { "username": &payload.username })
        .await?
        .ok_or(AppError::InvalidCredentials)?;

    let parsed_hash =
        PasswordHash::new(&user.password_hash).map_err(|e| AppError::Hash(e.into()))?;

    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::InvalidCredentials)?;

    issue_token_pair(&state, &payload.username).await
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<TokenPair>, AppError> {
    let tokens = state.db.collection::<RefreshToken>("refresh_tokens");
    let token_hash = auth::hash_token(&payload.refresh_token);

    let stored = tokens
        .find_one(doc! { "token_hash": &token_hash })
        .await?
        .ok_or(AppError::InvalidRefreshToken)?;

    // rotation: this token is now spent, valid or not
    tokens
        .delete_one(doc! { "token_hash": &token_hash })
        .await?;

    if stored.expires_at < auth::now_unix() {
        return Err(AppError::InvalidRefreshToken);
    }

    issue_token_pair(&state, &stored.username).await
}

async fn issue_token_pair(state: &AppState, username: &str) -> Result<Json<TokenPair>, AppError> {
    let access_token = auth::create_access_token(username, &state.jwt_secret)?;
    let refresh_token = auth::generate_refresh_token();

    let record = RefreshToken {
        id: None,
        username: username.to_string(),
        token_hash: auth::hash_token(&refresh_token),
        expires_at: auth::now_unix() + auth::REFRESH_TOKEN_EXPIRATION * 24 * 60 * 60,
    };

    state
        .db
        .collection::<RefreshToken>("refresh_tokens")
        .insert_one(record)
        .await?;

    Ok(Json(TokenPair {
        access_token,
        refresh_token,
    }))
}

pub async fn me(auth_user: auth::AuthUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "username": auth_user.username }))
}
