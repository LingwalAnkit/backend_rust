use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use axum::{Json, extract::State};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{auth, error::AppError, models::User, state::AppState};

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
pub struct LoginResponse {
    pub token: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
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

    let token = auth::create_token(&payload.username, &state.jwt_secret)?;

    Ok(Json(LoginResponse { token }))
}

pub async fn me(auth_user: auth::AuthUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "username": auth_user.username }))
}
