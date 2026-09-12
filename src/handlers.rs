use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use axum::{Json, extract::State, http::StatusCode};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{models::User, state::AppState};

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
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    // result [Json<RegisterResponse> / (StatusCode , String)]
    let users = state.db.collection::<User>("users");
    // "Give me access to the users collection, and the documents inside it represent User objects."

    let existing = users
        .find_one(doc! { "username": &payload.username })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "username already taken".to_string()));
    }

    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    let new_user = User {
        id: None,
        username: payload.username.clone(),
        password_hash,
    };

    users
        .insert_one(new_user)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let users = state.db.collection::<User>("users");

    let user = match users.find_one(doc! { "username": &payload.username }).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Invalid username or password".to_string(),
            ));
        }

        Err(e) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        }
    };

    // to handel no username

    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "invalid username or password".to_string(),
            )
        })?;

    let token = crate::auth::create_token(&payload.username)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(LoginResponse { token }))
}

pub async fn me(auth_user: crate::auth::AuthUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "username" : auth_user.username}))
}
