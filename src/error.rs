use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use serde_json::json;

pub enum AppError {
    Database(mongodb::error::Error),
    Hash(argon2::password_hash::Error),
    Jwt(jsonwebtoken::errors::Error),
    Unauthorized(String),
    UsernameTaken,
    InvalidCredentials,
    InvalidRefreshToken,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Database(e) => {
                eprintln!("database error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
            AppError::Hash(e) => {
                eprintln!("hash error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
            AppError::Jwt(e) => {
                eprintln!("jwt error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
            AppError::UsernameTaken => (StatusCode::CONFLICT, "username already taken".to_string()),
            AppError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid username or password".to_string(),
            ),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::InvalidRefreshToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid refresh token".to_string(),
            ),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<mongodb::error::Error> for AppError {
    fn from(e: mongodb::error::Error) -> Self {
        AppError::Database(e)
    }
}
impl From<argon2::password_hash::Error> for AppError {
    fn from(e: argon2::password_hash::Error) -> Self {
        AppError::Hash(e)
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        AppError::Jwt(e)
    }
}
