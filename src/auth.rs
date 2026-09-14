use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    RequestPartsExt,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

// TEMP: hardcoded — moves to an env var in the cleanup step
pub const JWT_SECRET: &[u8] = b"dev-secret-change-me";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub fn create_token(username: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 60 * 60; // 1 hour

    let claims = Claims {
        sub: username.to_string(),
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
}

pub struct AuthUser {
    pub username: String,
}

// Tell Axum how to create AuthUser
// "If one of my routes asks for an AuthUser, I will tell you how to get it from the HTTP request."

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    // HTTP request Information
    // GET /me
    // Authorization: Bearer eyJhbGci...
    // Content-Type: application/json
    // parts
    // │
    // ├── headers
    // │     └── Authorization: Bearer <JWT>
    // ├── method
    // ├── URI
    // └── ...

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Result<Authuser , (StatusCode, String)>
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "missing or invalid authorization header".to_string(),
                )
            })?;

        // After the above function bearer contain the string "Bearer <JWT>"

        let token_data = decode::<Claims>(
            bearer.token(),
            &DecodingKey::from_secret(JWT_SECRET),
            &Validation::default(),
        )
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "invalid or expired token".to_string(),
            )
        })?;

        Ok(AuthUser {
            username: token_data.claims.sub, //
        })
    }
}
