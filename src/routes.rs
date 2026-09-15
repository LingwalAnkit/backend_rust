use axum::{
    Router,
    routing::{get, post},
};

use crate::{handlers, state::AppState};

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/health/db", get(handlers::health_check_db))
        .route("/register", post(handlers::register))
        .route("/login", post(handlers::login))
        .route("/me", get(handlers::me))
        .route("/refresh", get(handlers::refresh))
        .with_state(state)
}
