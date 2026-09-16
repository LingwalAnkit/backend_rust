use mongodb::Database;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub jwt_secret: String,
    pub rate_limt: crate::rate_limit::LoginAttempts,
}
