use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub const MAX_ATTEMPTS: usize = 5;
pub const WINDOW: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub struct LoginAttempts {
    inner: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl LoginAttempts {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn is_locked_out(&self, username: &str) -> bool {
        let mut map = self.inner.lock().await;
        let attempts = map.entry(username.to_string()).or_default();
        let cutoff = Instant::now() - WINDOW;
        attempts.retain(|&t| t > cutoff);
        attempts.len() >= MAX_ATTEMPTS
    }

    pub async fn record_failure(&self, username: &str) {
        let mut map = self.inner.lock().await;
        map.entry(username.to_string())
            .or_default()
            .push(Instant::now());
    }

    pub async fn clear(&self, username: &str) {
        let mut map = self.inner.lock().await;
        map.remove(username);
    }
}
