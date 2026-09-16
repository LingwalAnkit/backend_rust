use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub const MAX_ATTEMPTS: usize = 5;
pub const WINDOW: Duration = Duration::from_secs(15 * 60); // 15 minutes lockout

#[derive(Clone)]
pub struct LoginAttempts {
    inner: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    // hashmap [username: String , timestamps: Vec<Instant>]
    // "For every username, keep a list of the times they failed login."
    // "ankit" → [Instant(10:01), Instant(10:05), Instant(10:10)]
    //
    // mutex is used to protect the hashmap from concurrent access.
    // req A and req B made simultaneously from different clients.
}

impl LoginAttempts {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn is_locked_out(&self, username: &str) -> bool {
        let mut map = self.inner.lock().await;
        // "Give me the key. I need temporary access to the HashMap."
        // {
        // "Ankit" -> [Instant(10:01), Instant(10:05), Instant(10:10)]
        // "Aman" -> [Instant(10:02), Instant(10:06), Instant(10:11)]
        // }
        let attempts = map.entry(username.to_string()).or_default();
        // "Add a username to map if exist use the existing from map if not create one "
        let cutoff = Instant::now() - WINDOW;
        // let say instant is 1pm then - WINDOW is 15 minutes so cutoff is 12:45pm now this tell to count the attempts in this time frame 12:45 to 1pm
        attempts.retain(|&t| t > cutoff);
        attempts.len() >= MAX_ATTEMPTS
    }

    pub async fn record_failure(&self, username: &str) {
        let mut map = self.inner.lock().await;
        map.entry(username.to_string())
            .or_default()
            .push(Instant::now());
        // "For every username, keep a list of the times they failed login."
        // "ankit" → [Instant(10:01), Instant(10:05), Instant(10:10)]
    }

    // Record Failure is for the users that does not exist in the db and we are still applying rate limiting
    // to prevent brute force attacks on non-existent users.

    pub async fn clear(&self, username: &str) {
        let mut map = self.inner.lock().await;
        map.remove(username);
    }
}

// is_locked_out() = checks how many recent failures there are
// record_failure() = records a failed login attempt for a given username
// clear() = removes all failures for a given username let say ankit tried to login but failed 3 times and then used the correct credentials so now remove all failures for ankit
