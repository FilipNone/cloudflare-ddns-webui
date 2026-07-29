//! Authentication: PBKDF2-hashed password verification (via `ring`, already
//! used by rustls — no extra crypto dependencies), in-memory session tokens
//! and per-IP login rate limiting.

use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const SESSION_TOKEN_LEN: usize = 32;

const MAX_LOGIN_FAILURES: u32 = 5;
const LOGIN_LOCKOUT: Duration = Duration::from_secs(5 * 60);

pub struct PasswordHash {
    salt: [u8; SALT_LEN],
    key: [u8; KEY_LEN],
}

impl PasswordHash {
    /// Derive a hash from the plaintext password at boot time. The password
    /// itself is then dropped; only the salted hash stays in memory.
    pub fn from_password(password: &str) -> Self {
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).expect("secure RNG failure");
        let mut key = [0u8; KEY_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            &salt,
            password.as_bytes(),
            &mut key,
        );
        PasswordHash { salt, key }
    }

    /// Constant-time verification of a login attempt.
    pub fn verify(&self, password: &str) -> bool {
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            &self.salt,
            password.as_bytes(),
            &self.key,
        )
        .is_ok()
    }
}

struct SessionEntry {
    expires_at: Instant,
}

pub struct SessionStore {
    sessions: Mutex<HashMap<String, SessionEntry>>,
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        SessionStore {
            sessions: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn create(&self) -> String {
        let rng = SystemRandom::new();
        let mut bytes = [0u8; SESSION_TOKEN_LEN];
        rng.fill(&mut bytes).expect("secure RNG failure");
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut sessions = self.sessions.lock().unwrap();
        // Opportunistic cleanup of expired sessions.
        let now = Instant::now();
        sessions.retain(|_, e| e.expires_at > now);
        sessions.insert(
            token.clone(),
            SessionEntry {
                expires_at: now + self.ttl,
            },
        );
        token
    }

    pub fn is_valid(&self, token: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(token) {
            Some(entry) if entry.expires_at > Instant::now() => true,
            Some(_) => {
                sessions.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn destroy(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

/// Simple per-IP login rate limiter: after MAX_LOGIN_FAILURES consecutive
/// failures the source is locked out for LOGIN_LOCKOUT.
pub struct LoginLimiter {
    state: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        LoginLimiter {
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_locked_out(&self, ip: IpAddr) -> bool {
        let state = self.state.lock().unwrap();
        match state.get(&ip) {
            Some((fails, since)) => {
                *fails >= MAX_LOGIN_FAILURES && since.elapsed() < LOGIN_LOCKOUT
            }
            None => false,
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut state = self.state.lock().unwrap();
        // Bound the map size.
        if state.len() > 10_000 {
            state.clear();
        }
        let entry = state.entry(ip).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn record_success(&self, ip: IpAddr) {
        self.state.lock().unwrap().remove(&ip);
    }
}
