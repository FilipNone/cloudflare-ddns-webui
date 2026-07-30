//! Authentication state: password verification (PBKDF2 via `ring`), TOTP
//! two-factor with one-time backup codes, pending-login challenges, in-memory
//! sessions, and per-IP login rate limiting.
//!
//! The credential hash is kept in a small JSON state file under a data volume
//! so container restarts do not lock the admin out. Passwords and backup
//! codes are only ever stored as PBKDF2 hashes; the TOTP secret is stored
//! base32-encoded (a hard requirement of TOTP itself).

use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const SESSION_TOKEN_LEN: usize = 32;
const CHALLENGE_TOKEN_LEN: usize = 32;
const TOTP_SECRET_LEN: usize = 20; // 160-bit, standard
const BACKUP_CODE_COUNT: usize = 8;

const MAX_LOGIN_FAILURES: u32 = 5;
const LOGIN_LOCKOUT: Duration = Duration::from_secs(5 * 60);
const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_2FA_ATTEMPTS: u32 = 5;

// --- Hashing ---

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        &mut key,
    );
    key
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; N];
    rng.fill(&mut bytes).expect("secure RNG failure");
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn subtle_constant_time_eq(a: &[u8; KEY_LEN], b: &[u8; KEY_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..KEY_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// --- Persisted state file ---

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuthState {
    pub password_salt: Option<String>,
    pub password_key: Option<String>,
    pub totp_secret: Option<String>, // base32
    pub backup_code_hashes: Vec<String>,
}

impl AuthState {
    pub fn is_configured(&self) -> bool {
        self.password_salt.is_some() && self.password_key.is_some()
    }
    pub fn totp_enabled(&self) -> bool {
        self.totp_secret.is_some()
    }
}

// --- Pending login challenge (password OK, 2FA pending) ---

struct Challenge {
    expires_at: Instant,
    attempts: u32,
}

// --- Pending TOTP enrollment ---

pub struct PendingTotp {
    pub secret: Vec<u8>,
    pub expires_at: Instant,
}

pub struct Auth {
    pub state: Mutex<AuthState>,
    sessions: Mutex<HashMap<String, Instant>>,
    challenges: Mutex<HashMap<String, Challenge>>,
    pending_totp: Mutex<Option<PendingTotp>>,
    limiter: LoginLimiter,
    session_ttl: Duration,
    state_path: String,
}

impl Auth {
    pub fn new(session_ttl: Duration, state_path: &str) -> Self {
        let state = load_state(state_path);
        Auth {
            state: Mutex::new(state),
            sessions: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            pending_totp: Mutex::new(None),
            limiter: LoginLimiter::new(),
            session_ttl,
            state_path: state_path.to_string(),
        }
    }

    fn persist(&self) -> Result<(), String> {
        let state = self.state.lock().unwrap().clone();
        save_state(&self.state_path, &state)
    }

    pub fn is_configured(&self) -> bool {
        self.state.lock().unwrap().is_configured()
    }

    pub fn totp_enabled(&self) -> bool {
        self.state.lock().unwrap().totp_enabled()
    }

    // --- First-run setup / password changes ---

    /// Set the password. Only valid on first run (or via change_password).
    pub fn setup_password(&self, password: &str) -> Result<(), String> {
        validate_password(password)?;
        {
            let mut state = self.state.lock().unwrap();
            if state.is_configured() {
                return Err("already configured".to_string());
            }
            let salt = random_bytes::<SALT_LEN>();
            let key = derive_key(password, &salt);
            state.password_salt = Some(hex(&salt));
            state.password_key = Some(hex(&key));
        }
        self.persist()
    }

    pub fn change_password(&self, new_password: &str) -> Result<(), String> {
        validate_password(new_password)?;
        {
            let salt = random_bytes::<SALT_LEN>();
            let key = derive_key(new_password, &salt);
            let mut state = self.state.lock().unwrap();
            state.password_salt = Some(hex(&salt));
            state.password_key = Some(hex(&key));
        }
        // Invalidate all sessions on password change.
        self.sessions.lock().unwrap().clear();
        self.persist()
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let state = self.state.lock().unwrap();
        let (Some(salt_hex), Some(key_hex)) = (&state.password_salt, &state.password_key) else {
            return false;
        };
        let salt = match hex_decode_salt(salt_hex) {
            Some(s) => s,
            None => return false,
        };
        let expected = match hex_decode_key(key_hex) {
            Some(k) => k,
            None => return false,
        };
        let candidate = derive_key(password, &salt);
        // Constant-time comparison.
        subtle_constant_time_eq(&candidate, &expected)
    }

    // --- Login flow ---

    pub fn limiter(&self) -> &LoginLimiter {
        &self.limiter
    }

    /// Step 1: password. Returns Ok(None) when no 2FA is needed (caller
    /// should create a session), or Ok(Some(challenge_token)) when a second
    /// factor is required.
    pub fn login_step1(&self, ip: IpAddr, password: &str) -> Result<Option<String>, &'static str> {
        if self.limiter.is_locked_out(ip) {
            return Err("locked_out");
        }
        if !self.verify_password(password) {
            self.limiter.record_failure(ip);
            return Err("invalid_password");
        }
        if !self.totp_enabled() {
            self.limiter.record_success(ip);
            return Ok(None);
        }
        let token = hex(&random_bytes::<CHALLENGE_TOKEN_LEN>());
        let mut challenges = self.challenges.lock().unwrap();
        let now = Instant::now();
        challenges.retain(|_, c| c.expires_at > now);
        challenges.insert(
            token.clone(),
            Challenge {
                expires_at: now + CHALLENGE_TTL,
                attempts: 0,
            },
        );
        Ok(Some(token))
    }

    /// Step 2: TOTP code or backup code for a pending challenge.
    pub fn login_step2(
        &self,
        ip: IpAddr,
        challenge_token: &str,
        code: &str,
    ) -> Result<Login2faOutcome, &'static str> {
        let mut challenges = self.challenges.lock().unwrap();
        let valid = matches!(challenges.get(challenge_token), Some(c) if c.expires_at > Instant::now());
        if !valid {
            return Err("challenge_expired");
        }
        let entry = challenges.get_mut(challenge_token).unwrap();
        entry.attempts += 1;
        if entry.attempts > MAX_2FA_ATTEMPTS {
            challenges.remove(challenge_token);
            self.limiter.record_failure(ip);
            return Err("too_many_attempts");
        }
        drop(challenges);

        let normalized: String = code
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();

        // Try TOTP first.
        let secret_b32 = self.state.lock().unwrap().totp_secret.clone();
        if let Some(secret_b32) = &secret_b32 {
            if normalized.len() == 6 && normalized.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(secret) = crate::totp::base32_decode(secret_b32) {
                    if crate::totp::totp_verify(&secret, &normalized, now_secs()) {
                        self.challenges.lock().unwrap().remove(challenge_token);
                        self.limiter.record_success(ip);
                        return Ok(Login2faOutcome::Totp);
                    }
                }
            }
        }

        // Try backup code.
        let mut state = self.state.lock().unwrap();
        let normalized_upper = normalized.to_uppercase();
        let mut consumed = false;
        state.backup_code_hashes.retain(|h| {
            if consumed {
                return true;
            }
            if verify_backup_code(h, &normalized_upper) {
                consumed = true;
                false // consume the code
            } else {
                true
            }
        });
        if consumed {
            let remaining = state.backup_code_hashes.len();
            drop(state);
            let _ = self.persist();
            self.challenges.lock().unwrap().remove(challenge_token);
            self.limiter.record_success(ip);
            return Ok(Login2faOutcome::BackupCode { remaining });
        }

        self.limiter.record_failure(ip);
        Err("invalid_code")
    }

    // --- TOTP enrollment ---

    /// Begin enrollment: generates a secret and otpauth URI + QR SVG.
    pub fn totp_enroll_begin(&self) -> Result<(String, String, Option<String>), String> {
        if self.totp_enabled() {
            return Err("2FA is already enabled".to_string());
        }
        let secret = random_bytes::<TOTP_SECRET_LEN>();
        let secret_b32 = crate::totp::base32_encode(&secret);
        let uri = crate::totp::otpauth_uri(&secret_b32, "Cloudflare DDNS", "admin");
        let qr = crate::totp::qr_svg(&uri);
        let mut pending = self.pending_totp.lock().unwrap();
        *pending = Some(PendingTotp {
            secret: secret.to_vec(),
            expires_at: Instant::now() + CHALLENGE_TTL,
        });
        Ok((secret_b32, uri, qr))
    }

    /// Confirm enrollment with the first TOTP code; returns backup codes.
    pub fn totp_enroll_confirm(&self, code: &str) -> Result<Vec<String>, String> {
        let pending = {
            let mut p = self.pending_totp.lock().unwrap();
            match p.as_ref() {
                Some(pt) if pt.expires_at > Instant::now() => p.take(),
                _ => None,
            }
        };
        let pending = pending.ok_or("enrollment expired - start again")?;
        let normalized: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if !crate::totp::totp_verify(&pending.secret, &normalized, now_secs()) {
            return Err("invalid code - check your authenticator and try again".to_string());
        }
        let codes = generate_backup_codes();
        let hashes = codes.iter().map(|c| hash_backup_code(c)).collect();
        {
            let mut state = self.state.lock().unwrap();
            state.totp_secret = Some(crate::totp::base32_encode(&pending.secret));
            state.backup_code_hashes = hashes;
        }
        self.persist()?;
        Ok(codes)
    }

    pub fn totp_enroll_cancel(&self) {
        *self.pending_totp.lock().unwrap() = None;
    }

    /// Disable 2FA entirely (caller must verify identity first).
    pub fn totp_disable(&self) -> Result<(), String> {
        {
            let mut state = self.state.lock().unwrap();
            state.totp_secret = None;
            state.backup_code_hashes.clear();
        }
        self.persist()
    }

    /// Verify and consume a backup code outside the login flow (identity
    /// confirmation for sensitive operations).
    pub fn try_consume_backup_code(&self, code: &str) -> bool {
        let normalized: String = code
            .to_uppercase()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let mut state = self.state.lock().unwrap();
        let mut consumed = false;
        state.backup_code_hashes.retain(|h| {
            if consumed {
                return true;
            }
            if verify_backup_code(h, &normalized) {
                consumed = true;
                false
            } else {
                true
            }
        });
        if consumed {
            drop(state);
            let _ = self.persist();
        }
        consumed
    }

    pub fn backup_codes_remaining(&self) -> usize {
        self.state.lock().unwrap().backup_code_hashes.len()
    }

    // --- Sessions ---

    pub fn create_session(&self) -> String {
        let token = hex(&random_bytes::<SESSION_TOKEN_LEN>());
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|_, exp| *exp > now);
        sessions.insert(token.clone(), now + self.session_ttl);
        token
    }

    pub fn session_valid(&self, token: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(token) {
            Some(exp) if *exp > Instant::now() => true,
            Some(_) => {
                sessions.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn destroy_session(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

pub enum Login2faOutcome {
    Totp,
    BackupCode { remaining: usize },
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("password must be at least 8 characters long".to_string());
    }
    if password.len() > 256 {
        return Err("password is too long".to_string());
    }
    Ok(())
}

// --- Backup codes ---

/// Generate 8 codes in the standard XXXX-XXXX format (Crockford base32).
fn generate_backup_codes() -> Vec<String> {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let bytes = random_bytes::<8>();
            let chars: String = bytes.iter().map(|b| ALPHABET[(b % 32) as usize] as char).collect();
            format!("{}-{}", &chars[..4], &chars[4..])
        })
        .collect()
}

fn backup_salt(normalized: &str) -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    let h = derive_key(&format!("backup-salt:{normalized}"), b"cfddnswebui-salt");
    s.copy_from_slice(&h[..SALT_LEN]);
    s
}

fn hash_backup_code(code: &str) -> String {
    let normalized: String = code.to_uppercase().chars().filter(|c| *c != '-').collect();
    hex(&derive_key(&normalized, &backup_salt(&normalized)))
}

fn verify_backup_code(hash_hex: &str, code: &str) -> bool {
    let expected: [u8; KEY_LEN] = match hex_decode_key(hash_hex) {
        Some(e) => e,
        None => return false,
    };
    let normalized: String = code.to_uppercase().chars().filter(|c| *c != '-').collect();
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        &backup_salt(&normalized),
        normalized.as_bytes(),
        &expected,
    )
    .is_ok()
}

// --- State file I/O ---

fn load_state(path: &str) -> AuthState {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => AuthState::default(),
    }
}

fn save_state(path: &str, state: &AuthState) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("cannot create data dir: {e}"))?;
    }
    let tmp = format!("{path}.tmp");
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, json).map_err(|e| format!("cannot write state file: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot save state file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn hex_decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex_decode_salt(s: &str) -> Option<[u8; SALT_LEN]> {
    hex_decode::<SALT_LEN>(s)
}

fn hex_decode_key(s: &str) -> Option<[u8; KEY_LEN]> {
    hex_decode::<KEY_LEN>(s)
}

// --- Rate limiter ---

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
            Some((fails, since)) => *fails >= MAX_LOGIN_FAILURES && since.elapsed() < LOGIN_LOCKOUT,
            None => false,
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut state = self.state.lock().unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_password_flow() {
        let salt = random_bytes::<SALT_LEN>();
        let password = "super-secret-password";
        let key = derive_key(password, &salt);
        let salt_hex = hex(&salt);
        let key_hex = hex(&key);
        assert_eq!(salt_hex.len(), SALT_LEN * 2, "salt hex len");
        assert_eq!(key_hex.len(), KEY_LEN * 2, "key hex len");
        let salt2 = hex_decode_salt(&salt_hex).expect("salt decode");
        let key2 = hex_decode_key(&key_hex).expect("key decode");
        assert_eq!(salt2, salt, "salt roundtrip");
        assert_eq!(key2, key, "key roundtrip");
        let candidate = derive_key(password, &salt2);
        assert_eq!(candidate, key2, "derive matches");
        assert!(subtle_constant_time_eq(&candidate, &key2));
    }

    #[test]
    fn backup_codes_hash_and_verify() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        for c in &codes {
            assert_eq!(c.len(), 9); // XXXX-XXXX
            assert_eq!(c.chars().nth(4), Some('-'));
            let h = hash_backup_code(c);
            assert!(verify_backup_code(&h, c));
            let nodash: String = c.chars().filter(|x| *x != '-').collect();
            assert!(verify_backup_code(&h, &nodash));
            assert!(!verify_backup_code(&h, "AAAA-AAAA"));
        }
    }

    #[test]
    fn state_roundtrip() {
        let dir = std::env::temp_dir().join(format!("cfddns-test-{}", std::process::id()));
        let path = dir.join("state.json");
        let auth = Auth::new(Duration::from_secs(60), path.to_str().unwrap());
        assert!(!auth.is_configured());
        auth.setup_password("super-secret-password").unwrap();
        assert!(auth.is_configured());
        assert!(auth.verify_password("super-secret-password"));
        assert!(!auth.verify_password("wrong-password"));
        let auth2 = Auth::new(Duration::from_secs(60), path.to_str().unwrap());
        assert!(auth2.is_configured());
        assert!(auth2.verify_password("super-secret-password"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn totp_enrollment_flow() {
        let dir = std::env::temp_dir().join(format!("cfddns-test2-{}", std::process::id()));
        let path = dir.join("state.json");
        let auth = Auth::new(Duration::from_secs(60), path.to_str().unwrap());
        auth.setup_password("super-secret-password").unwrap();
        let (_secret_b32, uri, qr) = auth.totp_enroll_begin().unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(qr.is_some());
        let pending = auth.pending_totp.lock().unwrap().as_ref().unwrap().secret.clone();
        let code = format!("{:06}", crate::totp::totp_at(&pending, now_secs()));
        let backup = auth.totp_enroll_confirm(&code).unwrap();
        assert_eq!(backup.len(), BACKUP_CODE_COUNT);
        assert!(auth.totp_enabled());
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let challenge = auth.login_step1(ip, "super-secret-password").unwrap();
        assert!(challenge.is_some());
        let outcome = auth.login_step2(ip, &challenge.unwrap(), &backup[0]).unwrap();
        match outcome {
            Login2faOutcome::BackupCode { remaining } => {
                assert_eq!(remaining, BACKUP_CODE_COUNT - 1)
            }
            _ => panic!("expected backup code outcome"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
