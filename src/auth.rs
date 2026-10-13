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
}

// --- Pending TOTP enrollment ---

pub struct PendingTotp {
    pub secret: Vec<u8>,
    pub expires_at: Instant,
}

pub struct Auth {
    state: Mutex<AuthState>,
    operations: Mutex<()>,
    sessions: Mutex<HashMap<String, Instant>>,
    challenges: Mutex<HashMap<String, Challenge>>,
    pending_totp: Mutex<Option<PendingTotp>>,
    limiter: LoginLimiter,
    factor_failures: Mutex<(u32, Instant)>,
    session_ttl: Duration,
    state_path: String,
}

impl Auth {
    pub fn new(session_ttl: Duration, state_path: &str) -> Result<Self, String> {
        let state = load_state(state_path)?;
        Ok(Auth {
            state: Mutex::new(state),
            operations: Mutex::new(()),
            sessions: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            pending_totp: Mutex::new(None),
            limiter: LoginLimiter::new(),
            factor_failures: Mutex::new((0, Instant::now())),
            session_ttl,
            state_path: state_path.to_string(),
        })
    }

    fn commit_state(&self, candidate: AuthState) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        save_state(&self.state_path, &candidate)?;
        *state = candidate;
        Ok(())
    }

    fn revoke_authentication(&self) {
        self.sessions.lock().unwrap().clear();
        self.challenges.lock().unwrap().clear();
        *self.pending_totp.lock().unwrap() = None;
    }

    fn factor_locked_out(&self) -> bool {
        let mut failures = self.factor_failures.lock().unwrap();
        if failures.1.elapsed() >= LOGIN_LOCKOUT {
            failures.0 = 0;
        }
        failures.0 >= MAX_2FA_ATTEMPTS
    }

    fn factor_failure(&self, ip: Option<IpAddr>) {
        let mut failures = self.factor_failures.lock().unwrap();
        if failures.1.elapsed() >= LOGIN_LOCKOUT {
            failures.0 = 0;
        }
        failures.0 = failures.0.saturating_add(1);
        failures.1 = Instant::now();
        if let Some(ip) = ip {
            self.limiter.record_failure(ip);
        }
    }

    fn factor_success(&self, ip: IpAddr) {
        *self.factor_failures.lock().unwrap() = (0, Instant::now());
        self.limiter.record_success(ip);
    }

    // The operations lock covers proof verification through the persisted mutation.
    fn verify_factor_locked(
        &self,
        ip: IpAddr,
        code: &str,
        state: &AuthState,
    ) -> Result<Option<usize>, &'static str> {
        if self.factor_locked_out() || self.limiter.is_locked_out(ip) {
            return Err("locked_out");
        }
        let normalized: String = code
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        // Try TOTP first.
        if let Some(secret) = state
            .totp_secret
            .as_ref()
            .and_then(|secret| crate::totp::base32_decode(secret).ok())
        {
            if crate::totp::totp_verify(&secret, &normalized, now_secs()) {
                return Ok(None);
            }
        }
        // Try backup code.
        let normalized = normalized.to_ascii_uppercase();
        if let Some(index) = state
            .backup_code_hashes
            .iter()
            .position(|hash| verify_backup_code(hash, &normalized))
        {
            return Ok(Some(index));
        }
        self.factor_failure(Some(ip));
        Err("invalid_code")
    }

    pub fn is_configured(&self) -> bool {
        self.state.lock().unwrap().is_configured()
    }

    pub fn totp_enabled(&self) -> bool {
        self.state.lock().unwrap().totp_enabled()
    }

    // --- First-run setup / password changes ---

    /// Set the password. Only valid on first run (or via change_password).
    #[cfg(test)]
    pub fn setup_password(&self, password: &str) -> Result<(), String> {
        let _operation = self.operations.lock().unwrap();
        self.setup_password_locked(password)
    }

    pub fn setup_password_session(&self, password: &str) -> Result<String, String> {
        let _operation = self.operations.lock().unwrap();
        self.setup_password_locked(password)?;
        Ok(self.create_session())
    }

    fn setup_password_locked(&self, password: &str) -> Result<(), String> {
        validate_password(password)?;
        let mut candidate = self.state.lock().unwrap().clone();
        if candidate.is_configured() {
            return Err("already configured".to_string());
        }
        let salt = random_bytes::<SALT_LEN>();
        candidate.password_salt = Some(hex(&salt));
        candidate.password_key = Some(hex(&derive_key(password, &salt)));
        self.commit_state(candidate)
    }

    #[cfg(test)]
    pub fn change_password(&self, new_password: &str) -> Result<(), String> {
        validate_password(new_password)?;
        let _operation = self.operations.lock().unwrap();
        let mut candidate = self.state.lock().unwrap().clone();
        let salt = random_bytes::<SALT_LEN>();
        candidate.password_salt = Some(hex(&salt));
        candidate.password_key = Some(hex(&derive_key(new_password, &salt)));
        self.commit_state(candidate)?;
        // Invalidate all sessions on password change.
        self.revoke_authentication();
        Ok(())
    }

    pub fn change_password_verified(
        &self,
        ip: IpAddr,
        current_password: &str,
        code: Option<&str>,
        new_password: &str,
    ) -> Result<String, String> {
        validate_password(new_password)?;
        let _operation = self.operations.lock().unwrap();
        if self.factor_locked_out() || self.limiter.is_locked_out(ip) {
            return Err("locked_out".to_string());
        }
        if !self.verify_password(current_password) {
            self.factor_failure(Some(ip));
            return Err("invalid_password".to_string());
        }
        let mut candidate = self.state.lock().unwrap().clone();
        if candidate.totp_enabled() {
            if let Some(index) = self.verify_factor_locked(ip, code.unwrap_or(""), &candidate)? {
                candidate.backup_code_hashes.remove(index);
            }
        }
        let salt = random_bytes::<SALT_LEN>();
        candidate.password_salt = Some(hex(&salt));
        candidate.password_key = Some(hex(&derive_key(new_password, &salt)));
        self.commit_state(candidate)
            .map_err(|_| "persistence_failed".to_string())?;
        self.revoke_authentication();
        self.factor_success(ip);
        Ok(self.create_session())
    }

    pub fn verify_password(&self, password: &str) -> bool {
        if password.len() > 256 {
            return false;
        }
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
    #[cfg(test)]
    pub fn login_step1(&self, ip: IpAddr, password: &str) -> Result<Option<String>, &'static str> {
        let _operation = self.operations.lock().unwrap();
        self.login_step1_locked(ip, password)
    }

    pub fn login_step1_session(
        &self,
        ip: IpAddr,
        password: &str,
    ) -> Result<LoginStep1Outcome, &'static str> {
        let _operation = self.operations.lock().unwrap();
        match self.login_step1_locked(ip, password)? {
            Some(challenge) => Ok(LoginStep1Outcome::Challenge(challenge)),
            None => Ok(LoginStep1Outcome::Session(self.create_session())),
        }
    }

    fn login_step1_locked(
        &self,
        ip: IpAddr,
        password: &str,
    ) -> Result<Option<String>, &'static str> {
        if self.limiter.is_locked_out(ip) || self.factor_locked_out() {
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
            },
        );
        Ok(Some(token))
    }

    /// Step 2: TOTP code or backup code for a pending challenge.
    #[cfg(test)]
    pub fn login_step2(
        &self,
        ip: IpAddr,
        challenge_token: &str,
        code: &str,
    ) -> Result<Login2faOutcome, &'static str> {
        let _operation = self.operations.lock().unwrap();
        self.login_step2_locked(ip, challenge_token, code)
    }

    pub fn login_step2_session(
        &self,
        ip: IpAddr,
        challenge_token: &str,
        code: &str,
    ) -> Result<(Login2faOutcome, String), &'static str> {
        let _operation = self.operations.lock().unwrap();
        let outcome = self.login_step2_locked(ip, challenge_token, code)?;
        Ok((outcome, self.create_session()))
    }

    fn login_step2_locked(
        &self,
        ip: IpAddr,
        challenge_token: &str,
        code: &str,
    ) -> Result<Login2faOutcome, &'static str> {
        if self.limiter.is_locked_out(ip) || self.factor_locked_out() {
            return Err("locked_out");
        }
        let challenges = self.challenges.lock().unwrap();
        let valid =
            matches!(challenges.get(challenge_token), Some(c) if c.expires_at > Instant::now());
        if !valid {
            return Err("challenge_expired");
        }
        drop(challenges);

        let mut candidate = self.state.lock().unwrap().clone();
        let outcome = match self.verify_factor_locked(ip, code, &candidate)? {
            None => Login2faOutcome::Totp,
            Some(index) => {
                candidate.backup_code_hashes.remove(index);
                let remaining = candidate.backup_code_hashes.len();
                self.commit_state(candidate)
                    .map_err(|_| "persistence_failed")?;
                Login2faOutcome::BackupCode { remaining }
            }
        };
        self.challenges.lock().unwrap().remove(challenge_token);
        self.factor_success(ip);
        Ok(outcome)
    }

    // --- TOTP enrollment ---

    /// Begin enrollment: generates a secret and otpauth URI + QR SVG.
    #[cfg(test)]
    pub fn totp_enroll_begin(&self) -> Result<(String, String, Option<String>), String> {
        let _operation = self.operations.lock().unwrap();
        self.totp_enroll_begin_locked()
    }

    pub fn totp_enroll_begin_verified(
        &self,
        ip: IpAddr,
        password: &str,
    ) -> Result<(String, String, Option<String>), String> {
        let _operation = self.operations.lock().unwrap();
        if self.factor_locked_out() || self.limiter.is_locked_out(ip) {
            return Err("locked_out".to_string());
        }
        if !self.verify_password(password) {
            self.factor_failure(Some(ip));
            return Err("invalid_password".to_string());
        }
        self.totp_enroll_begin_locked()
    }

    fn totp_enroll_begin_locked(&self) -> Result<(String, String, Option<String>), String> {
        if self.factor_locked_out() {
            return Err("locked_out".to_string());
        }
        if !self.is_configured() {
            return Err("not_configured".to_string());
        }
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
    #[cfg(test)]
    pub fn totp_enroll_confirm(&self, code: &str) -> Result<Vec<String>, String> {
        let _operation = self.operations.lock().unwrap();
        self.totp_enroll_confirm_locked(code)
    }

    pub fn totp_enroll_confirm_session(&self, code: &str) -> Result<(Vec<String>, String), String> {
        let _operation = self.operations.lock().unwrap();
        let codes = self.totp_enroll_confirm_locked(code)?;
        Ok((codes, self.create_session()))
    }

    fn totp_enroll_confirm_locked(&self, code: &str) -> Result<Vec<String>, String> {
        if self.factor_locked_out() {
            return Err("locked_out".to_string());
        }
        let mut pending_guard = self.pending_totp.lock().unwrap();
        let pending = pending_guard
            .as_ref()
            .filter(|pt| pt.expires_at > Instant::now())
            .ok_or("enrollment expired - start again")?;
        let normalized: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if !crate::totp::totp_verify(&pending.secret, &normalized, now_secs()) {
            self.factor_failure(None);
            return Err("invalid code - check your authenticator and try again".to_string());
        }
        let codes = generate_backup_codes();
        let hashes = codes.iter().map(|c| hash_backup_code(c)).collect();
        let mut candidate = self.state.lock().unwrap().clone();
        candidate.totp_secret = Some(crate::totp::base32_encode(&pending.secret));
        candidate.backup_code_hashes = hashes;
        self.commit_state(candidate)
            .map_err(|_| "persistence_failed".to_string())?;
        *pending_guard = None;
        self.sessions.lock().unwrap().clear();
        self.challenges.lock().unwrap().clear();
        *self.factor_failures.lock().unwrap() = (0, Instant::now());
        Ok(codes)
    }

    pub fn totp_enroll_cancel(&self) {
        let _operation = self.operations.lock().unwrap();
        *self.pending_totp.lock().unwrap() = None;
    }

    /// Disable 2FA entirely (caller must verify identity first).
    #[cfg(test)]
    pub fn totp_disable(&self) -> Result<(), String> {
        let _operation = self.operations.lock().unwrap();
        let mut candidate = self.state.lock().unwrap().clone();
        candidate.totp_secret = None;
        candidate.backup_code_hashes.clear();
        self.commit_state(candidate)?;
        self.revoke_authentication();
        Ok(())
    }

    pub fn totp_disable_verified(&self, ip: IpAddr, code: &str) -> Result<String, &'static str> {
        let _operation = self.operations.lock().unwrap();
        let mut candidate = self.state.lock().unwrap().clone();
        if !candidate.totp_enabled() {
            return Err("not_enabled");
        }
        self.verify_factor_locked(ip, code, &candidate)?;
        candidate.totp_secret = None;
        candidate.backup_code_hashes.clear();
        self.commit_state(candidate)
            .map_err(|_| "persistence_failed")?;
        self.revoke_authentication();
        self.factor_success(ip);
        Ok(self.create_session())
    }

    /// Verify and consume a backup code outside the login flow (identity
    /// confirmation for sensitive operations).
    #[cfg(test)]
    pub fn try_consume_backup_code(&self, code: &str) -> bool {
        let _operation = self.operations.lock().unwrap();
        if self.factor_locked_out() {
            return false;
        }
        let normalized: String = code
            .to_uppercase()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let mut candidate = self.state.lock().unwrap().clone();
        let Some(index) = candidate
            .backup_code_hashes
            .iter()
            .position(|hash| verify_backup_code(hash, &normalized))
        else {
            self.factor_failure(None);
            return false;
        };
        candidate.backup_code_hashes.remove(index);
        if self.commit_state(candidate).is_err() {
            return false;
        }
        *self.factor_failures.lock().unwrap() = (0, Instant::now());
        true
    }

    pub fn backup_codes_remaining(&self) -> usize {
        self.state.lock().unwrap().backup_code_hashes.len()
    }

    // --- Sessions ---

    fn create_session(&self) -> String {
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

pub enum LoginStep1Outcome {
    Session(String),
    Challenge(String),
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
            let chars: String = bytes
                .iter()
                .map(|b| ALPHABET[(b % 32) as usize] as char)
                .collect();
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
    let normalized: String = code
        .to_ascii_uppercase()
        .chars()
        .filter(|c| *c != '-')
        .collect();
    if normalized.len() != 8
        || !normalized
            .bytes()
            .all(|byte| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&byte))
    {
        return false;
    }
    let expected: [u8; KEY_LEN] = match hex_decode_key(hash_hex) {
        Some(e) => e,
        None => return false,
    };
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

fn load_state(path: &str) -> Result<AuthState, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(AuthState::default())
                }
                _ => Err("cannot read auth state file".to_string()),
            };
        }
        Err(_) => return Err("cannot read auth state file".to_string()),
    };
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| "invalid auth state JSON".to_string())?;
    if !json.is_object() {
        return Err("invalid auth state JSON".to_string());
    }
    let state: AuthState =
        serde_json::from_str(&text).map_err(|_| "invalid auth state JSON".to_string())?;
    let valid_hex = |value: &str, len: usize| {
        value.len() == len * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    match (&state.password_salt, &state.password_key) {
        (None, None) => return Err("auth state is missing a password".to_string()),
        (Some(salt), Some(key)) if valid_hex(salt, SALT_LEN) && valid_hex(key, KEY_LEN) => {}
        _ => return Err("invalid auth password state".to_string()),
    }
    if let Some(secret) = &state.totp_secret {
        if !secret.is_ascii() {
            return Err("invalid auth TOTP secret".to_string());
        }
        let decoded = crate::totp::base32_decode(secret)
            .map_err(|_| "invalid auth TOTP secret".to_string())?;
        let normalized: String = secret
            .chars()
            .filter(|&c| c != ' ' && c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if decoded.is_empty() || crate::totp::base32_encode(&decoded) != normalized {
            return Err("invalid auth TOTP secret".to_string());
        }
    }
    if !state.backup_code_hashes.is_empty() && !state.totp_enabled() {
        return Err("auth recovery codes require TOTP".to_string());
    }
    if state
        .backup_code_hashes
        .iter()
        .any(|hash| !valid_hex(hash, KEY_LEN))
    {
        return Err("invalid auth recovery hash".to_string());
    }
    Ok(state)
}

fn save_state(path: &str, state: &AuthState) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|_| "cannot create data dir".to_string())?;
        }
    }
    let tmp = format!("{path}.{}.tmp", hex(&random_bytes::<16>()));
    let json = serde_json::to_string_pretty(state)
        .map_err(|_| "cannot serialize auth state".to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|_| "cannot create auth state file".to_string())?;
    let result = (|| {
        file.write_all(json.as_bytes())
            .map_err(|_| "cannot write auth state file".to_string())?;
        file.sync_all()
            .map_err(|_| "cannot sync auth state file".to_string())?;
        std::fs::rename(&tmp, path).map_err(|_| "cannot save auth state file".to_string())
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn hex_decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
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
        if entry.1.elapsed() >= LOGIN_LOCKOUT {
            entry.0 = 0;
        }
        entry.0 = entry.0.saturating_add(1);
        entry.1 = Instant::now();
    }

    pub fn record_success(&self, ip: IpAddr) {
        self.state.lock().unwrap().remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestState {
        dir: std::path::PathBuf,
        path: String,
    }

    impl TestState {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "cfddns-auth-test-{}-{}",
                std::process::id(),
                hex(&random_bytes::<8>())
            ));
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("state.json").to_str().unwrap().to_string();
            Self { dir, path }
        }

        fn write(&self, contents: impl AsRef<[u8]>) {
            std::fs::write(&self.path, contents).unwrap();
        }

        fn load(&self) -> Result<Auth, String> {
            Auth::new(Duration::from_secs(60), &self.path)
        }
    }

    impl Drop for TestState {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn configured_auth(file: &TestState) -> Auth {
        let auth = file.load().unwrap();
        auth.setup_password("synthetic-password").unwrap();
        auth
    }

    fn enrolled_auth(file: &TestState) -> (Auth, Vec<String>) {
        let auth = configured_auth(file);
        let (secret, _, _) = auth.totp_enroll_begin().unwrap();
        let code = format!(
            "{:06}",
            crate::totp::totp_at(&crate::totp::base32_decode(&secret).unwrap(), now_secs())
        );
        let codes = auth.totp_enroll_confirm(&code).unwrap();
        (auth, codes)
    }

    fn block_saves(file: &TestState) -> Vec<u8> {
        let saved = std::fs::read(&file.path).unwrap();
        std::fs::remove_file(&file.path).unwrap();
        std::fs::create_dir(&file.path).unwrap();
        saved
    }

    fn restore_saves(file: &TestState, saved: Vec<u8>) {
        std::fs::remove_dir(&file.path).unwrap();
        file.write(saved);
    }

    #[test]
    fn security_setup_failure_is_transactional() {
        let file = TestState::new();
        let auth = file.load().unwrap();
        std::fs::create_dir(&file.path).unwrap();
        assert!(auth.setup_password("synthetic-password").is_err());
        assert!(!auth.is_configured());
        std::fs::remove_dir(&file.path).unwrap();
        auth.setup_password("synthetic-password").unwrap();
        assert!(file.load().unwrap().verify_password("synthetic-password"));
    }

    #[test]
    fn security_password_failure_preserves_identity_and_sessions() {
        let file = TestState::new();
        let auth = configured_auth(&file);
        let session = auth.create_session();
        let saved = block_saves(&file);
        assert!(auth.change_password("replacement-password").is_err());
        assert!(auth.verify_password("synthetic-password"));
        assert!(!auth.verify_password("replacement-password"));
        assert!(auth.session_valid(&session));
        restore_saves(&file, saved);
        assert!(file.load().unwrap().verify_password("synthetic-password"));
    }

    #[test]
    fn security_enrollment_failure_preserves_pending_secret() {
        let file = TestState::new();
        let auth = configured_auth(&file);
        let (secret, _, _) = auth.totp_enroll_begin().unwrap();
        let code = format!(
            "{:06}",
            crate::totp::totp_at(&crate::totp::base32_decode(&secret).unwrap(), now_secs())
        );
        let saved = block_saves(&file);
        assert!(auth.totp_enroll_confirm(&code).is_err());
        assert!(!auth.totp_enabled());
        assert_eq!(auth.backup_codes_remaining(), 0);
        assert!(auth.pending_totp.lock().unwrap().is_some());
        restore_saves(&file, saved);
        assert!(!file.load().unwrap().totp_enabled());
        assert_eq!(
            auth.totp_enroll_confirm(&code).unwrap().len(),
            BACKUP_CODE_COUNT
        );
        assert!(file.load().unwrap().totp_enabled());
    }

    #[test]
    fn security_disable_failure_preserves_factors() {
        let file = TestState::new();
        let (auth, _) = enrolled_auth(&file);
        let saved = block_saves(&file);
        assert!(auth.totp_disable().is_err());
        assert!(auth.totp_enabled());
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        restore_saves(&file, saved);
        let restarted = file.load().unwrap();
        assert!(restarted.totp_enabled());
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT);
    }

    #[test]
    fn security_login_recovery_save_failure_denies_and_preserves_code() {
        let file = TestState::new();
        let (auth, codes) = enrolled_auth(&file);
        let ip = "127.0.0.1".parse().unwrap();
        let challenge = auth.login_step1(ip, "synthetic-password").unwrap().unwrap();
        let saved = block_saves(&file);
        for _ in 0..=MAX_2FA_ATTEMPTS {
            assert!(matches!(
                auth.login_step2(ip, &challenge, &codes[0]),
                Err("persistence_failed")
            ));
        }
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        restore_saves(&file, saved);
        let restarted = file.load().unwrap();
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT);
        assert!(auth.login_step2(ip, &challenge, &codes[0]).is_ok());
        let restarted = file.load().unwrap();
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT - 1);
        assert!(!restarted.try_consume_backup_code(&codes[0]));
    }

    #[test]
    fn security_sensitive_recovery_save_failure_denies_and_preserves_code() {
        let file = TestState::new();
        let (auth, codes) = enrolled_auth(&file);
        let saved = block_saves(&file);
        assert!(!auth.try_consume_backup_code(&codes[0]));
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        restore_saves(&file, saved);
        assert!(auth.try_consume_backup_code(&codes[0].to_lowercase().replace('-', " ")));
        let restarted = file.load().unwrap();
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT - 1);
        assert!(!restarted.try_consume_backup_code(&codes[0]));
        assert!(restarted.try_consume_backup_code(&codes[1]));
    }

    #[test]
    fn security_password_change_revokes_pending_challenges_and_enrollment() {
        let file = TestState::new();
        let (auth, _) = enrolled_auth(&file);
        let ip = "127.0.0.1".parse().unwrap();
        let challenge = auth.login_step1(ip, "synthetic-password").unwrap().unwrap();
        let secret =
            crate::totp::base32_decode(auth.state.lock().unwrap().totp_secret.as_ref().unwrap())
                .unwrap();
        auth.change_password("replacement-password").unwrap();
        let code = format!("{:06}", crate::totp::totp_at(&secret, now_secs()));
        assert!(matches!(
            auth.login_step2(ip, &challenge, &code),
            Err("challenge_expired")
        ));
        auth.totp_disable().unwrap();
        auth.totp_enroll_begin().unwrap();
        auth.change_password("another-password").unwrap();
        assert!(auth.pending_totp.lock().unwrap().is_none());
    }

    #[test]
    fn security_factor_lockout_spans_challenges_and_addresses() {
        let file = TestState::new();
        let (auth, codes) = enrolled_auth(&file);
        let challenges: Vec<_> = (0..=MAX_2FA_ATTEMPTS)
            .map(|i| {
                let ip = IpAddr::from([127, 0, 0, i as u8 + 1]);
                (
                    ip,
                    auth.login_step1(ip, "synthetic-password").unwrap().unwrap(),
                )
            })
            .collect();
        for (ip, challenge) in challenges.iter().take(MAX_2FA_ATTEMPTS as usize) {
            assert!(matches!(
                auth.login_step2(*ip, challenge, "invalid"),
                Err("invalid_code")
            ));
        }
        let (ip, challenge) = challenges.last().unwrap();
        assert!(matches!(
            auth.login_step2(*ip, challenge, &codes[0]),
            Err("locked_out")
        ));
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
    }

    #[test]
    fn security_sensitive_recovery_respects_factor_lockout() {
        let file = TestState::new();
        let (auth, codes) = enrolled_auth(&file);
        for _ in 0..MAX_2FA_ATTEMPTS {
            assert!(!auth.try_consume_backup_code("invalid"));
        }
        assert!(!auth.try_consume_backup_code(&codes[0]));
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
    }

    #[test]
    fn security_verified_password_mutation_preserves_recovery_on_save_failure() {
        let file = TestState::new();
        let (auth, codes) = enrolled_auth(&file);
        let ip = "127.0.0.1".parse().unwrap();
        let session = auth.create_session();
        let challenge = auth.login_step1(ip, "synthetic-password").unwrap().unwrap();
        let saved = block_saves(&file);
        assert_eq!(
            auth.change_password_verified(
                ip,
                "synthetic-password",
                Some(&codes[0]),
                "replacement-password"
            )
            .unwrap_err(),
            "persistence_failed"
        );
        assert!(auth.verify_password("synthetic-password"));
        assert!(auth.session_valid(&session));
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        assert!(auth.challenges.lock().unwrap().contains_key(&challenge));
        restore_saves(&file, saved);
        auth.change_password_verified(
            ip,
            "synthetic-password",
            Some(&codes[0]),
            "replacement-password",
        )
        .unwrap();
        assert!(!auth.session_valid(&session));
        assert!(auth.challenges.lock().unwrap().is_empty());
        let restarted = file.load().unwrap();
        assert!(restarted.verify_password("replacement-password"));
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT - 1);
        assert!(!restarted.try_consume_backup_code(&codes[0]));
    }

    #[test]
    fn security_verified_disable_preserves_factors_on_save_failure() {
        let file = TestState::new();
        let (auth, codes) = enrolled_auth(&file);
        let ip = "127.0.0.1".parse().unwrap();
        let session = auth.create_session();
        let saved = block_saves(&file);
        assert!(matches!(
            auth.totp_disable_verified(ip, &codes[0]),
            Err("persistence_failed")
        ));
        assert!(auth.totp_enabled());
        assert!(auth.session_valid(&session));
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        restore_saves(&file, saved);
        auth.totp_disable_verified(ip, &codes[0]).unwrap();
        assert!(!auth.session_valid(&session));
        assert!(!file.load().unwrap().totp_enabled());
        assert_eq!(file.load().unwrap().backup_codes_remaining(), 0);
    }

    #[test]
    fn security_sensitive_factor_lockout_blocks_totp_and_recovery() {
        let file = TestState::new();
        let (auth, codes) = enrolled_auth(&file);
        for index in 1..=MAX_2FA_ATTEMPTS {
            let ip = IpAddr::from([127, 0, 0, index as u8]);
            assert!(matches!(
                auth.totp_disable_verified(ip, "invalid"),
                Err("invalid_code")
            ));
        }
        let ip = "127.0.0.20".parse().unwrap();
        let secret =
            crate::totp::base32_decode(auth.state.lock().unwrap().totp_secret.as_ref().unwrap())
                .unwrap();
        let code = format!("{:06}", crate::totp::totp_at(&secret, now_secs()));
        assert!(matches!(
            auth.totp_disable_verified(ip, &code),
            Err("locked_out")
        ));
        assert_eq!(
            auth.change_password_verified(
                ip,
                "synthetic-password",
                Some(&codes[0]),
                "replacement-password"
            )
            .unwrap_err(),
            "locked_out"
        );
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        *auth.factor_failures.lock().unwrap() = (MAX_2FA_ATTEMPTS, Instant::now() - LOGIN_LOCKOUT);
        auth.totp_disable_verified(ip, &code).unwrap();
    }

    #[test]
    fn security_enrollment_requires_password_and_shares_lockout() {
        let file = TestState::new();
        let auth = configured_auth(&file);
        let ip = "127.0.0.1".parse().unwrap();
        assert!(auth
            .totp_enroll_begin_verified(ip, "wrong-password")
            .is_err());
        assert!(auth.pending_totp.lock().unwrap().is_none());
        let (secret, _, _) = auth
            .totp_enroll_begin_verified(ip, "synthetic-password")
            .unwrap();
        let code = format!(
            "{:06}",
            crate::totp::totp_at(&crate::totp::base32_decode(&secret).unwrap(), now_secs())
        );
        for _ in 1..MAX_2FA_ATTEMPTS {
            assert!(auth.totp_enroll_confirm("invalid").is_err());
        }
        assert_eq!(auth.totp_enroll_confirm(&code).unwrap_err(), "locked_out");
        assert_eq!(
            auth.totp_enroll_begin_verified(ip, "synthetic-password")
                .unwrap_err(),
            "locked_out"
        );
        *auth.factor_failures.lock().unwrap() = (MAX_2FA_ATTEMPTS, Instant::now() - LOGIN_LOCKOUT);
        let session = auth.create_session();
        auth.totp_enroll_confirm(&code).unwrap();
        assert!(!auth.session_valid(&session));
        assert!(auth.pending_totp.lock().unwrap().is_none());
    }

    #[test]
    fn security_concurrent_recovery_consumption_is_single_use() {
        let file = TestState::new();
        let (auth, codes) = enrolled_auth(&file);
        let ip = "127.0.0.1".parse().unwrap();
        let challenge = auth.login_step1(ip, "synthetic-password").unwrap().unwrap();
        let barrier = std::sync::Barrier::new(2);
        let successes = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..2)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        auth.login_step2(ip, &challenge, &codes[0]).is_ok()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|success| *success)
                .count()
        });
        assert_eq!(successes, 1);
        assert_eq!(
            file.load().unwrap().backup_codes_remaining(),
            BACKUP_CODE_COUNT - 1
        );
    }

    #[test]
    fn security_sessions_are_issued_before_revocation_can_race() {
        let file = TestState::new();
        let auth = file.load().unwrap();
        let ip = "127.0.0.1".parse().unwrap();
        let setup_session = auth.setup_password_session("synthetic-password").unwrap();
        let barrier = std::sync::Barrier::new(2);
        let (login, changed_session) = std::thread::scope(|scope| {
            let login = scope.spawn(|| {
                barrier.wait();
                auth.login_step1_session(ip, "synthetic-password")
            });
            let change = scope.spawn(|| {
                barrier.wait();
                auth.change_password_verified(
                    ip,
                    "synthetic-password",
                    None,
                    "replacement-password",
                )
            });
            (login.join().unwrap(), change.join().unwrap().unwrap())
        });
        if let Ok(LoginStep1Outcome::Session(token)) = login {
            assert!(!auth.session_valid(&token));
        }
        assert!(!auth.session_valid(&setup_session));
        assert!(auth.session_valid(&changed_session));
        let (secret, _, _) = auth
            .totp_enroll_begin_verified(ip, "replacement-password")
            .unwrap();
        let code = format!(
            "{:06}",
            crate::totp::totp_at(&crate::totp::base32_decode(&secret).unwrap(), now_secs())
        );
        let (codes, enrolled_session) = auth.totp_enroll_confirm_session(&code).unwrap();
        assert!(!auth.session_valid(&changed_session));
        assert!(auth.session_valid(&enrolled_session));
        let challenge = match auth
            .login_step1_session(ip, "replacement-password")
            .unwrap()
        {
            LoginStep1Outcome::Challenge(challenge) => challenge,
            LoginStep1Outcome::Session(_) => panic!("2FA must require a challenge"),
        };
        let (_, factor_session) = auth.login_step2_session(ip, &challenge, &codes[0]).unwrap();
        assert!(auth.session_valid(&factor_session));
        let disabled_session = auth.totp_disable_verified(ip, &codes[1]).unwrap();
        assert!(!auth.session_valid(&factor_session));
        assert!(!auth.session_valid(&enrolled_session));
        assert!(auth.session_valid(&disabled_session));
        assert!(!file.load().unwrap().session_valid(&disabled_session));
    }

    #[cfg(unix)]
    #[test]
    fn security_saved_credentials_have_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let file = TestState::new();
        let auth = configured_auth(&file);
        assert_eq!(
            std::fs::metadata(&file.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        auth.change_password("replacement-password").unwrap();
        assert_eq!(
            std::fs::metadata(&file.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(&file.dir).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn security_temp_file_cannot_follow_attacker_symlink() {
        let file = TestState::new();
        let auth = file.load().unwrap();
        let victim = file.dir.join("synthetic-victim");
        std::fs::write(&victim, "unchanged").unwrap();
        std::os::unix::fs::symlink(&victim, format!("{}.tmp", file.path)).unwrap();
        auth.setup_password("synthetic-password").unwrap();
        assert_eq!(std::fs::read_to_string(victim).unwrap(), "unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn security_failed_save_leaves_no_readable_credentials() {
        use std::os::unix::fs::PermissionsExt;
        let file = TestState::new();
        let auth = file.load().unwrap();
        std::fs::create_dir(&file.path).unwrap();
        assert!(auth.setup_password("synthetic-password").is_err());
        for entry in std::fs::read_dir(&file.dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                assert_eq!(entry.metadata().unwrap().permissions().mode() & 0o077, 0);
                panic!("failed save must clean up its temporary credential file");
            }
        }
    }

    #[test]
    fn startup_missing_file_allows_setup() {
        let file = TestState::new();
        let auth = file.load().unwrap();
        assert!(!auth.is_configured());
        assert!(!auth.totp_enabled());
        assert_eq!(auth.backup_codes_remaining(), 0);
        assert!(!std::path::Path::new(&file.path).exists());
    }

    #[test]
    fn startup_preserves_optional_schema_defaults() {
        let file = TestState::new();
        let salt = [0xab; SALT_LEN];
        file.write(
            serde_json::json!({
                "password_salt": hex(&salt).to_uppercase(),
                "password_key": hex(&derive_key("synthetic-password", &salt)).to_uppercase()
            })
            .to_string(),
        );
        let auth = file.load().unwrap();
        assert!(auth.verify_password("synthetic-password"));
        assert!(!auth.totp_enabled());
    }

    #[test]
    fn startup_accepts_valid_totp_with_exhausted_recovery_codes() {
        let file = TestState::new();
        let secret = b"synthetic totp key";
        let salt = [0xab; SALT_LEN];
        file.write(serde_json::json!({
            "password_salt": hex(&salt),
            "password_key": hex(&derive_key("synthetic-password", &salt)),
            "totp_secret": format!(" {}=== ", crate::totp::base32_encode(secret).to_lowercase()),
            "backup_code_hashes": []
        }).to_string());
        let auth = file.load().unwrap();
        assert!(auth.totp_enabled());
        assert_eq!(auth.backup_codes_remaining(), 0);
        let ip = "127.0.0.1".parse().unwrap();
        let challenge = auth.login_step1(ip, "synthetic-password").unwrap().unwrap();
        let code = format!("{:06}", crate::totp::totp_at(secret, now_secs()));
        assert!(matches!(
            auth.login_step2(ip, &challenge, &code),
            Ok(Login2faOutcome::Totp)
        ));
    }

    #[test]
    fn startup_rejects_malformed_state() {
        let file = TestState::new();
        for contents in [
            "",
            "{",
            "null",
            "[]",
            r#"{"password_salt":42}"#,
            r#"{"backup_code_hashes":null}"#,
            r#"{"backup_code_hashes":"redaction-marker"}"#,
            r#"{"password_salt":"redaction-marker",}"#,
            r#"{"password_salt":null,"password_salt":null}"#,
        ] {
            file.write(contents);
            let error = file.load().err().expect("invalid JSON must fail startup");
            assert!(!error.contains("redaction-marker"));
        }
        file.write([0xff]);
        assert!(file.load().is_err());
    }

    #[test]
    fn startup_rejects_incomplete_password() {
        let file = TestState::new();
        for state in [
            serde_json::json!({}),
            serde_json::json!({"unrelated": true}),
            serde_json::to_value(AuthState::default()).unwrap(),
            serde_json::json!({"password_salt": hex(&[0; SALT_LEN])}),
            serde_json::json!({"password_key": hex(&[0; KEY_LEN])}),
        ] {
            file.write(state.to_string());
            assert!(file.load().is_err());
        }
    }

    #[test]
    fn startup_rejects_invalid_password_hex() {
        let file = TestState::new();
        for field in ["password_salt", "password_key"] {
            let len = if field == "password_salt" {
                SALT_LEN
            } else {
                KEY_LEN
            };
            for value in [
                String::new(),
                "0".repeat(len * 2 - 1),
                "0".repeat(len * 2 + 2),
                "g".repeat(len * 2),
                "\u{e9}".repeat(len),
                "+0".repeat(len),
            ] {
                let mut state = serde_json::json!({
                    "password_salt": hex(&[0; SALT_LEN]),
                    "password_key": hex(&[0; KEY_LEN])
                });
                state[field] = value.into();
                file.write(state.to_string());
                assert!(file.load().is_err());
            }
        }
    }

    #[test]
    fn startup_rejects_inconsistent_totp_state() {
        let file = TestState::new();
        let secret = crate::totp::base32_encode(&[0; TOTP_SECRET_LEN]);
        for state in [
            serde_json::json!({"totp_secret": secret}),
            serde_json::json!({"backup_code_hashes": [hex(&[0; KEY_LEN])]}),
            serde_json::json!({
                "password_salt": hex(&[0; SALT_LEN]),
                "password_key": hex(&[0; KEY_LEN]),
                "backup_code_hashes": [hex(&[0; KEY_LEN])]
            }),
        ] {
            file.write(state.to_string());
            assert!(file.load().is_err());
        }
        for secret in ["", " = ", "A", "invalid!", "AA\u{141}"] {
            file.write(
                serde_json::json!({
                    "password_salt": hex(&[0; SALT_LEN]),
                    "password_key": hex(&[0; KEY_LEN]),
                    "totp_secret": secret
                })
                .to_string(),
            );
            let error = file.load().err().expect("invalid TOTP must fail startup");
            assert!(!error.contains(secret) || secret.is_empty());
        }
    }

    #[test]
    fn startup_rejects_invalid_recovery_hashes() {
        let file = TestState::new();
        for hash in [
            "",
            "ab",
            &"0".repeat(KEY_LEN * 2 + 2),
            &"g".repeat(KEY_LEN * 2),
            &"+0".repeat(KEY_LEN),
        ] {
            file.write(
                serde_json::json!({
                    "password_salt": hex(&[0; SALT_LEN]),
                    "password_key": hex(&[0; KEY_LEN]),
                    "totp_secret": crate::totp::base32_encode(&[0; TOTP_SECRET_LEN]),
                    "backup_code_hashes": [hex(&[0; KEY_LEN]), hash]
                })
                .to_string(),
            );
            assert!(file.load().is_err());
        }
    }

    #[test]
    fn startup_rejects_directory_read_failure() {
        let file = TestState::new();
        std::fs::create_dir(&file.path).unwrap();
        assert!(file.load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn startup_rejects_dangling_state_symlink() {
        let file = TestState::new();
        std::os::unix::fs::symlink("missing-state-target", &file.path).unwrap();
        assert!(file.load().is_err());
    }

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
        let file = TestState::new();
        let auth = file.load().unwrap();
        assert!(!auth.is_configured());
        auth.setup_password("super-secret-password").unwrap();
        assert!(auth.is_configured());
        assert!(auth.verify_password("super-secret-password"));
        assert!(!auth.verify_password("wrong-password"));
        let auth2 = file.load().unwrap();
        assert!(auth2.is_configured());
        assert!(auth2.verify_password("super-secret-password"));
    }

    #[test]
    fn totp_enrollment_flow() {
        let file = TestState::new();
        let auth = file.load().unwrap();
        auth.setup_password("super-secret-password").unwrap();
        let (_secret_b32, uri, qr) = auth.totp_enroll_begin().unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(qr.is_some());
        let pending = auth
            .pending_totp
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .secret
            .clone();
        let code = format!("{:06}", crate::totp::totp_at(&pending, now_secs()));
        let backup = auth.totp_enroll_confirm(&code).unwrap();
        assert_eq!(backup.len(), BACKUP_CODE_COUNT);
        assert!(auth.totp_enabled());
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let challenge = auth.login_step1(ip, "super-secret-password").unwrap();
        assert!(challenge.is_some());
        let outcome = auth
            .login_step2(ip, &challenge.unwrap(), &backup[0])
            .unwrap();
        match outcome {
            Login2faOutcome::BackupCode { remaining } => {
                assert_eq!(remaining, BACKUP_CODE_COUNT - 1)
            }
            _ => panic!("expected backup code outcome"),
        }
        drop(auth);
        let restarted = file.load().unwrap();
        assert!(restarted.verify_password("super-secret-password"));
        assert!(restarted.totp_enabled());
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT - 1);
        let challenge = restarted
            .login_step1(ip, "super-secret-password")
            .unwrap()
            .unwrap();
        assert!(restarted.login_step2(ip, &challenge, &backup[0]).is_err());
        assert!(matches!(
            restarted.login_step2(ip, &challenge, &backup[1]),
            Ok(Login2faOutcome::BackupCode { remaining: 6 })
        ));
    }
}
