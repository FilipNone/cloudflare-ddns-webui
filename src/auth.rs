//! Authentication state: password verification (PBKDF2 via `ring`), TOTP
//! two-factor with one-time backup codes, pending-login challenges, in-memory
//! sessions, per-IP login rate limiting, and an account-wide lockout after
//! repeated second-factor failures.
//!
//! The credential hash is kept in a small JSON state file under a data volume
//! so container restarts do not lock the admin out. Passwords and backup
//! codes are only ever stored as PBKDF2 hashes; the TOTP secret is stored
//! base32-encoded (a hard requirement of TOTP itself).
//!
//! PBKDF2 is slow on purpose, so the HTTP layer calls the hashing methods
//! through `spawn_blocking`.

use crate::persist::SaveOutcome;
use crate::pp::PP;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// The unwrap runs at compile time, so a zero count fails the build.
const PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(100_000).unwrap();
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const SESSION_TOKEN_LEN: usize = 32;
const CHALLENGE_TOKEN_LEN: usize = 32;
const TOTP_SECRET_LEN: usize = 20; // 160-bit, standard
const MIN_TOTP_SECRET_LEN: usize = 16; // RFC 4226 R6: at least 128 bits
const BACKUP_CODE_COUNT: usize = 8;
const BACKUP_CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32

const MAX_LOGIN_FAILURES: u32 = 5;
const LOGIN_LOCKOUT: Duration = Duration::from_secs(5 * 60);
const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_2FA_ATTEMPTS: u32 = 5;
const MAX_LIMITER_ENTRIES: usize = 10_000;

/// Why an authentication call failed. `message` is the text the API sends
/// back, which the web UI shows as is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    LockedOut,
    InvalidPassword,
    InvalidCode,
    CodeAlreadyUsed,
    ChallengeExpired,
    PersistenceFailed,
    Internal,
    NotConfigured,
    AlreadyConfigured,
    TotpAlreadyEnabled,
    TotpNotEnabled,
    EnrollmentExpired,
    EnrollmentCodeRejected,
    PasswordTooShort,
    PasswordTooLong,
}

impl AuthError {
    pub fn message(self) -> &'static str {
        match self {
            AuthError::LockedOut => "locked_out",
            AuthError::InvalidPassword => "invalid_password",
            AuthError::InvalidCode => "invalid_code",
            AuthError::CodeAlreadyUsed => "this code was already used - wait for the next one",
            AuthError::ChallengeExpired => "challenge_expired",
            AuthError::PersistenceFailed => "persistence_failed",
            AuthError::Internal => "internal_error",
            AuthError::NotConfigured => "not_configured",
            AuthError::AlreadyConfigured => "already configured",
            AuthError::TotpAlreadyEnabled => "2FA is already enabled",
            AuthError::TotpNotEnabled => "not_enabled",
            AuthError::EnrollmentExpired => "enrollment expired - start again",
            AuthError::EnrollmentCodeRejected => {
                "invalid code - check your authenticator and try again"
            }
            AuthError::PasswordTooShort => "password must be at least 8 characters long",
            AuthError::PasswordTooLong => "password is too long",
        }
    }
}

// --- Hashing ---

fn derive_key(secret: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        PBKDF2_ITERATIONS,
        salt,
        secret.as_bytes(),
        &mut key,
    );
    key
}

fn key_matches(secret: &str, salt: &[u8], expected: &[u8]) -> bool {
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        PBKDF2_ITERATIONS,
        salt,
        secret.as_bytes(),
        expected,
    )
    .is_ok()
}

fn random_bytes<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AuthError::Internal)?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Locks a mutex even if an earlier holder panicked. Release builds abort on
/// panic, so a poisoned lock can only appear in tests.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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

// --- Pending TOTP enrollment ---

struct PendingTotp {
    secret: Vec<u8>,
    expires_at: Instant,
}

/// Login and enrollment state. It only changes while the `flow` lock is
/// held, and that lock stays held from checking a proof to saving its
/// result, so two requests cannot both use one code.
struct Flow {
    /// Pending login challenges (password OK, 2FA pending) and their expiry.
    challenges: HashMap<String, Instant>,
    pending_totp: Option<PendingTotp>,
    /// Failed second-factor attempts from any client, and when the last one
    /// happened.
    factor_failures: (u32, Instant),
    /// Highest TOTP time step accepted for the current secret. It lives in
    /// memory only, so a restart inside the ~90 s window of a used code
    /// forgets it.
    last_totp_step: Option<u64>,
}

impl Flow {
    fn factor_locked_out(&mut self) -> bool {
        if self.factor_failures.1.elapsed() >= LOGIN_LOCKOUT {
            self.factor_failures.0 = 0;
        }
        self.factor_failures.0 >= MAX_2FA_ATTEMPTS
    }
}

/// A second factor that passed verification.
enum Factor {
    /// A TOTP code and the time step it belongs to.
    Totp(u64),
    /// Index of the matching backup code hash.
    Backup(usize),
}

impl Factor {
    /// Removes a used backup code from `state`. Returns the TOTP step to
    /// remember, if the factor was a TOTP code.
    fn consume(self, state: &mut AuthState) -> Option<u64> {
        match self {
            Factor::Totp(step) => Some(step),
            Factor::Backup(index) => {
                state.backup_code_hashes.remove(index);
                None
            }
        }
    }
}

/// Lock order: `flow` first, then `state`, `sessions` or the limiter, each
/// held only briefly.
pub struct Auth {
    state: Mutex<AuthState>,
    flow: Mutex<Flow>,
    sessions: Mutex<HashMap<String, Instant>>,
    limiter: LoginLimiter,
    session_ttl: Duration,
    state_path: String,
    pp: PP,
}

impl Auth {
    pub fn new(session_ttl: Duration, state_path: &str, pp: PP) -> Result<Self, String> {
        let state = load_state(state_path)?;
        crate::persist::remove_temp_files(std::path::Path::new(state_path));
        Ok(Auth {
            state: Mutex::new(state),
            flow: Mutex::new(Flow {
                challenges: HashMap::new(),
                pending_totp: None,
                factor_failures: (0, Instant::now()),
                last_totp_step: None,
            }),
            sessions: Mutex::new(HashMap::new()),
            limiter: LoginLimiter::new(),
            session_ttl,
            state_path: state_path.to_string(),
            pp,
        })
    }

    fn snapshot(&self) -> AuthState {
        lock(&self.state).clone()
    }

    // Callers hold the flow lock, which keeps saves in order. The state lock
    // is only taken for the swap, so readers never wait for disk I/O.
    fn commit_state(&self, candidate: AuthState) -> Result<(), AuthError> {
        match save_state(&self.state_path, &candidate) {
            Ok(SaveOutcome::Durable) => {}
            Ok(SaveOutcome::DirectoryNotSynced) => self.pp.warningf(
                crate::pp::EMOJI_LOCK,
                "Saved auth state, but could not sync the data directory; a power loss may undo the change",
            ),
            Err(error) => {
                self.pp.errorf(
                    crate::pp::EMOJI_ERROR,
                    format!("Cannot save auth state: {error}"),
                );
                return Err(AuthError::PersistenceFailed);
            }
        }
        *lock(&self.state) = candidate;
        Ok(())
    }

    fn revoke_authentication(&self, flow: &mut Flow) {
        lock(&self.sessions).clear();
        flow.challenges.clear();
        flow.pending_totp = None;
    }

    fn check_lockout(&self, flow: &mut Flow, ip: Option<IpAddr>) -> Result<(), AuthError> {
        if flow.factor_locked_out() || ip.is_some_and(|ip| self.limiter.is_locked_out(ip)) {
            return Err(AuthError::LockedOut);
        }
        Ok(())
    }

    fn factor_failure(&self, flow: &mut Flow, ip: Option<IpAddr>) {
        let (count, last) = &mut flow.factor_failures;
        if last.elapsed() >= LOGIN_LOCKOUT {
            *count = 0;
        }
        *count = count.saturating_add(1);
        *last = Instant::now();
        if let Some(ip) = ip {
            self.limiter.record_failure(ip);
        }
    }

    fn factor_success(&self, flow: &mut Flow, ip: Option<IpAddr>) {
        flow.factor_failures = (0, Instant::now());
        if let Some(ip) = ip {
            self.limiter.record_success(ip);
        }
    }

    // The flow lock covers proof verification through the persisted mutation.
    // Callers check the lockout first.
    fn verify_factor(
        &self,
        flow: &mut Flow,
        ip: IpAddr,
        code: &str,
        state: &AuthState,
    ) -> Result<Factor, AuthError> {
        let code = normalize_code(code);
        let secret = state
            .totp_secret
            .as_deref()
            .and_then(|secret| crate::totp::base32_decode(secret).ok());
        if let Some(step) =
            secret.and_then(|secret| crate::totp::totp_verify(&secret, &code, now_secs()))
        {
            // RFC 6238 section 5.2: each code is accepted only once.
            if flow.last_totp_step.is_none_or(|last| step > last) {
                return Ok(Factor::Totp(step));
            }
            // The code was right, just used already, so it is not a guess and
            // does not count toward the lockout. Usually the user typed the
            // code still on screen right after logging in.
            return Err(AuthError::CodeAlreadyUsed);
        }
        if let Some(index) = find_backup_code(&state.backup_code_hashes, &code) {
            return Ok(Factor::Backup(index));
        }
        self.factor_failure(flow, Some(ip));
        Err(AuthError::InvalidCode)
    }

    /// Saves a changed identity, signs out every session and pending login,
    /// and issues a new session for the caller.
    fn commit_and_reissue(
        &self,
        flow: &mut Flow,
        ip: Option<IpAddr>,
        candidate: AuthState,
        totp_step: Option<u64>,
    ) -> Result<String, AuthError> {
        self.commit_state(candidate)?;
        if totp_step.is_some() {
            flow.last_totp_step = totp_step;
        }
        self.revoke_authentication(flow);
        self.factor_success(flow, ip);
        self.create_session()
    }

    pub fn is_configured(&self) -> bool {
        lock(&self.state).is_configured()
    }

    pub fn totp_enabled(&self) -> bool {
        lock(&self.state).totp_enabled()
    }

    /// True when some backup codes still use the unsalted hash format from
    /// older versions.
    pub fn has_legacy_backup_hashes(&self) -> bool {
        lock(&self.state)
            .backup_code_hashes
            .iter()
            .any(|hash| !hash.contains(':'))
    }

    // --- First-run setup / password changes ---

    /// Set the password on first run and sign the caller in.
    pub fn setup_password_session(&self, password: &str) -> Result<String, AuthError> {
        validate_password(password)?;
        let _flow = lock(&self.flow);
        let mut candidate = self.snapshot();
        if candidate.is_configured() {
            return Err(AuthError::AlreadyConfigured);
        }
        set_password(&mut candidate, password)?;
        self.commit_state(candidate)?;
        self.create_session()
    }

    pub fn change_password_verified(
        &self,
        ip: IpAddr,
        current_password: &str,
        code: Option<&str>,
        new_password: &str,
    ) -> Result<String, AuthError> {
        validate_password(new_password)?;
        let mut flow = lock(&self.flow);
        self.check_lockout(&mut flow, Some(ip))?;
        if !self.verify_password(current_password) {
            self.factor_failure(&mut flow, Some(ip));
            return Err(AuthError::InvalidPassword);
        }
        let mut candidate = self.snapshot();
        let totp_step = if candidate.totp_enabled() {
            self.verify_factor(&mut flow, ip, code.unwrap_or(""), &candidate)?
                .consume(&mut candidate)
        } else {
            None
        };
        set_password(&mut candidate, new_password)?;
        self.commit_and_reissue(&mut flow, Some(ip), candidate, totp_step)
    }

    fn verify_password(&self, password: &str) -> bool {
        if password.len() > 256 {
            return false;
        }
        // Copy the hash out so the slow derivation runs without the state lock.
        let stored = {
            let state = lock(&self.state);
            state
                .password_salt
                .as_deref()
                .and_then(hex_decode_salt)
                .zip(state.password_key.as_deref().and_then(hex_decode_key))
        };
        stored.is_some_and(|(salt, key)| key_matches(password, &salt, &key))
    }

    // --- Login flow ---

    pub fn limiter(&self) -> &LoginLimiter {
        &self.limiter
    }

    /// Step 1: password. Returns a session when no 2FA is needed, or a
    /// challenge token when a second factor is required.
    pub fn login_step1_session(
        &self,
        ip: IpAddr,
        password: &str,
    ) -> Result<LoginStep1Outcome, AuthError> {
        let mut flow = lock(&self.flow);
        self.check_lockout(&mut flow, Some(ip))?;
        if !self.verify_password(password) {
            self.limiter.record_failure(ip);
            return Err(AuthError::InvalidPassword);
        }
        if !self.totp_enabled() {
            self.limiter.record_success(ip);
            return Ok(LoginStep1Outcome::Session(self.create_session()?));
        }
        let token = hex(&random_bytes::<CHALLENGE_TOKEN_LEN>()?);
        let now = Instant::now();
        flow.challenges.retain(|_, expires_at| *expires_at > now);
        flow.challenges.insert(token.clone(), now + CHALLENGE_TTL);
        Ok(LoginStep1Outcome::Challenge(token))
    }

    /// Step 2: TOTP code or backup code for a pending challenge.
    pub fn login_step2_session(
        &self,
        ip: IpAddr,
        challenge_token: &str,
        code: &str,
    ) -> Result<(Login2faOutcome, String), AuthError> {
        let mut flow = lock(&self.flow);
        self.check_lockout(&mut flow, Some(ip))?;
        let valid = flow
            .challenges
            .get(challenge_token)
            .is_some_and(|expires_at| *expires_at > Instant::now());
        if !valid {
            return Err(AuthError::ChallengeExpired);
        }
        let mut candidate = self.snapshot();
        let outcome = match self.verify_factor(&mut flow, ip, code, &candidate)? {
            Factor::Totp(step) => {
                flow.last_totp_step = Some(step);
                Login2faOutcome::Totp
            }
            Factor::Backup(index) => {
                candidate.backup_code_hashes.remove(index);
                let remaining = candidate.backup_code_hashes.len();
                self.commit_state(candidate)?;
                Login2faOutcome::BackupCode { remaining }
            }
        };
        flow.challenges.remove(challenge_token);
        self.factor_success(&mut flow, Some(ip));
        Ok((outcome, self.create_session()?))
    }

    // --- TOTP enrollment ---

    /// Begin enrollment: generates a secret and otpauth URI + QR SVG.
    pub fn totp_enroll_begin_verified(
        &self,
        ip: IpAddr,
        password: &str,
    ) -> Result<(String, String, Option<String>), AuthError> {
        let mut flow = lock(&self.flow);
        self.check_lockout(&mut flow, Some(ip))?;
        if !self.verify_password(password) {
            self.factor_failure(&mut flow, Some(ip));
            return Err(AuthError::InvalidPassword);
        }
        if !self.is_configured() {
            return Err(AuthError::NotConfigured);
        }
        if self.totp_enabled() {
            return Err(AuthError::TotpAlreadyEnabled);
        }
        let secret = random_bytes::<TOTP_SECRET_LEN>()?;
        let secret_b32 = crate::totp::base32_encode(&secret);
        let uri = crate::totp::otpauth_uri(&secret_b32, "Cloudflare DDNS", "admin");
        let qr = crate::totp::qr_svg(&uri);
        flow.pending_totp = Some(PendingTotp {
            secret: secret.to_vec(),
            expires_at: Instant::now() + CHALLENGE_TTL,
        });
        Ok((secret_b32, uri, qr))
    }

    /// Confirm enrollment with the first TOTP code; returns backup codes.
    pub fn totp_enroll_confirm_session(
        &self,
        code: &str,
    ) -> Result<(Vec<String>, String), AuthError> {
        let mut flow = lock(&self.flow);
        self.check_lockout(&mut flow, None)?;
        let secret = flow
            .pending_totp
            .as_ref()
            .filter(|pending| pending.expires_at > Instant::now())
            .map(|pending| pending.secret.clone())
            .ok_or(AuthError::EnrollmentExpired)?;
        let Some(step) = crate::totp::totp_verify(&secret, &normalize_code(code), now_secs())
        else {
            self.factor_failure(&mut flow, None);
            return Err(AuthError::EnrollmentCodeRejected);
        };
        let codes = generate_backup_codes()?;
        let hashes = codes
            .iter()
            .map(|code| hash_backup_code(code))
            .collect::<Result<Vec<_>, _>>()?;
        let mut candidate = self.snapshot();
        candidate.totp_secret = Some(crate::totp::base32_encode(&secret));
        candidate.backup_code_hashes = hashes;
        let session = self.commit_and_reissue(&mut flow, None, candidate, Some(step))?;
        Ok((codes, session))
    }

    pub fn totp_enroll_cancel(&self) {
        lock(&self.flow).pending_totp = None;
    }

    pub fn totp_disable_verified(&self, ip: IpAddr, code: &str) -> Result<String, AuthError> {
        let mut flow = lock(&self.flow);
        let mut candidate = self.snapshot();
        if !candidate.totp_enabled() {
            return Err(AuthError::TotpNotEnabled);
        }
        self.check_lockout(&mut flow, Some(ip))?;
        let totp_step = self
            .verify_factor(&mut flow, ip, code, &candidate)?
            .consume(&mut candidate);
        candidate.totp_secret = None;
        candidate.backup_code_hashes.clear();
        self.commit_and_reissue(&mut flow, Some(ip), candidate, totp_step)
    }

    pub fn backup_codes_remaining(&self) -> usize {
        lock(&self.state).backup_code_hashes.len()
    }

    // --- Sessions ---

    fn create_session(&self) -> Result<String, AuthError> {
        let token = hex(&random_bytes::<SESSION_TOKEN_LEN>()?);
        let mut sessions = lock(&self.sessions);
        let now = Instant::now();
        sessions.retain(|_, exp| *exp > now);
        sessions.insert(token.clone(), now + self.session_ttl);
        Ok(token)
    }

    pub fn session_valid(&self, token: &str) -> bool {
        let mut sessions = lock(&self.sessions);
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
        lock(&self.sessions).remove(token);
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

fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.len() < 8 {
        return Err(AuthError::PasswordTooShort);
    }
    if password.len() > 256 {
        return Err(AuthError::PasswordTooLong);
    }
    Ok(())
}

/// Stores a hash of `password` under a fresh salt.
fn set_password(state: &mut AuthState, password: &str) -> Result<(), AuthError> {
    let salt = random_bytes::<SALT_LEN>()?;
    state.password_salt = Some(hex(&salt));
    state.password_key = Some(hex(&derive_key(password, &salt)));
    Ok(())
}

/// The single rule for typed codes: drop whitespace and dashes, then
/// uppercase ASCII letters. TOTP and backup code checks then require their
/// exact formats, so anything else fails there.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

// --- Backup codes ---

/// Generate 8 codes in the standard XXXX-XXXX format (Crockford base32).
fn generate_backup_codes() -> Result<Vec<String>, AuthError> {
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let bytes = random_bytes::<8>()?;
            let chars: String = bytes
                .iter()
                .map(|b| BACKUP_CODE_ALPHABET[usize::from(b % 32)] as char)
                .collect();
            Ok(format!("{}-{}", &chars[..4], &chars[4..]))
        })
        .collect()
}

/// Salt used by hashes saved before codes had their own random salt. It only
/// exists so those codes keep working; new hashes never use it.
fn legacy_backup_salt(normalized: &str) -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    let h = derive_key(&format!("backup-salt:{normalized}"), b"cfddnswebui-salt");
    s.copy_from_slice(&h[..SALT_LEN]);
    s
}

/// Stored as `<salt hex>:<key hex>` with a fresh random salt for each code.
fn hash_backup_code(code: &str) -> Result<String, AuthError> {
    let salt = random_bytes::<SALT_LEN>()?;
    let key = derive_key(&normalize_code(code), &salt);
    Ok(format!("{}:{}", hex(&salt), hex(&key)))
}

fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Accepts `<salt hex>:<key hex>`, or a bare key hex written by older versions.
fn valid_backup_hash(stored: &str) -> bool {
    match stored.split_once(':') {
        Some((salt, key)) => valid_hex(salt, SALT_LEN) && valid_hex(key, KEY_LEN),
        None => valid_hex(stored, KEY_LEN),
    }
}

/// Returns the index of the stored hash that matches an already normalized
/// code.
fn find_backup_code(hashes: &[String], code: &str) -> Option<usize> {
    if code.len() != 8
        || !code
            .bytes()
            .all(|byte| BACKUP_CODE_ALPHABET.contains(&byte))
    {
        return None;
    }
    // Legacy hashes all derive their salt from the code, so work it out once.
    let mut legacy_salt = None;
    hashes.iter().position(|stored| {
        let (salt, expected) = match stored.split_once(':') {
            Some((salt, key)) => match (hex_decode_salt(salt), hex_decode_key(key)) {
                (Some(salt), Some(key)) => (salt, key),
                _ => return false,
            },
            None => match hex_decode_key(stored) {
                Some(key) => (
                    *legacy_salt.get_or_insert_with(|| legacy_backup_salt(code)),
                    key,
                ),
                None => return false,
            },
        };
        key_matches(code, &salt, &expected)
    })
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
    // Serde's derived struct parser also accepts a JSON array (fields by
    // position), so check for an object first. The typed parse below then
    // rejects duplicate keys, which the generic parse lets through.
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| "invalid auth state JSON".to_string())?;
    if !json.is_object() {
        return Err("invalid auth state JSON".to_string());
    }
    let state: AuthState =
        serde_json::from_str(&text).map_err(|_| "invalid auth state JSON".to_string())?;
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
        if decoded.len() < MIN_TOTP_SECRET_LEN || crate::totp::base32_encode(&decoded) != normalized
        {
            return Err("invalid auth TOTP secret".to_string());
        }
    }
    if !state.backup_code_hashes.is_empty() && !state.totp_enabled() {
        return Err("auth recovery codes require TOTP".to_string());
    }
    if state
        .backup_code_hashes
        .iter()
        .any(|hash| !valid_backup_hash(hash))
    {
        return Err("invalid auth recovery hash".to_string());
    }
    Ok(state)
}

fn save_state(path: &str, state: &AuthState) -> Result<SaveOutcome, String> {
    let json = serde_json::to_string_pretty(state)
        .map_err(|_| "cannot serialize auth state".to_string())?;
    crate::persist::replace_file(std::path::Path::new(path), json.as_bytes())
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

/// Failed password attempts per client, keyed by `limiter_key`.
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
        let mut state = lock(&self.state);
        match state.get(&limiter_key(ip)) {
            Some((fails, since)) => *fails >= MAX_LOGIN_FAILURES && since.elapsed() < LOGIN_LOCKOUT,
            // Only a table full of active lockouts has no room to count a new
            // client, so only then are new clients refused.
            None => !make_room(&mut state),
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let key = limiter_key(ip);
        let mut state = lock(&self.state);
        if !state.contains_key(&key) && !make_room(&mut state) {
            return;
        }
        let now = Instant::now();
        let entry = state.entry(key).or_insert((0, now));
        if now.duration_since(entry.1) >= LOGIN_LOCKOUT {
            entry.0 = 0;
        }
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now;
    }

    pub fn record_success(&self, ip: IpAddr) {
        lock(&self.state).remove(&limiter_key(ip));
    }
}

/// Makes room for one more client once the table reaches its cap, and
/// reports whether there is room. Expired entries go first, then the oldest
/// client that is not locked out. Active lockouts are never dropped, so
/// flooding the table with new addresses cannot lift one.
fn make_room(state: &mut HashMap<IpAddr, (u32, Instant)>) -> bool {
    if state.len() < MAX_LIMITER_ENTRIES {
        return true;
    }
    state.retain(|_, (_, last)| last.elapsed() < LOGIN_LOCKOUT);
    if state.len() < MAX_LIMITER_ENTRIES {
        return true;
    }
    let oldest = state
        .iter()
        .filter(|(_, (fails, _))| *fails < MAX_LOGIN_FAILURES)
        .min_by_key(|(_, (_, last))| *last)
        .map(|(key, _)| *key);
    match oldest {
        Some(key) => state.remove(&key).is_some(),
        None => false,
    }
}

/// IPv6 clients are counted per /64, because one host usually controls a
/// whole /64. IPv4-mapped addresses count as the IPv4 address they carry.
fn limiter_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "synthetic-password";

    struct TestState {
        dir: std::path::PathBuf,
        path: String,
    }

    impl TestState {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "cfddns-auth-test-{}-{}",
                std::process::id(),
                hex(&random_bytes::<8>().unwrap())
            ));
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("state.json").to_str().unwrap().to_string();
            Self { dir, path }
        }

        fn write(&self, contents: impl AsRef<[u8]>) {
            std::fs::write(&self.path, contents).unwrap();
        }

        fn load(&self) -> Result<Auth, String> {
            Auth::new(Duration::from_secs(60), &self.path, PP::new(false, true))
        }
    }

    impl Drop for TestState {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn localhost() -> IpAddr {
        IpAddr::from([127, 0, 0, 1])
    }

    #[test]
    fn security_startup_removes_temp_files_left_by_a_crash() {
        let file = TestState::new();
        let leftover = format!("{}.{}.tmp", file.path, "a".repeat(32));
        std::fs::write(&leftover, "synthetic-leftover").unwrap();
        let unrelated = format!("{}.backup", file.path);
        std::fs::write(&unrelated, "synthetic-backup").unwrap();
        file.load().unwrap();
        assert!(!std::path::Path::new(&leftover).exists());
        assert!(std::path::Path::new(&unrelated).exists());
    }

    fn totp_in(secret_b32: &str, seconds: u64) -> String {
        let secret = crate::totp::base32_decode(secret_b32).unwrap();
        format!("{:06}", crate::totp::totp_at(&secret, now_secs() + seconds))
    }

    fn totp_now(secret_b32: &str) -> String {
        totp_in(secret_b32, 0)
    }

    /// The code for the next time step. The ±1 step drift accepts it, and it
    /// is newer than any code used so far in a test.
    fn totp_next(secret_b32: &str) -> String {
        totp_in(secret_b32, 30)
    }

    fn challenge(auth: &Auth, ip: IpAddr, password: &str) -> String {
        match auth.login_step1_session(ip, password).unwrap() {
            LoginStep1Outcome::Challenge(token) => token,
            LoginStep1Outcome::Session(_) => panic!("2FA must require a challenge"),
        }
    }

    fn configured_auth(file: &TestState) -> Auth {
        let auth = file.load().unwrap();
        auth.setup_password_session(PASSWORD).unwrap();
        auth
    }

    /// Returns the auth, its TOTP secret (base32) and the backup codes.
    fn enrolled_auth(file: &TestState) -> (Auth, String, Vec<String>) {
        let auth = configured_auth(file);
        let (secret, _, _) = auth
            .totp_enroll_begin_verified(localhost(), PASSWORD)
            .unwrap();
        let (codes, _) = auth
            .totp_enroll_confirm_session(&totp_now(&secret))
            .unwrap();
        (auth, secret, codes)
    }

    /// Unsalted backup code hash in the format older versions wrote.
    fn legacy_hash(normalized: &str) -> String {
        let derived = derive_key(&format!("backup-salt:{normalized}"), b"cfddnswebui-salt");
        hex(&derive_key(normalized, &derived[..SALT_LEN]))
    }

    fn backup_matches(stored: &str, code: &str) -> bool {
        find_backup_code(&[stored.to_string()], &normalize_code(code)).is_some()
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
        assert_eq!(
            auth.setup_password_session(PASSWORD).unwrap_err(),
            AuthError::PersistenceFailed
        );
        assert!(!auth.is_configured());
        std::fs::remove_dir(&file.path).unwrap();
        auth.setup_password_session(PASSWORD).unwrap();
        assert!(file.load().unwrap().verify_password(PASSWORD));
    }

    #[test]
    fn security_password_failure_preserves_identity_and_sessions() {
        let file = TestState::new();
        let auth = configured_auth(&file);
        let session = auth.create_session().unwrap();
        let saved = block_saves(&file);
        assert_eq!(
            auth.change_password_verified(localhost(), PASSWORD, None, "replacement-password")
                .unwrap_err(),
            AuthError::PersistenceFailed
        );
        assert!(auth.verify_password(PASSWORD));
        assert!(!auth.verify_password("replacement-password"));
        assert!(auth.session_valid(&session));
        restore_saves(&file, saved);
        assert!(file.load().unwrap().verify_password(PASSWORD));
    }

    #[test]
    fn security_enrollment_failure_preserves_pending_secret() {
        let file = TestState::new();
        let auth = configured_auth(&file);
        let (secret, _, _) = auth
            .totp_enroll_begin_verified(localhost(), PASSWORD)
            .unwrap();
        let code = totp_now(&secret);
        let saved = block_saves(&file);
        assert_eq!(
            auth.totp_enroll_confirm_session(&code).unwrap_err(),
            AuthError::PersistenceFailed
        );
        assert!(!auth.totp_enabled());
        assert_eq!(auth.backup_codes_remaining(), 0);
        assert!(lock(&auth.flow).pending_totp.is_some());
        restore_saves(&file, saved);
        assert!(!file.load().unwrap().totp_enabled());
        assert_eq!(
            auth.totp_enroll_confirm_session(&code).unwrap().0.len(),
            BACKUP_CODE_COUNT
        );
        assert!(file.load().unwrap().totp_enabled());
    }

    #[test]
    fn security_disable_failure_preserves_factors() {
        let file = TestState::new();
        let (auth, secret, _) = enrolled_auth(&file);
        let saved = block_saves(&file);
        assert_eq!(
            auth.totp_disable_verified(localhost(), &totp_next(&secret))
                .unwrap_err(),
            AuthError::PersistenceFailed
        );
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
        let (auth, _, codes) = enrolled_auth(&file);
        let ip = localhost();
        let challenge_token = challenge(&auth, ip, PASSWORD);
        let saved = block_saves(&file);
        for _ in 0..=MAX_2FA_ATTEMPTS {
            assert!(matches!(
                auth.login_step2_session(ip, &challenge_token, &codes[0]),
                Err(AuthError::PersistenceFailed)
            ));
        }
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        restore_saves(&file, saved);
        let restarted = file.load().unwrap();
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT);
        assert!(auth
            .login_step2_session(ip, &challenge_token, &codes[0])
            .is_ok());
        let restarted = file.load().unwrap();
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT - 1);
        let challenge_token = challenge(&restarted, ip, PASSWORD);
        assert!(matches!(
            restarted.login_step2_session(ip, &challenge_token, &codes[0]),
            Err(AuthError::InvalidCode)
        ));
    }

    #[test]
    fn security_sensitive_recovery_save_failure_denies_and_preserves_code() {
        let file = TestState::new();
        let (auth, _, codes) = enrolled_auth(&file);
        let ip = localhost();
        let saved = block_saves(&file);
        assert_eq!(
            auth.change_password_verified(ip, PASSWORD, Some(&codes[0]), "replacement-password")
                .unwrap_err(),
            AuthError::PersistenceFailed
        );
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        restore_saves(&file, saved);
        let spaced = codes[0].to_lowercase().replace('-', " ");
        auth.change_password_verified(ip, PASSWORD, Some(&spaced), "replacement-password")
            .unwrap();
        let restarted = file.load().unwrap();
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT - 1);
        assert_eq!(
            restarted
                .change_password_verified(ip, "replacement-password", Some(&codes[0]), PASSWORD)
                .unwrap_err(),
            AuthError::InvalidCode
        );
        restarted
            .change_password_verified(ip, "replacement-password", Some(&codes[1]), PASSWORD)
            .unwrap();
    }

    #[test]
    fn security_password_change_revokes_pending_challenges_and_enrollment() {
        let file = TestState::new();
        let (auth, secret, codes) = enrolled_auth(&file);
        let ip = localhost();
        let challenge_token = challenge(&auth, ip, PASSWORD);
        auth.change_password_verified(ip, PASSWORD, Some(&codes[0]), "replacement-password")
            .unwrap();
        assert!(matches!(
            auth.login_step2_session(ip, &challenge_token, &totp_next(&secret)),
            Err(AuthError::ChallengeExpired)
        ));
        auth.totp_disable_verified(ip, &codes[1]).unwrap();
        auth.totp_enroll_begin_verified(ip, "replacement-password")
            .unwrap();
        auth.change_password_verified(ip, "replacement-password", None, "another-password")
            .unwrap();
        assert!(lock(&auth.flow).pending_totp.is_none());
    }

    #[test]
    fn security_factor_lockout_spans_challenges_and_addresses() {
        let file = TestState::new();
        let (auth, _, codes) = enrolled_auth(&file);
        let challenges: Vec<_> = (0..=MAX_2FA_ATTEMPTS)
            .map(|i| {
                let ip = IpAddr::from([127, 0, 0, i as u8 + 1]);
                (ip, challenge(&auth, ip, PASSWORD))
            })
            .collect();
        for (ip, token) in challenges.iter().take(MAX_2FA_ATTEMPTS as usize) {
            assert!(matches!(
                auth.login_step2_session(*ip, token, "invalid"),
                Err(AuthError::InvalidCode)
            ));
        }
        let (ip, token) = challenges.last().unwrap();
        assert!(matches!(
            auth.login_step2_session(*ip, token, &codes[0]),
            Err(AuthError::LockedOut)
        ));
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
    }

    #[test]
    fn security_sensitive_recovery_respects_factor_lockout() {
        let file = TestState::new();
        let (auth, _, codes) = enrolled_auth(&file);
        for index in 1..=MAX_2FA_ATTEMPTS {
            let ip = IpAddr::from([127, 0, 0, index as u8]);
            assert_eq!(
                auth.change_password_verified(
                    ip,
                    PASSWORD,
                    Some("invalid"),
                    "replacement-password"
                )
                .unwrap_err(),
                AuthError::InvalidCode
            );
        }
        let ip = "127.0.0.20".parse().unwrap();
        assert_eq!(
            auth.change_password_verified(ip, PASSWORD, Some(&codes[0]), "replacement-password")
                .unwrap_err(),
            AuthError::LockedOut
        );
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        assert!(auth.verify_password(PASSWORD));
    }

    #[test]
    fn security_verified_password_mutation_preserves_recovery_on_save_failure() {
        let file = TestState::new();
        let (auth, _, codes) = enrolled_auth(&file);
        let ip = localhost();
        let session = auth.create_session().unwrap();
        let challenge_token = challenge(&auth, ip, PASSWORD);
        let saved = block_saves(&file);
        assert_eq!(
            auth.change_password_verified(ip, PASSWORD, Some(&codes[0]), "replacement-password")
                .unwrap_err(),
            AuthError::PersistenceFailed
        );
        assert!(auth.verify_password(PASSWORD));
        assert!(auth.session_valid(&session));
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        assert!(lock(&auth.flow).challenges.contains_key(&challenge_token));
        restore_saves(&file, saved);
        auth.change_password_verified(ip, PASSWORD, Some(&codes[0]), "replacement-password")
            .unwrap();
        assert!(!auth.session_valid(&session));
        assert!(lock(&auth.flow).challenges.is_empty());
        let restarted = file.load().unwrap();
        assert!(restarted.verify_password("replacement-password"));
        assert_eq!(restarted.backup_codes_remaining(), BACKUP_CODE_COUNT - 1);
        assert_eq!(
            restarted
                .change_password_verified(ip, "replacement-password", Some(&codes[0]), PASSWORD)
                .unwrap_err(),
            AuthError::InvalidCode
        );
    }

    #[test]
    fn security_verified_disable_preserves_factors_on_save_failure() {
        let file = TestState::new();
        let (auth, _, codes) = enrolled_auth(&file);
        let ip = localhost();
        let session = auth.create_session().unwrap();
        let saved = block_saves(&file);
        assert!(matches!(
            auth.totp_disable_verified(ip, &codes[0]),
            Err(AuthError::PersistenceFailed)
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
        let (auth, secret, codes) = enrolled_auth(&file);
        for index in 1..=MAX_2FA_ATTEMPTS {
            let ip = IpAddr::from([127, 0, 0, index as u8]);
            assert!(matches!(
                auth.totp_disable_verified(ip, "invalid"),
                Err(AuthError::InvalidCode)
            ));
        }
        let ip = "127.0.0.20".parse().unwrap();
        let code = totp_next(&secret);
        assert!(matches!(
            auth.totp_disable_verified(ip, &code),
            Err(AuthError::LockedOut)
        ));
        assert_eq!(
            auth.change_password_verified(ip, PASSWORD, Some(&codes[0]), "replacement-password")
                .unwrap_err(),
            AuthError::LockedOut
        );
        assert_eq!(auth.backup_codes_remaining(), BACKUP_CODE_COUNT);
        lock(&auth.flow).factor_failures = (MAX_2FA_ATTEMPTS, Instant::now() - LOGIN_LOCKOUT);
        auth.totp_disable_verified(ip, &code).unwrap();
    }

    #[test]
    fn security_enrollment_requires_password_and_shares_lockout() {
        let file = TestState::new();
        let auth = configured_auth(&file);
        let ip = localhost();
        assert_eq!(
            auth.totp_enroll_begin_verified(ip, "wrong-password")
                .unwrap_err(),
            AuthError::InvalidPassword
        );
        assert!(lock(&auth.flow).pending_totp.is_none());
        let (secret, _, _) = auth.totp_enroll_begin_verified(ip, PASSWORD).unwrap();
        let code = totp_now(&secret);
        for _ in 1..MAX_2FA_ATTEMPTS {
            assert_eq!(
                auth.totp_enroll_confirm_session("invalid").unwrap_err(),
                AuthError::EnrollmentCodeRejected
            );
        }
        assert_eq!(
            auth.totp_enroll_confirm_session(&code).unwrap_err(),
            AuthError::LockedOut
        );
        assert_eq!(
            auth.totp_enroll_begin_verified(ip, PASSWORD).unwrap_err(),
            AuthError::LockedOut
        );
        lock(&auth.flow).factor_failures = (MAX_2FA_ATTEMPTS, Instant::now() - LOGIN_LOCKOUT);
        let session = auth.create_session().unwrap();
        auth.totp_enroll_confirm_session(&code).unwrap();
        assert!(!auth.session_valid(&session));
        assert!(lock(&auth.flow).pending_totp.is_none());
    }

    #[test]
    fn security_concurrent_recovery_consumption_is_single_use() {
        let file = TestState::new();
        let (auth, _, codes) = enrolled_auth(&file);
        let ip = localhost();
        let challenge_token = challenge(&auth, ip, PASSWORD);
        let barrier = std::sync::Barrier::new(2);
        let successes = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..2)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        auth.login_step2_session(ip, &challenge_token, &codes[0])
                            .is_ok()
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
        let ip = localhost();
        let setup_session = auth.setup_password_session(PASSWORD).unwrap();
        let barrier = std::sync::Barrier::new(2);
        let (login, changed_session) = std::thread::scope(|scope| {
            let login = scope.spawn(|| {
                barrier.wait();
                auth.login_step1_session(ip, PASSWORD)
            });
            let change = scope.spawn(|| {
                barrier.wait();
                auth.change_password_verified(ip, PASSWORD, None, "replacement-password")
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
        let (codes, enrolled_session) = auth
            .totp_enroll_confirm_session(&totp_now(&secret))
            .unwrap();
        assert!(!auth.session_valid(&changed_session));
        assert!(auth.session_valid(&enrolled_session));
        let challenge_token = challenge(&auth, ip, "replacement-password");
        let (_, factor_session) = auth
            .login_step2_session(ip, &challenge_token, &codes[0])
            .unwrap();
        assert!(auth.session_valid(&factor_session));
        let disabled_session = auth.totp_disable_verified(ip, &codes[1]).unwrap();
        assert!(!auth.session_valid(&factor_session));
        assert!(!auth.session_valid(&enrolled_session));
        assert!(auth.session_valid(&disabled_session));
        assert!(!file.load().unwrap().session_valid(&disabled_session));
    }

    #[test]
    fn security_totp_code_is_accepted_once() {
        let file = TestState::new();
        let (auth, secret, _) = enrolled_auth(&file);
        let ip = localhost();
        let decoded = crate::totp::base32_decode(&secret).unwrap();
        // Enrollment used this step. A fast test is still inside its ±1 window,
        // so only replay protection can reject it.
        let used = lock(&auth.flow).last_totp_step.unwrap();
        let replayed = format!("{:06}", crate::totp::totp_at(&decoded, used * 30));
        let token = challenge(&auth, ip, PASSWORD);
        // A replay is rejected, but the code was right, so it does not count
        // toward the account-wide lockout.
        for _ in 0..=MAX_2FA_ATTEMPTS {
            assert!(matches!(
                auth.login_step2_session(ip, &token, &replayed),
                Err(AuthError::CodeAlreadyUsed)
            ));
        }
        assert_eq!(lock(&auth.flow).factor_failures.0, 0);
        let next = format!("{:06}", crate::totp::totp_at(&decoded, (used + 1) * 30));
        assert!(matches!(
            auth.login_step2_session(ip, &token, &next),
            Ok((Login2faOutcome::Totp, _))
        ));
        let token = challenge(&auth, ip, PASSWORD);
        assert!(matches!(
            auth.login_step2_session(ip, &token, &next),
            Err(AuthError::CodeAlreadyUsed)
        ));
    }

    #[test]
    fn security_totp_code_used_for_password_change_cannot_log_in() {
        let file = TestState::new();
        let (auth, secret, _) = enrolled_auth(&file);
        let ip = localhost();
        let code = totp_next(&secret);
        auth.change_password_verified(ip, PASSWORD, Some(&code), "replacement-password")
            .unwrap();
        let token = challenge(&auth, ip, "replacement-password");
        assert!(matches!(
            auth.login_step2_session(ip, &token, &code),
            Err(AuthError::CodeAlreadyUsed)
        ));
    }

    #[test]
    fn codes_share_one_normalization_rule() {
        assert_eq!(normalize_code(" abcd-efgh\t"), "ABCDEFGH");
        assert_eq!(normalize_code("123 456"), "123456");
        assert_eq!(normalize_code("123-456"), "123456");
        // Non-ASCII letters are left alone, so they fail the format checks.
        assert_eq!(normalize_code("\u{ff21}bcd-efgh"), "\u{ff21}BCDEFGH");
        let stored = hash_backup_code("ABCD-EFGH").unwrap();
        assert!(!backup_matches(&stored, "\u{ff21}BCD-EFGH"));
        // Enrollment accepts the same spacing as login.
        let file = TestState::new();
        let auth = configured_auth(&file);
        let (secret, _, _) = auth
            .totp_enroll_begin_verified(localhost(), PASSWORD)
            .unwrap();
        let code = totp_now(&secret);
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        auth.totp_enroll_confirm_session(&spaced).unwrap();
    }

    #[test]
    fn security_limiter_flood_keeps_existing_lockout() {
        let limiter = LoginLimiter::new();
        let victim: IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..MAX_LOGIN_FAILURES {
            limiter.record_failure(victim);
        }
        assert!(limiter.is_locked_out(victim));
        for i in 0..MAX_LIMITER_ENTRIES as u32 + 50 {
            limiter.record_failure(IpAddr::from((0x0a00_0000u32 + i).to_be_bytes()));
        }
        assert!(limiter.is_locked_out(victim));
        assert!(lock(&limiter.state).len() <= MAX_LIMITER_ENTRIES);
    }

    #[test]
    fn security_limiter_full_of_single_failures_still_admits_new_clients() {
        let limiter = LoginLimiter::new();
        for i in 0..MAX_LIMITER_ENTRIES as u32 {
            limiter.record_failure(IpAddr::from((0x0a00_0000u32 + i).to_be_bytes()));
        }
        let newcomer: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(!limiter.is_locked_out(newcomer));
        limiter.record_failure(newcomer);
        let state = lock(&limiter.state);
        assert_eq!(state.len(), MAX_LIMITER_ENTRIES);
        assert!(state.contains_key(&newcomer));
        // The oldest entry made room.
        assert!(!state.contains_key(&IpAddr::from([10, 0, 0, 0])));
    }

    #[test]
    fn security_limiter_full_of_lockouts_refuses_new_clients_until_entries_expire() {
        let limiter = LoginLimiter::new();
        {
            let mut state = lock(&limiter.state);
            for i in 0..MAX_LIMITER_ENTRIES as u32 {
                let ip = IpAddr::from((0x0a00_0000u32 + i).to_be_bytes());
                state.insert(ip, (MAX_LOGIN_FAILURES, Instant::now()));
            }
        }
        let newcomer: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(limiter.is_locked_out(newcomer));
        for entry in lock(&limiter.state).values_mut() {
            entry.1 = Instant::now() - LOGIN_LOCKOUT;
        }
        assert!(!limiter.is_locked_out(newcomer));
        limiter.record_failure(newcomer);
        assert_eq!(lock(&limiter.state).len(), 1);
    }

    #[test]
    fn security_limiter_groups_ipv6_by_slash64() {
        let limiter = LoginLimiter::new();
        for _ in 0..MAX_LOGIN_FAILURES {
            limiter.record_failure("2001:db8::1".parse().unwrap());
        }
        assert!(limiter.is_locked_out("2001:db8::2".parse().unwrap()));
        assert!(limiter.is_locked_out("2001:db8::ffff:1".parse().unwrap()));
        assert!(!limiter.is_locked_out("2001:db8:0:1::1".parse().unwrap()));
        for _ in 0..MAX_LOGIN_FAILURES {
            limiter.record_failure("::ffff:192.0.2.1".parse().unwrap());
        }
        assert!(limiter.is_locked_out("192.0.2.1".parse().unwrap()));
        assert!(!limiter.is_locked_out("::ffff:192.0.2.2".parse().unwrap()));
        limiter.record_success("2001:db8::3".parse().unwrap());
        assert!(!limiter.is_locked_out("2001:db8::1".parse().unwrap()));
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
        auth.change_password_verified(localhost(), PASSWORD, None, "replacement-password")
            .unwrap();
        assert_eq!(
            std::fs::metadata(&file.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(&file.dir).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn security_failed_save_leaves_no_temporary_credentials() {
        let file = TestState::new();
        let auth = file.load().unwrap();
        // A directory at the state path makes the final rename fail after the
        // temporary file has been written.
        std::fs::create_dir(&file.path).unwrap();
        assert!(auth.setup_password_session(PASSWORD).is_err());
        let leftovers: Vec<_> = std::fs::read_dir(&file.dir)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| !entry.file_type().unwrap().is_dir())
            .map(|entry| entry.file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "failed save left files behind: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn security_unsynced_directory_still_commits() {
        use std::os::unix::fs::PermissionsExt;
        let file = TestState::new();
        let auth = file.load().unwrap();
        // Write and search without read: the rename works, opening the
        // directory to sync it does not.
        let mode = |bits| std::fs::Permissions::from_mode(bits);
        std::fs::set_permissions(&file.dir, mode(0o300)).unwrap();
        if std::fs::File::open(&file.dir).is_ok() {
            // Running as root, which ignores the missing read bit.
            std::fs::set_permissions(&file.dir, mode(0o700)).unwrap();
            return;
        }
        let outcome = save_state(&file.path, &AuthState::default());
        let session = auth.setup_password_session(PASSWORD);
        std::fs::set_permissions(&file.dir, mode(0o700)).unwrap();
        assert_eq!(outcome, Ok(SaveOutcome::DirectoryNotSynced));
        assert!(session.is_ok());
        assert!(auth.is_configured());
        assert!(file.load().unwrap().verify_password(PASSWORD));
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
                "password_key": hex(&derive_key(PASSWORD, &salt)).to_uppercase()
            })
            .to_string(),
        );
        let auth = file.load().unwrap();
        assert!(auth.verify_password(PASSWORD));
        assert!(!auth.totp_enabled());
    }

    #[test]
    fn startup_accepts_valid_totp_with_exhausted_recovery_codes() {
        let file = TestState::new();
        let secret = b"synthetic totp key";
        let salt = [0xab; SALT_LEN];
        file.write(serde_json::json!({
            "password_salt": hex(&salt),
            "password_key": hex(&derive_key(PASSWORD, &salt)),
            "totp_secret": format!(" {}=== ", crate::totp::base32_encode(secret).to_lowercase()),
            "backup_code_hashes": []
        }).to_string());
        let auth = file.load().unwrap();
        assert!(auth.totp_enabled());
        assert_eq!(auth.backup_codes_remaining(), 0);
        let ip = localhost();
        let token = challenge(&auth, ip, PASSWORD);
        let code = totp_now(&crate::totp::base32_encode(secret));
        assert!(matches!(
            auth.login_step2_session(ip, &token, &code),
            Ok((Login2faOutcome::Totp, _))
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
    fn startup_rejects_totp_secret_shorter_than_128_bits() {
        let file = TestState::new();
        for (len, accepted) in [
            (MIN_TOTP_SECRET_LEN - 1, false),
            (MIN_TOTP_SECRET_LEN, true),
        ] {
            file.write(
                serde_json::json!({
                    "password_salt": hex(&[0; SALT_LEN]),
                    "password_key": hex(&[0; KEY_LEN]),
                    "totp_secret": crate::totp::base32_encode(&vec![1; len]),
                })
                .to_string(),
            );
            assert_eq!(file.load().is_ok(), accepted, "{len}-byte secret");
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
            &format!("{}:", hex(&[1; SALT_LEN])),
            &format!(":{}", hex(&[2; KEY_LEN])),
            &format!("{}:{}", hex(&[1; SALT_LEN - 1]), hex(&[2; KEY_LEN])),
            &format!(
                "{}:{}:{}",
                hex(&[1; SALT_LEN]),
                hex(&[2; KEY_LEN]),
                hex(&[3; 1])
            ),
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
    fn backup_codes_hash_and_verify() {
        let codes = generate_backup_codes().unwrap();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        for c in &codes {
            assert_eq!(c.len(), 9); // XXXX-XXXX
            assert_eq!(c.chars().nth(4), Some('-'));
            let h = hash_backup_code(c).unwrap();
            assert!(backup_matches(&h, c));
            let nodash: String = c.chars().filter(|x| *x != '-').collect();
            assert!(backup_matches(&h, &nodash));
            assert!(!backup_matches(&h, "AAAA-AAAA"));
        }
    }

    #[test]
    fn backup_code_hashes_use_a_random_salt_per_code() {
        let code = "ABCD-EFGH";
        let first = hash_backup_code(code).unwrap();
        let second = hash_backup_code(code).unwrap();
        assert_ne!(first, second);
        for stored in [&first, &second] {
            let (salt, key) = stored.split_once(':').expect("salt:key format");
            assert_eq!(salt.len(), SALT_LEN * 2);
            assert_eq!(key.len(), KEY_LEN * 2);
            assert!(backup_matches(stored, code));
            assert!(backup_matches(stored, "abcdefgh"));
            assert!(!backup_matches(stored, "ABCD-EFGJ"));
        }
    }

    #[test]
    fn legacy_backup_code_hashes_still_verify() {
        // Hashes saved before per-code salts used a salt derived from the code.
        let legacy = legacy_hash("ABCDEFGH");
        assert!(backup_matches(&legacy, "abcd-efgh"));
        assert!(!backup_matches(&legacy, "ABCD-EFGJ"));
        let salted = hash_backup_code("ABCD-EFGJ").unwrap();
        let mixed = [legacy_hash("ABCDEFGK"), salted, legacy.clone()];
        assert_eq!(find_backup_code(&mixed, "ABCDEFGH"), Some(2));
        assert_eq!(find_backup_code(&mixed, "ABCDEFGJ"), Some(1));
    }

    #[test]
    fn legacy_recovery_hash_from_state_file_logs_in_once_after_restart() {
        let file = TestState::new();
        let password_salt = [7; SALT_LEN];
        file.write(
            serde_json::json!({
                "password_salt": hex(&password_salt),
                "password_key": hex(&derive_key(PASSWORD, &password_salt)),
                "totp_secret": crate::totp::base32_encode(&[0; TOTP_SECRET_LEN]),
                "backup_code_hashes": [legacy_hash("ABCDEFGH")]
            })
            .to_string(),
        );
        let auth = file.load().unwrap();
        assert!(auth.has_legacy_backup_hashes());
        let ip = localhost();
        let token = challenge(&auth, ip, PASSWORD);
        assert!(matches!(
            auth.login_step2_session(ip, &token, "abcd-efgh"),
            Ok((Login2faOutcome::BackupCode { remaining: 0 }, _))
        ));
        let restarted = file.load().unwrap();
        assert_eq!(restarted.backup_codes_remaining(), 0);
        assert!(!restarted.has_legacy_backup_hashes());
        let token = challenge(&restarted, ip, PASSWORD);
        assert!(restarted
            .login_step2_session(ip, &token, "ABCD-EFGH")
            .is_err());
    }

    #[test]
    fn startup_accepts_salted_and_legacy_recovery_hashes() {
        let file = TestState::new();
        let salted = format!("{}:{}", hex(&[1; SALT_LEN]), hex(&[2; KEY_LEN]));
        let state = |hashes: Vec<String>| {
            serde_json::json!({
                "password_salt": hex(&[0; SALT_LEN]),
                "password_key": hex(&[0; KEY_LEN]),
                "totp_secret": crate::totp::base32_encode(&[0; TOTP_SECRET_LEN]),
                "backup_code_hashes": hashes
            })
            .to_string()
        };
        file.write(state(vec![hex(&[0; KEY_LEN]), salted.clone()]));
        let auth = file.load().unwrap();
        assert_eq!(auth.backup_codes_remaining(), 2);
        assert!(auth.has_legacy_backup_hashes());
        file.write(state(vec![salted]));
        assert!(!file.load().unwrap().has_legacy_backup_hashes());
    }

    #[test]
    fn state_roundtrip() {
        let file = TestState::new();
        let auth = file.load().unwrap();
        assert!(!auth.is_configured());
        auth.setup_password_session("super-secret-password")
            .unwrap();
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
        auth.setup_password_session("super-secret-password")
            .unwrap();
        let ip = localhost();
        let (_secret_b32, uri, qr) = auth
            .totp_enroll_begin_verified(ip, "super-secret-password")
            .unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(qr.is_some());
        let pending = lock(&auth.flow)
            .pending_totp
            .as_ref()
            .unwrap()
            .secret
            .clone();
        let code = totp_now(&crate::totp::base32_encode(&pending));
        let (backup, _) = auth.totp_enroll_confirm_session(&code).unwrap();
        assert_eq!(backup.len(), BACKUP_CODE_COUNT);
        assert!(auth.totp_enabled());
        let token = challenge(&auth, ip, "super-secret-password");
        let (outcome, _) = auth.login_step2_session(ip, &token, &backup[0]).unwrap();
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
        let token = challenge(&restarted, ip, "super-secret-password");
        assert!(restarted
            .login_step2_session(ip, &token, &backup[0])
            .is_err());
        assert!(matches!(
            restarted.login_step2_session(ip, &token, &backup[1]),
            Ok((Login2faOutcome::BackupCode { remaining: 6 }, _))
        ));
    }
}
