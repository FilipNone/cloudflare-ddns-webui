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
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Uuid, Webauthn,
    WebauthnBuilder,
};

// The unwraps run at compile time, so a zero count fails the build.
/// Iterations for new password hashes. 600,000 is the OWASP Password
/// Storage Cheat Sheet value for PBKDF2-HMAC-SHA256.
const PASSWORD_ITERATIONS: NonZeroU32 = NonZeroU32::new(600_000).unwrap();
/// Count for state files saved before `password_iterations` existed.
const LEGACY_PASSWORD_ITERATIONS: NonZeroU32 = NonZeroU32::new(100_000).unwrap();
/// Highest count a state file may ask for. A damaged or edited file must
/// not make every login take minutes.
const MAX_PASSWORD_ITERATIONS: NonZeroU32 = NonZeroU32::new(6_000_000).unwrap();
/// Backup codes are random 40-bit codes, and a wrong code is checked against
/// every stored hash, so they keep the lower count. 600,000 would make each
/// attempt about six times slower for little gain.
const BACKUP_CODE_ITERATIONS: NonZeroU32 = NonZeroU32::new(100_000).unwrap();
/// How long to skip password hash upgrades after one fails to save. Each
/// attempt costs a full rehash and a log line, and anyone who knows the
/// password could otherwise repeat it on a full or read-only volume.
const UPGRADE_RETRY_DELAY: Duration = Duration::from_secs(10 * 60);
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
const MAX_PASSKEYS: usize = 20;
const MAX_PASSKEY_NAME_BYTES: usize = 64;
const PASSKEY_ID_LEN: usize = 16;
const MAX_PENDING_PASSKEY_FLOWS: usize = 64;

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
    PasskeyUnavailable,
    PasskeyInvalid,
    PasskeyNotFound,
    PasskeyLimitReached,
    PasskeyNameInvalid,
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
            AuthError::PasskeyUnavailable => "passkeys are unavailable for this origin",
            AuthError::PasskeyInvalid => "passkey verification failed",
            AuthError::PasskeyNotFound => "passkey not found",
            AuthError::PasskeyLimitReached => "passkey limit reached",
            AuthError::PasskeyNameInvalid => "passkey name must be 1 to 64 bytes",
        }
    }
}

// --- Hashing ---

fn derive_key(secret: &str, salt: &[u8], iterations: NonZeroU32) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        secret.as_bytes(),
        &mut key,
    );
    key
}

fn key_matches(secret: &str, salt: &[u8], iterations: NonZeroU32, expected: &[u8]) -> bool {
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
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
    /// PBKDF2 iterations behind `password_key`. Missing in files from older
    /// versions, which used `LEGACY_PASSWORD_ITERATIONS`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_iterations: Option<u32>,
    pub totp_secret: Option<String>, // base32
    pub backup_code_hashes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passkey_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passkey_rp_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    passkeys: Vec<StoredPasskey>,
}

impl AuthState {
    pub fn is_configured(&self) -> bool {
        self.password_salt.is_some() && self.password_key.is_some()
    }
    pub fn totp_enabled(&self) -> bool {
        self.totp_secret.is_some()
    }

    /// The iteration count to check the password with, or None when the
    /// saved count is out of range.
    fn password_hash_iterations(&self) -> Option<NonZeroU32> {
        match self.password_iterations {
            None => Some(LEGACY_PASSWORD_ITERATIONS),
            Some(count) => NonZeroU32::new(count).filter(|count| {
                (LEGACY_PASSWORD_ITERATIONS..=MAX_PASSWORD_ITERATIONS).contains(count)
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPasskey {
    id: String,
    name: String,
    created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<u64>,
    credential: Passkey,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasskeySummary {
    pub id: String,
    pub name: String,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
}

struct PendingPasskeyRegistration {
    state: PasskeyRegistration,
    name: String,
    user_id: Uuid,
    session_token: String,
    expires_at: Instant,
}

struct PendingPasskeyAuthentication {
    state: PasskeyAuthentication,
    expires_at: Instant,
}

struct PasskeyRuntime {
    webauthn: Webauthn,
    rp_id: String,
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
    /// After a password hash upgrade fails to save, upgrades are skipped
    /// until this time. It lives in memory only, so a restart tries again.
    upgrade_retry_after: Option<Instant>,
    passkey_registrations: HashMap<String, PendingPasskeyRegistration>,
    passkey_authentications: HashMap<String, PendingPasskeyAuthentication>,
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
    passkeys: Option<PasskeyRuntime>,
}

impl Auth {
    #[cfg(test)]
    pub fn new(session_ttl: Duration, state_path: &str, pp: PP) -> Result<Self, String> {
        Self::new_inner(session_ttl, state_path, pp, None)
    }

    pub fn new_with_origin(
        session_ttl: Duration,
        state_path: &str,
        pp: PP,
        origin: Option<&reqwest::Url>,
    ) -> Result<Self, String> {
        let passkeys = origin
            .map(|origin| -> Result<PasskeyRuntime, String> {
                let rp_id = origin
                    .host_str()
                    .ok_or_else(|| "PUBLIC_ORIGIN has no passkey relying-party ID".to_string())?;
                let webauthn = WebauthnBuilder::new(rp_id, origin)
                    .and_then(|builder| builder.rp_name("Cloudflare DDNS").build())
                    .map_err(|_| "PUBLIC_ORIGIN is not valid for WebAuthn".to_string())?;
                Ok(PasskeyRuntime {
                    webauthn,
                    rp_id: rp_id.to_string(),
                })
            })
            .transpose()?;
        Self::new_inner(session_ttl, state_path, pp, passkeys)
    }

    fn new_inner(
        session_ttl: Duration,
        state_path: &str,
        pp: PP,
        passkeys: Option<PasskeyRuntime>,
    ) -> Result<Self, String> {
        let state = load_state(state_path)?;
        crate::persist::remove_temp_files(std::path::Path::new(state_path));
        Ok(Auth {
            state: Mutex::new(state),
            flow: Mutex::new(Flow {
                challenges: HashMap::new(),
                pending_totp: None,
                factor_failures: (0, Instant::now()),
                last_totp_step: None,
                upgrade_retry_after: None,
                passkey_registrations: HashMap::new(),
                passkey_authentications: HashMap::new(),
            }),
            sessions: Mutex::new(HashMap::new()),
            limiter: LoginLimiter::new(),
            session_ttl,
            state_path: state_path.to_string(),
            pp,
            passkeys,
        })
    }

    fn snapshot(&self) -> AuthState {
        lock(&self.state).clone()
    }

    fn commit_state(&self, candidate: AuthState) -> Result<(), AuthError> {
        self.save_and_swap(candidate).map_err(|error| {
            self.pp.errorf(
                crate::pp::EMOJI_ERROR,
                format!("Cannot save auth state: {error}"),
            );
            AuthError::PersistenceFailed
        })
    }

    // Callers hold the flow lock, which keeps saves in order. The state lock
    // is only taken for the swap, so readers never wait for disk I/O.
    // On error nothing changes and the caller decides how to log it.
    fn save_and_swap(&self, candidate: AuthState) -> Result<(), String> {
        match save_state(&self.state_path, &candidate)? {
            SaveOutcome::Durable => {}
            SaveOutcome::DirectoryNotSynced => self.pp.warningf(
                crate::pp::EMOJI_LOCK,
                "Saved auth state, but could not sync the data directory; a power loss may undo the change",
            ),
        }
        *lock(&self.state) = candidate;
        Ok(())
    }

    /// Rehashes a password that has just been verified when its stored hash
    /// uses fewer iterations than new hashes. Callers hold the flow lock.
    /// Sessions and challenges stay valid, since the password is the same.
    /// A failed save keeps the old hash and only logs a warning, so the
    /// login still works. Upgrades then pause for `UPGRADE_RETRY_DELAY`.
    fn upgrade_password_hash(&self, flow: &mut Flow, password: &str) {
        if flow
            .upgrade_retry_after
            .is_some_and(|retry_after| Instant::now() < retry_after)
        {
            return;
        }
        let mut candidate = self.snapshot();
        if candidate
            .password_hash_iterations()
            .is_none_or(|iterations| iterations >= PASSWORD_ITERATIONS)
        {
            return;
        }
        let result = set_password(&mut candidate, password)
            .map_err(|_| "cannot generate a salt".to_string())
            .and_then(|()| self.save_and_swap(candidate));
        if let Err(error) = result {
            flow.upgrade_retry_after = Instant::now().checked_add(UPGRADE_RETRY_DELAY);
            self.pp.warningf(
                crate::pp::EMOJI_LOCK,
                format!(
                    "Cannot upgrade the stored password hash; keeping the old hash and retrying at the first login after {} minutes: {error}",
                    UPGRADE_RETRY_DELAY.as_secs() / 60
                ),
            );
        }
    }

    fn revoke_authentication(&self, flow: &mut Flow) {
        lock(&self.sessions).clear();
        flow.challenges.clear();
        flow.pending_totp = None;
        flow.passkey_registrations.clear();
        flow.passkey_authentications.clear();
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

    fn verified_step_up(
        &self,
        flow: &mut Flow,
        ip: IpAddr,
        password: &str,
        code: Option<&str>,
    ) -> Result<(AuthState, Option<u64>, bool), AuthError> {
        self.check_lockout(flow, Some(ip))?;
        if !self.verify_password(password) {
            self.factor_failure(flow, Some(ip));
            return Err(AuthError::InvalidPassword);
        }
        self.upgrade_password_hash(flow, password);
        let mut candidate = self.snapshot();
        if !candidate.totp_enabled() {
            return Ok((candidate, None, false));
        }
        let recovery_codes = candidate.backup_code_hashes.len();
        let totp_step = self
            .verify_factor(flow, ip, code.unwrap_or(""), &candidate)?
            .consume(&mut candidate);
        Ok((
            candidate,
            totp_step,
            recovery_codes != self.backup_codes_remaining(),
        ))
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
                .zip(state.password_hash_iterations())
        };
        stored
            .is_some_and(|((salt, key), iterations)| key_matches(password, &salt, iterations, &key))
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
        self.upgrade_password_hash(&mut flow, password);
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

    // --- Passkeys ---

    pub fn passkey_supported(&self) -> bool {
        self.passkeys.is_some()
    }

    pub fn passkey_count(&self) -> usize {
        lock(&self.state).passkeys.len()
    }

    pub fn passkey_summaries(&self) -> Vec<PasskeySummary> {
        lock(&self.state)
            .passkeys
            .iter()
            .map(|passkey| PasskeySummary {
                id: passkey.id.clone(),
                name: passkey.name.clone(),
                created_at: passkey.created_at,
                last_used_at: passkey.last_used_at,
            })
            .collect()
    }

    pub fn passkey_authentication_start(
        &self,
        ip: IpAddr,
    ) -> Result<(String, RequestChallengeResponse), AuthError> {
        let runtime = self
            .passkeys
            .as_ref()
            .ok_or(AuthError::PasskeyUnavailable)?;
        let mut flow = lock(&self.flow);
        self.check_lockout(&mut flow, Some(ip))?;
        let state = self.snapshot();
        if state.passkeys.is_empty()
            || state
                .passkey_rp_id
                .as_deref()
                .is_some_and(|rp_id| rp_id != runtime.rp_id)
        {
            return Err(AuthError::PasskeyUnavailable);
        }
        let credentials = state
            .passkeys
            .iter()
            .map(|passkey| passkey.credential.clone())
            .collect::<Vec<_>>();
        let now = Instant::now();
        flow.passkey_authentications
            .retain(|_, pending| pending.expires_at > now);
        if flow.passkey_authentications.len() >= MAX_PENDING_PASSKEY_FLOWS {
            return Err(AuthError::LockedOut);
        }
        let (options, authentication) = runtime
            .webauthn
            .start_passkey_authentication(&credentials)
            .map_err(|_| AuthError::Internal)?;
        let token = hex(&random_bytes::<CHALLENGE_TOKEN_LEN>()?);
        flow.passkey_authentications.insert(
            token.clone(),
            PendingPasskeyAuthentication {
                state: authentication,
                expires_at: now + CHALLENGE_TTL,
            },
        );
        Ok((token, options))
    }

    pub fn passkey_authentication_finish(
        &self,
        ip: IpAddr,
        flow_token: &str,
        credential: &PublicKeyCredential,
    ) -> Result<String, AuthError> {
        let runtime = self
            .passkeys
            .as_ref()
            .ok_or(AuthError::PasskeyUnavailable)?;
        let mut flow = lock(&self.flow);
        self.check_lockout(&mut flow, Some(ip))?;
        let Some(pending) = flow.passkey_authentications.remove(flow_token) else {
            return Err(AuthError::ChallengeExpired);
        };
        if pending.expires_at <= Instant::now() {
            return Err(AuthError::ChallengeExpired);
        }
        let result = runtime
            .webauthn
            .finish_passkey_authentication(credential, &pending.state)
            .map_err(|_| {
                self.factor_failure(&mut flow, Some(ip));
                AuthError::PasskeyInvalid
            })?;
        let mut candidate = self.snapshot();
        let mut matched = false;
        for passkey in &mut candidate.passkeys {
            if passkey.credential.update_credential(&result).is_some() {
                if matched {
                    return Err(AuthError::Internal);
                }
                matched = true;
                passkey.last_used_at = Some(now_secs());
            }
        }
        if !matched {
            self.factor_failure(&mut flow, Some(ip));
            return Err(AuthError::PasskeyInvalid);
        }
        self.commit_state(candidate)?;
        self.factor_success(&mut flow, Some(ip));
        self.create_session()
    }

    pub fn passkey_registration_start_verified(
        &self,
        ip: IpAddr,
        session_token: &str,
        name: &str,
        password: &str,
        code: Option<&str>,
    ) -> Result<(String, CreationChallengeResponse), AuthError> {
        let runtime = self
            .passkeys
            .as_ref()
            .ok_or(AuthError::PasskeyUnavailable)?;
        let name = validate_passkey_name(name)?;
        let mut flow = lock(&self.flow);
        if !self.session_valid(session_token) {
            return Err(AuthError::ChallengeExpired);
        }
        let now = Instant::now();
        flow.passkey_registrations
            .retain(|_, pending| pending.expires_at > now);
        if flow.passkey_registrations.len() >= MAX_PENDING_PASSKEY_FLOWS {
            return Err(AuthError::LockedOut);
        }
        let (candidate, totp_step, recovery_used) =
            self.verified_step_up(&mut flow, ip, password, code)?;
        if candidate.passkeys.len() >= MAX_PASSKEYS {
            return Err(AuthError::PasskeyLimitReached);
        }
        if !candidate.passkeys.is_empty()
            && candidate
                .passkey_rp_id
                .as_deref()
                .is_some_and(|rp_id| rp_id != runtime.rp_id)
        {
            return Err(AuthError::PasskeyUnavailable);
        }
        if recovery_used {
            self.commit_state(candidate.clone())?;
        }
        if let Some(step) = totp_step {
            flow.last_totp_step = Some(step);
        }
        self.factor_success(&mut flow, Some(ip));

        let user_id = candidate
            .passkey_user_id
            .as_deref()
            .and_then(|id| Uuid::parse_str(id).ok())
            .unwrap_or_else(Uuid::new_v4);
        let excluded = candidate
            .passkeys
            .iter()
            .map(|passkey| passkey.credential.cred_id().clone())
            .collect::<Vec<_>>();
        let (options, registration) = runtime
            .webauthn
            .start_passkey_registration(
                user_id,
                "admin",
                "Cloudflare DDNS administrator",
                Some(excluded),
            )
            .map_err(|_| AuthError::Internal)?;
        let token = hex(&random_bytes::<CHALLENGE_TOKEN_LEN>()?);
        flow.passkey_registrations.insert(
            token.clone(),
            PendingPasskeyRegistration {
                state: registration,
                name,
                user_id,
                session_token: session_token.to_string(),
                expires_at: now + CHALLENGE_TTL,
            },
        );
        Ok((token, options))
    }

    pub fn passkey_registration_finish(
        &self,
        ip: IpAddr,
        session_token: &str,
        flow_token: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<(PasskeySummary, String), AuthError> {
        let runtime = self
            .passkeys
            .as_ref()
            .ok_or(AuthError::PasskeyUnavailable)?;
        let mut flow = lock(&self.flow);
        let Some(pending) = flow.passkey_registrations.remove(flow_token) else {
            return Err(AuthError::ChallengeExpired);
        };
        if pending.expires_at <= Instant::now()
            || pending.session_token != session_token
            || !self.session_valid(session_token)
        {
            return Err(AuthError::ChallengeExpired);
        }
        let passkey = runtime
            .webauthn
            .finish_passkey_registration(credential, &pending.state)
            .map_err(|_| {
                self.factor_failure(&mut flow, Some(ip));
                AuthError::PasskeyInvalid
            })?;
        let mut candidate = self.snapshot();
        if candidate.passkeys.len() >= MAX_PASSKEYS {
            return Err(AuthError::PasskeyLimitReached);
        }
        if candidate
            .passkeys
            .iter()
            .any(|stored| stored.credential.cred_id() == passkey.cred_id())
        {
            return Err(AuthError::PasskeyInvalid);
        }
        if candidate
            .passkey_user_id
            .as_deref()
            .is_some_and(|id| id != pending.user_id.to_string())
        {
            return Err(AuthError::Internal);
        }
        let stored = StoredPasskey {
            id: hex(&random_bytes::<PASSKEY_ID_LEN>()?),
            name: pending.name,
            created_at: now_secs(),
            last_used_at: None,
            credential: passkey,
        };
        let summary = PasskeySummary {
            id: stored.id.clone(),
            name: stored.name.clone(),
            created_at: stored.created_at,
            last_used_at: None,
        };
        candidate.passkey_user_id = Some(pending.user_id.to_string());
        candidate.passkey_rp_id = Some(runtime.rp_id.clone());
        candidate.passkeys.push(stored);
        let token = self.commit_and_reissue(&mut flow, Some(ip), candidate, None)?;
        Ok((summary, token))
    }

    pub fn passkey_rename(
        &self,
        session_token: &str,
        id: &str,
        name: &str,
    ) -> Result<(), AuthError> {
        let name = validate_passkey_name(name)?;
        let _flow = lock(&self.flow);
        if !self.session_valid(session_token) {
            return Err(AuthError::ChallengeExpired);
        }
        let mut candidate = self.snapshot();
        let Some(passkey) = candidate
            .passkeys
            .iter_mut()
            .find(|passkey| passkey.id == id)
        else {
            return Err(AuthError::PasskeyNotFound);
        };
        passkey.name = name;
        self.commit_state(candidate)
    }

    pub fn passkey_remove_verified(
        &self,
        ip: IpAddr,
        session_token: &str,
        id: &str,
        password: &str,
        code: Option<&str>,
    ) -> Result<String, AuthError> {
        let mut flow = lock(&self.flow);
        if !self.session_valid(session_token) {
            return Err(AuthError::ChallengeExpired);
        }
        let (mut candidate, totp_step, _) = self.verified_step_up(&mut flow, ip, password, code)?;
        let Some(index) = candidate
            .passkeys
            .iter()
            .position(|passkey| passkey.id == id)
        else {
            return Err(AuthError::PasskeyNotFound);
        };
        candidate.passkeys.remove(index);
        self.commit_and_reissue(&mut flow, Some(ip), candidate, totp_step)
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
        self.upgrade_password_hash(&mut flow, password);
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

fn validate_passkey_name(name: &str) -> Result<String, AuthError> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_PASSKEY_NAME_BYTES || name.chars().any(char::is_control)
    {
        return Err(AuthError::PasskeyNameInvalid);
    }
    Ok(name.to_string())
}

/// Stores a hash of `password` under a fresh salt.
fn set_password(state: &mut AuthState, password: &str) -> Result<(), AuthError> {
    let salt = random_bytes::<SALT_LEN>()?;
    state.password_salt = Some(hex(&salt));
    state.password_key = Some(hex(&derive_key(password, &salt, PASSWORD_ITERATIONS)));
    state.password_iterations = Some(PASSWORD_ITERATIONS.get());
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
    let h = derive_key(
        &format!("backup-salt:{normalized}"),
        b"cfddnswebui-salt",
        BACKUP_CODE_ITERATIONS,
    );
    s.copy_from_slice(&h[..SALT_LEN]);
    s
}

/// Stored as `<salt hex>:<key hex>` with a fresh random salt for each code.
fn hash_backup_code(code: &str) -> Result<String, AuthError> {
    let salt = random_bytes::<SALT_LEN>()?;
    let key = derive_key(&normalize_code(code), &salt, BACKUP_CODE_ITERATIONS);
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
        key_matches(code, &salt, BACKUP_CODE_ITERATIONS, &expected)
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
    if state.password_hash_iterations().is_none() {
        return Err("invalid auth password iteration count".to_string());
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
    if state.passkeys.len() > MAX_PASSKEYS {
        return Err("too many stored passkeys".to_string());
    }
    if state
        .passkey_user_id
        .as_deref()
        .is_some_and(|id| Uuid::parse_str(id).is_err())
    {
        return Err("invalid passkey user ID".to_string());
    }
    if !state.passkeys.is_empty()
        && (state.passkey_user_id.is_none() || state.passkey_rp_id.is_none())
    {
        return Err("stored passkeys are missing account metadata".to_string());
    }
    if state
        .passkey_rp_id
        .as_deref()
        .is_some_and(|rp_id| rp_id.is_empty() || !rp_id.is_ascii() || rp_id.len() > 253)
    {
        return Err("invalid passkey relying-party ID".to_string());
    }
    for (index, passkey) in state.passkeys.iter().enumerate() {
        if !valid_hex(&passkey.id, PASSKEY_ID_LEN)
            || validate_passkey_name(&passkey.name).as_deref() != Ok(passkey.name.as_str())
            || passkey
                .last_used_at
                .is_some_and(|last_used| last_used < passkey.created_at)
        {
            return Err("invalid stored passkey metadata".to_string());
        }
        if state.passkeys.iter().skip(index + 1).any(|other| {
            other.id == passkey.id || other.credential.cred_id() == passkey.credential.cred_id()
        }) {
            return Err("duplicate stored passkey".to_string());
        }
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
mod tests;
