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
    let derived = derive_key(
        &format!("backup-salt:{normalized}"),
        b"cfddnswebui-salt",
        NonZeroU32::new(100_000).unwrap(),
    );
    pbkdf2_key(normalized, &derived[..SALT_LEN], 100_000)
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
            auth.change_password_verified(ip, PASSWORD, Some("invalid"), "replacement-password")
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
            "password_key": pbkdf2_key(PASSWORD, &salt, 100_000).to_uppercase()
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
    file.write(
        serde_json::json!({
            "password_salt": hex(&salt),
            "password_key": pbkdf2_key(PASSWORD, &salt, 100_000),
            "totp_secret": format!(" {}=== ", crate::totp::base32_encode(secret).to_lowercase()),
            "backup_code_hashes": []
        })
        .to_string(),
    );
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
            "password_key": pbkdf2_key(PASSWORD, &password_salt, 100_000),
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

/// Hex PBKDF2-HMAC-SHA256 key, computed here so the tests do not rely
/// on the code under test.
fn pbkdf2_key(secret: &str, salt: &[u8], iterations: u32) -> String {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).unwrap(),
        salt,
        secret.as_bytes(),
        &mut key,
    );
    hex(&key)
}

const LEGACY_SALT: [u8; SALT_LEN] = [7; SALT_LEN];

/// Writes a state file in the format older versions saved: no
/// `password_iterations`, and a key derived with 100,000 iterations.
fn write_legacy_state(file: &TestState, extra: serde_json::Value) {
    let mut state = serde_json::json!({
        "password_salt": hex(&LEGACY_SALT),
        "password_key": pbkdf2_key(PASSWORD, &LEGACY_SALT, 100_000),
    });
    if let (Some(state), Some(extra)) = (state.as_object_mut(), extra.as_object()) {
        state.extend(extra.clone());
    }
    file.write(state.to_string());
}

fn stored(file: &TestState) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(&file.path).unwrap()).unwrap()
}

/// Checks that the saved password hash is `password` at 600,000
/// iterations under a salt other than the legacy one.
fn assert_upgraded(file: &TestState, password: &str) {
    let saved = stored(file);
    assert_eq!(saved["password_iterations"], 600_000);
    let salt = saved["password_salt"].as_str().unwrap();
    assert_ne!(salt, hex(&LEGACY_SALT));
    let salt = hex_decode_salt(salt).unwrap();
    assert_eq!(saved["password_key"], pbkdf2_key(password, &salt, 600_000));
}

fn assert_legacy(state: &serde_json::Value) {
    assert!(state.get("password_iterations").is_none_or(|n| n.is_null()));
    assert_eq!(state["password_salt"], hex(&LEGACY_SALT));
    assert_eq!(
        state["password_key"],
        pbkdf2_key(PASSWORD, &LEGACY_SALT, 100_000)
    );
}

fn memory_state(auth: &Auth) -> serde_json::Value {
    serde_json::to_value(&*lock(&auth.state)).unwrap()
}

#[test]
fn security_new_password_hashes_use_600000_iterations() {
    let file = TestState::new();
    let auth = configured_auth(&file);
    let text = std::fs::read_to_string(&file.path).unwrap();
    assert!(text.contains("\"password_iterations\": 600000"));
    let salt = hex_decode_salt(stored(&file)["password_salt"].as_str().unwrap()).unwrap();
    assert_eq!(
        stored(&file)["password_key"],
        pbkdf2_key(PASSWORD, &salt, 600_000)
    );
    assert!(file.load().unwrap().verify_password(PASSWORD));
    auth.change_password_verified(localhost(), PASSWORD, None, "replacement-password")
        .unwrap();
    let saved = stored(&file);
    assert_eq!(saved["password_iterations"], 600_000);
    let salt = hex_decode_salt(saved["password_salt"].as_str().unwrap()).unwrap();
    assert_eq!(
        saved["password_key"],
        pbkdf2_key("replacement-password", &salt, 600_000)
    );
    let restarted = file.load().unwrap();
    assert!(restarted.verify_password("replacement-password"));
    assert!(!restarted.verify_password(PASSWORD));
}

#[test]
fn security_legacy_password_hash_is_upgraded_at_login() {
    let file = TestState::new();
    write_legacy_state(&file, serde_json::json!({}));
    let auth = file.load().unwrap();
    let ip = localhost();
    let session = auth.create_session().unwrap();
    assert!(matches!(
        auth.login_step1_session(ip, PASSWORD),
        Ok(LoginStep1Outcome::Session(_))
    ));
    assert_upgraded(&file, PASSWORD);
    assert_eq!(memory_state(&auth), stored(&file));
    assert!(auth.session_valid(&session));
    // A login with the upgraded hash leaves the file alone.
    let upgraded = std::fs::read(&file.path).unwrap();
    assert!(matches!(
        auth.login_step1_session(ip, PASSWORD),
        Ok(LoginStep1Outcome::Session(_))
    ));
    assert_eq!(std::fs::read(&file.path).unwrap(), upgraded);
    let restarted = file.load().unwrap();
    assert!(matches!(
        restarted.login_step1_session(ip, PASSWORD),
        Ok(LoginStep1Outcome::Session(_))
    ));
    assert!(matches!(
        restarted.login_step1_session(ip, "wrong-password"),
        Err(AuthError::InvalidPassword)
    ));
    assert_eq!(std::fs::read(&file.path).unwrap(), upgraded);
}

#[test]
fn security_legacy_password_hash_is_upgraded_on_the_challenge_path() {
    let file = TestState::new();
    let secret = crate::totp::base32_encode(b"synthetic totp key");
    write_legacy_state(
        &file,
        serde_json::json!({
            "totp_secret": secret,
            "backup_code_hashes": [hash_backup_code("ABCD-EFGH").unwrap()]
        }),
    );
    let auth = file.load().unwrap();
    let ip = localhost();
    let session = auth.create_session().unwrap();
    lock(&auth.flow).challenges.insert(
        "synthetic-challenge".to_string(),
        Instant::now() + CHALLENGE_TTL,
    );
    let token = challenge(&auth, ip, PASSWORD);
    assert_upgraded(&file, PASSWORD);
    assert_eq!(memory_state(&auth), stored(&file));
    assert!(auth.session_valid(&session));
    assert!(lock(&auth.flow)
        .challenges
        .contains_key("synthetic-challenge"));
    // This path never calls `record_success`, so an empty limiter shows
    // the upgrade recorded no failure.
    assert!(lock(&auth.limiter.state).is_empty());
    assert_eq!(lock(&auth.flow).factor_failures.0, 0);
    // Consuming a backup code saves the state again and keeps the upgrade.
    assert!(matches!(
        auth.login_step2_session(ip, &token, "abcd-efgh"),
        Ok((Login2faOutcome::BackupCode { remaining: 0 }, _))
    ));
    assert_upgraded(&file, PASSWORD);
    let restarted = file.load().unwrap();
    let token = challenge(&restarted, ip, PASSWORD);
    assert!(matches!(
        restarted.login_step2_session(ip, &token, &totp_now(&secret)),
        Ok((Login2faOutcome::Totp, _))
    ));
}

#[test]
fn security_legacy_password_hash_is_upgraded_when_enrolling_2fa() {
    let file = TestState::new();
    write_legacy_state(&file, serde_json::json!({}));
    let auth = file.load().unwrap();
    let session = auth.create_session().unwrap();
    let (secret, _, _) = auth
        .totp_enroll_begin_verified(localhost(), PASSWORD)
        .unwrap();
    assert_upgraded(&file, PASSWORD);
    assert!(auth.session_valid(&session));
    assert!(lock(&auth.flow).pending_totp.is_some());
    assert!(lock(&auth.limiter.state).is_empty());
    assert_eq!(lock(&auth.flow).factor_failures.0, 0);
    auth.totp_enroll_confirm_session(&totp_now(&secret))
        .unwrap();
    assert_upgraded(&file, PASSWORD);
    assert!(file.load().unwrap().totp_enabled());
}

#[test]
fn security_stronger_password_hash_is_kept() {
    let file = TestState::new();
    let salt = [9; SALT_LEN];
    file.write(
        serde_json::json!({
            "password_salt": hex(&salt),
            "password_key": pbkdf2_key(PASSWORD, &salt, 700_000),
            "password_iterations": 700_000
        })
        .to_string(),
    );
    let saved = std::fs::read(&file.path).unwrap();
    let auth = file.load().unwrap();
    assert!(matches!(
        auth.login_step1_session(localhost(), PASSWORD),
        Ok(LoginStep1Outcome::Session(_))
    ));
    assert_eq!(std::fs::read(&file.path).unwrap(), saved);
    assert_eq!(memory_state(&auth)["password_iterations"], 700_000);
}

#[test]
fn security_wrong_password_does_not_rewrite_legacy_hash() {
    let file = TestState::new();
    write_legacy_state(&file, serde_json::json!({}));
    let legacy = std::fs::read(&file.path).unwrap();
    let auth = file.load().unwrap();
    let ip = localhost();
    assert!(matches!(
        auth.login_step1_session(ip, "wrong-password"),
        Err(AuthError::InvalidPassword)
    ));
    assert_eq!(
        auth.totp_enroll_begin_verified(ip, "wrong-password")
            .unwrap_err(),
        AuthError::InvalidPassword
    );
    assert_eq!(std::fs::read(&file.path).unwrap(), legacy);
    assert_legacy(&memory_state(&auth));
    // The right password still upgrades afterwards.
    assert!(matches!(
        auth.login_step1_session(ip, PASSWORD),
        Ok(LoginStep1Outcome::Session(_))
    ));
    assert_upgraded(&file, PASSWORD);
}

#[test]
fn security_legacy_upgrade_save_failure_still_logs_in() {
    let file = TestState::new();
    write_legacy_state(&file, serde_json::json!({}));
    let auth = Auth::new(Duration::from_secs(60), &file.path, PP::new(true, true)).unwrap();
    let ip = localhost();
    let session = auth.create_session().unwrap();
    let saved = block_saves(&file);
    let (outcome, logged) = crate::pp::capture_stderr(|| auth.login_step1_session(ip, PASSWORD));
    assert!(matches!(outcome, Ok(LoginStep1Outcome::Session(_))));
    assert_eq!(logged.lines().count(), 1, "{logged}");
    assert!(logged.starts_with(crate::pp::EMOJI_LOCK), "{logged}");
    for secret in [
        PASSWORD.to_string(),
        hex(&LEGACY_SALT),
        pbkdf2_key(PASSWORD, &LEGACY_SALT, 100_000),
    ] {
        assert!(!logged.contains(&secret));
    }
    assert_legacy(&memory_state(&auth));
    assert!(auth.session_valid(&session));
    assert_eq!(lock(&auth.flow).factor_failures.0, 0);
    // Nothing was written: the blocking directory is still empty and no
    // temporary file was left next to it.
    assert_eq!(std::fs::read_dir(&file.path).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&file.dir).unwrap().count(), 1);
    restore_saves(&file, saved);
    assert_legacy(&stored(&file));
    assert!(file.load().unwrap().verify_password(PASSWORD));
    // A login after the retry delay tries again.
    lock(&auth.flow).upgrade_retry_after = Some(Instant::now());
    assert!(matches!(
        auth.login_step1_session(ip, PASSWORD),
        Ok(LoginStep1Outcome::Session(_))
    ));
    assert_upgraded(&file, PASSWORD);
    assert!(auth.session_valid(&session));
}

#[test]
fn security_legacy_upgrade_save_failure_still_issues_challenge() {
    let file = TestState::new();
    let secret = crate::totp::base32_encode(b"synthetic totp key");
    write_legacy_state(&file, serde_json::json!({ "totp_secret": secret }));
    let auth = file.load().unwrap();
    let ip = localhost();
    let session = auth.create_session().unwrap();
    let saved = block_saves(&file);
    let (token, logged) = crate::pp::capture_stderr(|| challenge(&auth, ip, PASSWORD));
    assert_eq!(logged.lines().count(), 1, "{logged}");
    assert!(!logged.contains(PASSWORD));
    assert_legacy(&memory_state(&auth));
    assert!(auth.session_valid(&session));
    assert!(lock(&auth.limiter.state).is_empty());
    assert_eq!(lock(&auth.flow).factor_failures.0, 0);
    assert_eq!(std::fs::read_dir(&file.path).unwrap().count(), 0);
    restore_saves(&file, saved);
    assert_legacy(&stored(&file));
    assert!(matches!(
        auth.login_step2_session(ip, &token, &totp_now(&secret)),
        Ok((Login2faOutcome::Totp, _))
    ));
    assert_legacy(&stored(&file));
}

#[test]
fn security_failed_upgrade_save_backs_off() {
    let file = TestState::new();
    write_legacy_state(&file, serde_json::json!({}));
    let auth = file.load().unwrap();
    let ip = localhost();
    let saved = block_saves(&file);
    // Each failed save logs one warning, so the line count is the number
    // of save attempts.
    let (outcomes, logged) = crate::pp::capture_stderr(|| {
        [
            auth.login_step1_session(ip, PASSWORD),
            auth.login_step1_session(ip, PASSWORD),
        ]
    });
    for outcome in outcomes {
        assert!(matches!(outcome, Ok(LoginStep1Outcome::Session(_))));
    }
    assert_eq!(logged.lines().count(), 1, "{logged}");
    assert_legacy(&memory_state(&auth));
    let retry_after = lock(&auth.flow).upgrade_retry_after.unwrap();
    assert!(retry_after > Instant::now() + Duration::from_secs(9 * 60));
    assert!(retry_after <= Instant::now() + UPGRADE_RETRY_DELAY);
    // Once the delay has passed, the next login tries again.
    lock(&auth.flow).upgrade_retry_after = Some(Instant::now());
    let (outcome, logged) = crate::pp::capture_stderr(|| auth.login_step1_session(ip, PASSWORD));
    assert!(matches!(outcome, Ok(LoginStep1Outcome::Session(_))));
    assert_eq!(logged.lines().count(), 1, "{logged}");
    // Saves work again, but the new delay still holds the upgrade back.
    restore_saves(&file, saved);
    let (outcome, logged) = crate::pp::capture_stderr(|| auth.login_step1_session(ip, PASSWORD));
    assert!(matches!(outcome, Ok(LoginStep1Outcome::Session(_))));
    assert!(logged.is_empty(), "{logged}");
    assert_legacy(&stored(&file));
    // A restart forgets the delay.
    let restarted = file.load().unwrap();
    assert!(matches!(
        restarted.login_step1_session(ip, PASSWORD),
        Ok(LoginStep1Outcome::Session(_))
    ));
    assert_upgraded(&file, PASSWORD);
}

#[test]
fn startup_rejects_out_of_range_password_iterations() {
    let file = TestState::new();
    for (iterations, accepted) in [
        (0, false),
        (99_999, false),
        (100_000, true),
        (600_000, true),
        (6_000_000, true),
        (6_000_001, false),
        (u32::MAX, false),
    ] {
        file.write(
            serde_json::json!({
                "password_salt": hex(&[0; SALT_LEN]),
                "password_key": hex(&[0; KEY_LEN]),
                "password_iterations": iterations
            })
            .to_string(),
        );
        match file.load() {
            Ok(_) => assert!(accepted, "{iterations} must fail startup"),
            Err(error) => {
                assert!(!accepted, "{iterations} must be accepted");
                assert_eq!(error, "invalid auth password iteration count");
            }
        }
    }
    // Null loads like a missing field, as the other optional fields do.
    file.write(
        serde_json::json!({
            "password_salt": hex(&LEGACY_SALT),
            "password_key": pbkdf2_key(PASSWORD, &LEGACY_SALT, 100_000),
            "password_iterations": null
        })
        .to_string(),
    );
    let auth = file.load().unwrap();
    assert_eq!(
        lock(&auth.state).password_hash_iterations(),
        Some(LEGACY_PASSWORD_ITERATIONS)
    );
    assert_eq!(LEGACY_PASSWORD_ITERATIONS.get(), 100_000);
    assert!(auth.verify_password(PASSWORD));
    for value in [
        serde_json::json!(-1),
        serde_json::json!(600_000.5),
        serde_json::json!("600000"),
        serde_json::json!(u64::from(u32::MAX) + 1),
    ] {
        file.write(
            serde_json::json!({
                "password_salt": hex(&[0; SALT_LEN]),
                "password_key": hex(&[0; KEY_LEN]),
                "password_iterations": value
            })
            .to_string(),
        );
        assert!(file.load().is_err(), "{value} must fail startup");
    }
}

#[test]
fn backup_code_hashes_use_100000_iterations() {
    let stored = hash_backup_code("ABCD-EFGH").unwrap();
    let (salt, key) = stored.split_once(':').unwrap();
    let salt = hex_decode_salt(salt).unwrap();
    assert_eq!(key, pbkdf2_key("ABCDEFGH", &salt, 100_000));
    assert!(backup_matches(&stored, "abcd-efgh"));
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
