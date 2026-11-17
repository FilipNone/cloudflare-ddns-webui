//! HTTP routing: static GUI assets, session auth (first-run setup, 2FA),
//! UI customization, and the JSON API that proxies the Cloudflare API.

use crate::auth::{Auth, AuthError, Login2faOutcome, LoginStep1Outcome};
use crate::cloudflare::{
    ApiFailure, CaaData, CloudflareClient, RecordData, RecordPatch, RecordPayload, SrvData,
    SvcbData,
};
use crate::config::{bare_url, host_ip, is_loopback_host, valid_ttl, Config, MAX_RECORD_COMMENT};
use crate::customize::{UiError, UiStore};
use crate::ddns;
use crate::http::{Request, Response};
use crate::pp::{self, PP};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, LazyLock};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SESSION_COOKIE: &str = "cfddns_session";
/// The cookie name with `SECURE_COOKIES=true`. Browsers accept the `__Host-`
/// prefix only on a Secure cookie with `Path=/` and no Domain, so another
/// subdomain cannot set or shadow it.
const SECURE_SESSION_COOKIE: &str = "__Host-cfddns_session";

static INDEX_HTML: LazyLock<String> =
    LazyLock::new(|| include_str!("../web/index.html").replace("__VERSION__", VERSION));
const STYLE_CSS: &str = include_str!("../web/style.css");
const FAVICON_SVG: &str = include_str!("../web/favicon.svg");

const JAVASCRIPT: &str = "application/javascript; charset=utf-8";

/// Embeds `web/<file>` as a script served at `/static/<file>`.
macro_rules! script {
    ($file:literal) => {
        (
            concat!("/static/", $file),
            include_str!(concat!("../web/", $file)),
        )
    };
}

/// Path and body of every script that index.html loads.
const SCRIPTS: &[(&str, &str)] = &[
    script!("js/core.js"),
    script!("js/i18n.js"),
    script!("js/ui.js"),
    script!("js/api.js"),
    script!("js/login.js"),
    script!("js/dashboard.js"),
    script!("js/records.js"),
    script!("js/record-modals.js"),
    script!("js/settings.js"),
    script!("app.js"),
];

const PROXIABLE_TYPES: [&str; 3] = ["A", "AAAA", "CNAME"];
pub const GITHUB_URL: &str = "https://github.com/FilipNone/cloudflare-ddns-webui";

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; \
    base-uri 'self'; form-action 'self'";
/// The GUI uses none of these browser features.
const PERMISSIONS_POLICY: &str = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";

pub struct AppState {
    pub cfg: Config,
    pub cf: CloudflareClient,
    pub detector: ddns::Detector,
    pub auth: Auth,
    pub ui: UiStore,
    pub pp: PP,
    pub ddns_running: std::sync::atomic::AtomicBool,
}

struct DdnsCycleGuard<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for DdnsCycleGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

// --- DTOs ---
// Unknown fields are rejected, so a misspelled field gets a 400.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBody {
    password: String,
    confirm: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpBody {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login2faBody {
    challenge: String,
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePasswordBody {
    current_password: String,
    code: Option<String>,
    new_password: String,
    confirm: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccentBody {
    accent: Option<String>,
}

/// Body of record create and update requests.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordBody {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: Option<String>,
    proxied: Option<bool>,
    ttl: Option<i64>,
    comment: Option<String>,
    tags: Option<Vec<String>>,
    priority: Option<u16>,
    /// Its shape depends on the record type, so `record_data` parses it.
    data: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BulkBody {
    action: String,
    ids: Vec<String>,
    patch: Option<BulkPatch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BulkPatch {
    ttl: Option<i64>,
    proxied: Option<bool>,
    comment: Option<String>,
    tags: Option<Vec<String>>,
}

// --- Response helpers ---

/// The headers every response from `handle` carries.
fn security_headers(cfg: &Config) -> Vec<(String, String)> {
    let mut headers = vec![
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("Permissions-Policy", PERMISSIONS_POLICY),
    ];
    // An https PUBLIC_ORIGIN is the only setup where browsers are known to
    // reach the GUI over HTTPS.
    if cfg
        .public_origin
        .as_ref()
        .is_some_and(|origin| origin.scheme() == "https")
    {
        headers.push(("Strict-Transport-Security", "max-age=31536000"));
    }
    headers
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn api_response(resp: Response) -> Response {
    resp.header("Cache-Control", "no-store")
}

fn api_json<T: serde::Serialize>(status: u16, value: &T) -> Response {
    api_response(Response::json(status, value))
}

fn api_error(status: u16, message: &str) -> Response {
    api_response(Response::json_error(status, message))
}

fn bad_request(message: &str) -> Response {
    api_error(400, message)
}

fn not_found() -> Response {
    api_error(404, "not found")
}

fn ok() -> Response {
    api_json(200, &json!({ "ok": true }))
}

fn cf_error_response(e: ApiFailure) -> Response {
    let status = match e.status {
        400 => 400,
        404 => 404,
        429 => 429,
        _ => 502,
    };
    api_error(status, &e.to_string())
}

fn json_body<T: DeserializeOwned>(req: &Request) -> Result<T, Response> {
    req.json().map_err(|e| bad_request(&e))
}

fn cookie_name(cfg: &Config) -> &'static str {
    if cfg.secure_cookies {
        SECURE_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    }
}

/// Builds the session Set-Cookie value. Logout sends an empty value with
/// `Max-Age=0` and the same attributes, which makes the browser drop it.
fn session_cookie(cfg: &Config, token: &str, max_age: u64) -> String {
    let mut cookie = format!(
        "{}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}",
        cookie_name(cfg)
    );
    if cfg.secure_cookies {
        cookie.push_str("; Secure");
    }
    cookie
}

fn with_session(resp: Response, cfg: &Config, token: &str) -> Response {
    resp.header(
        "Set-Cookie",
        &session_cookie(cfg, token, cfg.session_ttl.as_secs()),
    )
}

fn session_token(state: &AppState, req: &Request) -> Option<String> {
    req.cookie(cookie_name(&state.cfg))
}

fn authenticated(state: &AppState, req: &Request) -> bool {
    session_token(state, req).is_some_and(|token| state.auth.session_valid(&token))
}

fn mutation_allowed(req: &Request) -> bool {
    req.header("x-requested-with")
        .map(|v| v == "fetch")
        .unwrap_or(false)
}

fn valid_record_type(t: &str) -> bool {
    matches!(
        t,
        "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "NS" | "SRV" | "CAA" | "PTR" | "HTTPS" | "SVCB"
    )
}

/// Checks a record TTL, where a missing one means 1 (automatic).
fn record_ttl(ttl: Option<i64>) -> Result<i64, String> {
    let ttl = ttl.unwrap_or(1);
    match u32::try_from(ttl) {
        Ok(seconds) if valid_ttl(seconds) => Ok(ttl),
        _ => Err("TTL must be 1 (auto) or between 30 and 86400 seconds".to_string()),
    }
}

fn auth_error(error: AuthError) -> Response {
    let status = match error {
        AuthError::LockedOut => 429,
        AuthError::PersistenceFailed | AuthError::Internal => 500,
        AuthError::InvalidPassword
        | AuthError::InvalidCode
        | AuthError::CodeAlreadyUsed
        | AuthError::ChallengeExpired => 401,
        AuthError::AlreadyConfigured => 409,
        AuthError::NotConfigured
        | AuthError::TotpAlreadyEnabled
        | AuthError::TotpNotEnabled
        | AuthError::EnrollmentExpired
        | AuthError::EnrollmentCodeRejected
        | AuthError::PasswordTooShort
        | AuthError::PasswordTooLong => 400,
    };
    api_error(status, error.message())
}

/// Runs an `Auth` call on the blocking pool. PBKDF2 is slow on purpose, and
/// on the single runtime thread it would stall every other connection.
async fn run_auth<T, F>(state: &Arc<AppState>, call: F) -> Result<T, AuthError>
where
    T: Send + 'static,
    F: FnOnce(&Auth) -> Result<T, AuthError> + Send + 'static,
{
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || call(&state.auth))
        .await
        .unwrap_or(Err(AuthError::Internal))
}

/// Runs a UI settings change on the blocking pool, because saving writes
/// and syncs files.
async fn run_ui<F>(state: &Arc<AppState>, change: F) -> Result<Response, Response>
where
    F: FnOnce(&UiStore) -> Result<(), UiError> + Send + 'static,
{
    let task_state = Arc::clone(state);
    match tokio::task::spawn_blocking(move || change(&task_state.ui)).await {
        Ok(Ok(())) => Ok(ok()),
        Ok(Err(UiError::Invalid(message))) => Err(bad_request(&message)),
        Ok(Err(UiError::Save(error))) => {
            state.pp.errorf(
                pp::EMOJI_ERROR,
                format!("Cannot save appearance settings: {error}"),
            );
            Err(api_error(500, "cannot save appearance settings"))
        }
        Err(_) => Err(api_error(500, "internal_error")),
    }
}

// --- Router ---

pub async fn handle(state: Arc<AppState>, req: Request) -> Response {
    let mut resp = respond(&state, req).await;
    // The shared headers go first, so a route's own policy, such as the
    // favicon's sandbox CSP, comes after the general one.
    resp.headers.splice(0..0, security_headers(&state.cfg));
    resp
}

async fn respond(state: &Arc<AppState>, req: Request) -> Response {
    if !request_origin_allowed(&state.cfg, &req) {
        return api_error(403, "untrusted Host or Origin");
    }
    // The HTTP layer serves HEAD requests as GET.
    if req.method == "GET" {
        if let Some(resp) = static_file(state, &req.path) {
            return resp;
        }
    }
    let path = req.path.clone();
    let Some(rest) = path.strip_prefix("/api/") else {
        return Response::json_error(404, "not found");
    };
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match route(state, req, &segments).await {
        Ok(resp) | Err(resp) => resp,
    }
}

fn static_file(state: &AppState, path: &str) -> Option<Response> {
    let resp = match path {
        "/" => Response::new(200, "text/html; charset=utf-8", INDEX_HTML.as_str()),
        "/static/style.css" => {
            let css = state
                .ui
                .accent()
                .map(|accent| format!("{STYLE_CSS}\n:root{{--accent:{accent};}}"))
                .unwrap_or_else(|| STYLE_CSS.to_owned());
            Response::new(200, "text/css; charset=utf-8", css)
        }
        // Always the built-in cloud, even after a custom favicon upload.
        "/static/default-logo.svg" => Response::new(200, "image/svg+xml", FAVICON_SVG),
        "/static/favicon.svg" => match state.ui.icon() {
            Some((mime, data)) => Response::new(200, &mime, data)
                .header("Content-Security-Policy", "sandbox; default-src 'none'"),
            None => Response::new(200, "image/svg+xml", FAVICON_SVG),
        },
        _ => {
            let (_, body) = SCRIPTS.iter().find(|(file, _)| *file == path)?;
            Response::new(200, JAVASCRIPT, *body)
        }
    };
    Some(resp.header("Cache-Control", "no-cache"))
}

fn request_origin_allowed(cfg: &Config, req: &Request) -> bool {
    let Some(host) = req.header("host") else {
        return false;
    };
    let scheme = cfg
        .public_origin
        .as_ref()
        .map_or("http", |url| url.scheme());
    let Ok(host_url) = reqwest::Url::parse(&format!("{scheme}://{host}")) else {
        return false;
    };
    if !bare_url(&host_url) || host_url.path() != "/" {
        return false;
    }
    let expected_origin = if let Some(trusted) = &cfg.public_origin {
        if trusted.host_str() != host_url.host_str()
            || trusted.port_or_known_default() != host_url.port_or_known_default()
        {
            return false;
        }
        trusted.origin().ascii_serialization()
    } else {
        let listen = cfg.listen.ip();
        let host_matches = if listen.is_unspecified() {
            host_ip(&host_url).is_some() || is_loopback_host(&host_url)
        } else {
            host_ip(&host_url) == Some(listen)
                || (listen.is_loopback() && is_loopback_host(&host_url))
        };
        if !host_matches || host_url.port_or_known_default() != Some(cfg.listen.port()) {
            return false;
        }
        host_url.origin().ascii_serialization()
    };
    req.header("origin")
        .is_none_or(|origin| origin == expected_origin)
}

async fn route(
    state: &Arc<AppState>,
    req: Request,
    segments: &[&str],
) -> Result<Response, Response> {
    // A cross-site page cannot add this header without a CORS preflight,
    // which this server never approves.
    if req.method != "GET" && !mutation_allowed(&req) {
        return Err(api_error(403, "missing request header"));
    }
    match (req.method.as_str(), segments) {
        ("GET", ["config"]) => return Ok(public_config(state)),
        ("POST", ["auth", "setup"]) => return setup(state, &req).await,
        ("POST", ["auth", "login"]) => return login(state, &req).await,
        ("POST", ["auth", "login", "2fa"]) => return login_2fa(state, &req).await,
        // Needs no valid session, so an expired one can still clear its cookie.
        ("POST", ["auth", "logout"]) => return Ok(logout(state, &req)),
        _ => {}
    }
    if !authenticated(state, &req) {
        return Err(api_error(401, "authentication required"));
    }
    match segments {
        ["auth", ..] => account_routes(state, &req, segments).await,
        ["ui", ..] => appearance_routes(state, req, segments).await,
        ["zones", rest @ ..] => zone_routes(state, req, rest).await,
        ["ddns", ..] => ddns_routes(state, &req, segments).await,
        _ => Err(not_found()),
    }
}

// --- Public routes ---

fn public_config(state: &AppState) -> Response {
    let ui = state.ui.status();
    api_json(
        200,
        &json!({
            "version": VERSION,
            "languages": [{ "code": "en", "name": "English" }],
            "ddns_configured": !state.cfg.domains.is_empty(),
            "configured": state.auth.is_configured(),
            "accent": ui.accent,
            "has_icon": ui.has_icon,
            "github": GITHUB_URL,
        }),
    )
}

async fn setup(state: &Arc<AppState>, req: &Request) -> Result<Response, Response> {
    if state.auth.is_configured() {
        return Err(api_error(409, "already configured"));
    }
    let body: SetupBody = json_body(req)?;
    if body.password != body.confirm {
        return Err(bad_request("passwords do not match"));
    }
    let token = run_auth(state, move |auth| {
        auth.setup_password_session(&body.password)
    })
    .await
    .map_err(auth_error)?;
    state
        .pp
        .infof(pp::EMOJI_LOCK, "Admin password created (first-run setup)");
    Ok(with_session(ok(), &state.cfg, &token))
}

async fn login(state: &Arc<AppState>, req: &Request) -> Result<Response, Response> {
    if !state.auth.is_configured() {
        return Err(api_error(428, "setup required"));
    }
    let ip = req.remote.ip();
    if state.auth.limiter().is_locked_out(ip) {
        return Err(api_error(
            429,
            "too many failed attempts - try again in a few minutes",
        ));
    }
    let body: PasswordBody = json_body(req)?;
    match run_auth(state, move |auth| {
        auth.login_step1_session(ip, &body.password)
    })
    .await
    {
        Ok(LoginStep1Outcome::Session(token)) => {
            state
                .pp
                .infof(pp::EMOJI_LOCK, format!("Successful login from {ip}"));
            let resp = api_json(200, &json!({ "ok": true, "requires_2fa": false }));
            Ok(with_session(resp, &state.cfg, &token))
        }
        Ok(LoginStep1Outcome::Challenge(challenge)) => Ok(api_json(
            200,
            &json!({ "ok": false, "requires_2fa": true, "challenge": challenge }),
        )),
        Err(AuthError::LockedOut) => Err(api_error(429, "too many failed attempts")),
        Err(AuthError::InvalidPassword) => {
            state
                .pp
                .warningf(pp::EMOJI_LOCK, format!("Failed login from {ip}"));
            Err(api_error(401, "invalid password"))
        }
        Err(e) => Err(auth_error(e)),
    }
}

async fn login_2fa(state: &Arc<AppState>, req: &Request) -> Result<Response, Response> {
    let ip = req.remote.ip();
    let body: Login2faBody = json_body(req)?;
    match run_auth(state, move |auth| {
        auth.login_step2_session(ip, &body.challenge, &body.code)
    })
    .await
    {
        Ok((Login2faOutcome::Totp, token)) => {
            state
                .pp
                .infof(pp::EMOJI_LOCK, format!("Successful 2FA login from {ip}"));
            Ok(with_session(ok(), &state.cfg, &token))
        }
        Ok((Login2faOutcome::BackupCode { remaining }, token)) => {
            state.pp.warningf(
                pp::EMOJI_LOCK,
                format!("Backup code used from {ip} ({remaining} remaining)"),
            );
            let resp = api_json(
                200,
                &json!({ "ok": true, "backup_code_used": true, "backup_codes_remaining": remaining }),
            );
            Ok(with_session(resp, &state.cfg, &token))
        }
        Err(AuthError::ChallengeExpired) => {
            Err(api_error(401, "login session expired - sign in again"))
        }
        Err(AuthError::LockedOut) => Err(api_error(429, "too many attempts - sign in again")),
        Err(e @ (AuthError::PersistenceFailed | AuthError::Internal)) => Err(auth_error(e)),
        Err(_) => Err(api_error(401, "invalid code")),
    }
}

fn logout(state: &AppState, req: &Request) -> Response {
    if let Some(token) = session_token(state, req) {
        state.auth.destroy_session(&token);
    }
    ok().header("Set-Cookie", &session_cookie(&state.cfg, "", 0))
}

// --- Account: 2FA and password ---

async fn account_routes(
    state: &Arc<AppState>,
    req: &Request,
    segments: &[&str],
) -> Result<Response, Response> {
    let ip = req.remote.ip();
    match (req.method.as_str(), segments) {
        ("GET", ["auth", "me"]) => Ok(api_json(
            200,
            &json!({
                "authenticated": true,
                "session_ttl": state.cfg.session_ttl.as_secs(),
                "totp_enabled": state.auth.totp_enabled(),
                "backup_codes_remaining": state.auth.backup_codes_remaining(),
            }),
        )),
        ("POST", ["auth", "2fa", "begin"]) => {
            let body: PasswordBody = json_body(req)?;
            let (secret, uri, qr) = run_auth(state, move |auth| {
                auth.totp_enroll_begin_verified(ip, &body.password)
            })
            .await
            .map_err(auth_error)?;
            Ok(api_json(
                200,
                &json!({ "secret": secret, "uri": uri, "qr_svg": qr }),
            ))
        }
        ("POST", ["auth", "2fa", "confirm"]) => {
            let body: TotpBody = json_body(req)?;
            let (codes, token) = run_auth(state, move |auth| {
                auth.totp_enroll_confirm_session(&body.code)
            })
            .await
            .map_err(auth_error)?;
            state.pp.infof(pp::EMOJI_LOCK, "2FA enabled");
            let resp = api_json(200, &json!({ "backup_codes": codes }));
            Ok(with_session(resp, &state.cfg, &token))
        }
        ("POST", ["auth", "2fa", "cancel"]) => {
            // Cancel waits for the lock that hashing calls hold.
            run_auth(state, |auth| {
                auth.totp_enroll_cancel();
                Ok(())
            })
            .await
            .map_err(auth_error)?;
            Ok(ok())
        }
        ("POST", ["auth", "2fa", "disable"]) => {
            let body: TotpBody = json_body(req)?;
            if !state.auth.totp_enabled() {
                return Err(bad_request("2FA is not enabled"));
            }
            let token = run_auth(state, move |auth| {
                auth.totp_disable_verified(ip, &body.code)
            })
            .await
            .map_err(auth_error)?;
            state.pp.infof(pp::EMOJI_LOCK, "2FA disabled");
            Ok(with_session(ok(), &state.cfg, &token))
        }
        ("POST", ["auth", "password"]) => {
            let body: ChangePasswordBody = json_body(req)?;
            if body.new_password != body.confirm {
                return Err(bad_request("passwords do not match"));
            }
            let token = run_auth(state, move |auth| {
                auth.change_password_verified(
                    ip,
                    &body.current_password,
                    body.code.as_deref(),
                    &body.new_password,
                )
            })
            .await
            .map_err(auth_error)?;
            state.pp.infof(pp::EMOJI_LOCK, "Admin password changed");
            // Issue a fresh session for the current caller.
            Ok(with_session(ok(), &state.cfg, &token))
        }
        _ => Err(not_found()),
    }
}

// --- UI customization ---

async fn appearance_routes(
    state: &Arc<AppState>,
    req: Request,
    segments: &[&str],
) -> Result<Response, Response> {
    match (req.method.as_str(), segments) {
        ("POST", ["ui", "accent"]) => {
            let body: AccentBody = json_body(&req)?;
            let accent = body.accent.filter(|a| !a.trim().is_empty());
            run_ui(state, move |ui| ui.set_accent(accent)).await
        }
        ("POST", ["ui", "icon"]) => {
            if req.body.is_empty() {
                return Err(bad_request("empty image"));
            }
            let mime = req
                .query
                .get("mime")
                .cloned()
                .unwrap_or_else(|| "image/png".to_string());
            let data = req.body;
            run_ui(state, move |ui| ui.set_icon(&mime, data)).await
        }
        ("DELETE", ["ui", "icon"]) => run_ui(state, |ui| ui.reset_icon()).await,
        _ => Err(not_found()),
    }
}

// --- Zones and records ---

/// Routes below `/api/zones`. `segments` starts after `zones`.
async fn zone_routes(
    state: &Arc<AppState>,
    req: Request,
    segments: &[&str],
) -> Result<Response, Response> {
    if let [zone_id, ..] = segments {
        // cloudflare.rs checks IDs as well. Checking here also rejects a bad
        // zone before a bulk delete reports one failure per record.
        crate::cloudflare::validate_identifier(zone_id).map_err(cf_error_response)?;
    }
    let cf = &state.cf;
    match (req.method.as_str(), segments) {
        ("GET", []) => Ok(api_json(
            200,
            &cf.list_zones().await.map_err(cf_error_response)?,
        )),
        ("GET", [zone_id, "records"]) => {
            let (records, total) = cf.list_records(zone_id).await.map_err(cf_error_response)?;
            Ok(api_json(
                200,
                &json!({ "records": records, "total": total }),
            ))
        }
        ("POST", [zone_id, "records"]) => {
            let payload = record_payload(json_body(&req)?).map_err(|e| bad_request(&e))?;
            let record = cf
                .create_record(zone_id, &payload)
                .await
                .map_err(cf_error_response)?;
            Ok(api_json(201, &record))
        }
        ("POST", [zone_id, "records", "bulk"]) => bulk(state, &req, zone_id).await,
        // "bulk" names the route above and is never a record ID.
        (_, [_, "records", "bulk"]) => Err(not_found()),
        // Sent to Cloudflare as PATCH, so fields the payload leaves out keep
        // their values.
        ("PUT", [zone_id, "records", record_id]) => {
            let payload = record_payload(json_body(&req)?).map_err(|e| bad_request(&e))?;
            let record = cf
                .update_record(zone_id, record_id, &payload)
                .await
                .map_err(cf_error_response)?;
            Ok(api_json(200, &record))
        }
        ("DELETE", [zone_id, "records", record_id]) => {
            cf.delete_record(zone_id, record_id)
                .await
                .map_err(cf_error_response)?;
            Ok(ok())
        }
        ("GET", [zone_id, "export"]) => {
            let bind = cf
                .export_records(zone_id)
                .await
                .map_err(cf_error_response)?;
            Ok(
                api_response(Response::new(200, "text/plain; charset=utf-8", bind))
                    .header("Content-Disposition", "attachment; filename=\"zone.txt\""),
            )
        }
        ("POST", [zone_id, "import"]) => {
            if req.body.is_empty() {
                return Err(bad_request("empty zone file"));
            }
            crate::bind::validate(&req.body).map_err(|e| bad_request(&e))?;
            let filename = req
                .query
                .get("filename")
                .cloned()
                .unwrap_or_else(|| "zone.txt".to_string());
            let result = cf
                .import_records(zone_id, &filename, req.body)
                .await
                .map_err(cf_error_response)?;
            Ok(api_json(200, &result))
        }
        _ => Err(not_found()),
    }
}

// --- DDNS ---

async fn ddns_routes(
    state: &Arc<AppState>,
    req: &Request,
    segments: &[&str],
) -> Result<Response, Response> {
    match (req.method.as_str(), segments) {
        ("GET", ["ddns", "status"]) => {
            let status = ddns::status(&state.cfg, &state.cf, &state.detector).await;
            Ok(api_json(200, &status))
        }
        ("POST", ["ddns", "update"]) => {
            if state.cfg.domains.is_empty() {
                return Err(bad_request("no DDNS domains configured (set DOMAINS)"));
            }
            if state
                .ddns_running
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::Acquire,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_err()
            {
                return Err(api_error(409, "a DDNS update is already running"));
            }
            let _cycle = DdnsCycleGuard(&state.ddns_running);
            let result = ddns::update_now(&state.cfg, &state.cf, &state.detector, || {
                authenticated(state, req)
            })
            .await;
            for line in &result.log {
                state.pp.infof("", line);
            }
            Ok(api_json(200, &result))
        }
        _ => Err(not_found()),
    }
}

// --- Record payloads ---
// The TTL rule and the comment limit come from config.rs, which applies them
// to the DDNS settings too.

/// Checks a create or update request and builds the payload for Cloudflare.
fn record_payload(body: RecordBody) -> Result<RecordPayload, String> {
    let record_type = body.record_type.as_str();
    if !valid_record_type(record_type) {
        return Err("unsupported record type".to_string());
    }
    if body.name.trim().is_empty() {
        return Err("name is required".to_string());
    }
    if body.name.len() > 253
        || body
            .name
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("invalid record name".to_string());
    }
    validate_metadata(body.comment.as_deref(), body.tags.as_deref())?;
    let proxied = body.proxied.unwrap_or(false);
    if proxied && !PROXIABLE_TYPES.contains(&record_type) {
        return Err("only A, AAAA and CNAME records can be proxied".to_string());
    }
    let ttl = record_ttl(body.ttl)?;
    let content = body.content.as_deref();
    match record_type {
        "A" | "AAAA" => {
            let ip = content
                .ok_or("content is required")?
                .parse::<std::net::IpAddr>()
                .map_err(|_| "invalid IP address")?;
            if ip.is_ipv6() != (record_type == "AAAA") {
                return Err("IP address does not match the record type".to_string());
            }
        }
        "MX" => {
            if body.priority.is_none() {
                return Err("MX records require a priority".to_string());
            }
            require_content(content)?;
        }
        "SRV" | "CAA" | "HTTPS" | "SVCB" => {}
        _ => require_content(content)?,
    }
    let data = record_data(record_type, body.data)?;
    Ok(RecordPayload {
        record_type: body.record_type,
        name: body.name,
        content: body.content,
        proxied: Some(proxied),
        // Cloudflare forces TTL to automatic when a record is proxied.
        ttl: if proxied { 1 } else { ttl },
        comment: body.comment,
        tags: body.tags,
        priority: body.priority,
        data,
    })
}

/// Parses `data` into the shape of its record type. SRV, CAA, HTTPS and SVCB
/// records require it, and other types must not send it.
fn record_data(record_type: &str, data: Option<Value>) -> Result<Option<RecordData>, String> {
    fn parse<T: DeserializeOwned>(record_type: &str, data: Value) -> Result<T, String> {
        serde_json::from_value(data).map_err(|e| format!("invalid {record_type} data: {e}"))
    }
    let structured = matches!(record_type, "SRV" | "CAA" | "HTTPS" | "SVCB");
    let Some(data) = data else {
        return if structured {
            Err(format!("{record_type} records require data fields"))
        } else {
            Ok(None)
        };
    };
    let data = match record_type {
        "SRV" => {
            let srv: SrvData = parse(record_type, data)?;
            if srv.target.is_empty() {
                return Err("SRV data requires a target".to_string());
            }
            RecordData::Srv(srv)
        }
        "CAA" => {
            let caa: CaaData = parse(record_type, data)?;
            if caa.tag.is_empty() || caa.value.is_empty() {
                return Err("CAA data requires a tag and a value".to_string());
            }
            RecordData::Caa(caa)
        }
        "HTTPS" | "SVCB" => {
            let svcb: SvcbData = parse(record_type, data)?;
            if svcb.target.is_empty() {
                return Err(format!("{record_type} data requires a target"));
            }
            RecordData::Svcb(svcb)
        }
        _ => return Err("data is only allowed for SRV, CAA, HTTPS and SVCB records".to_string()),
    };
    Ok(Some(data))
}

fn validate_metadata(comment: Option<&str>, tags: Option<&[String]>) -> Result<(), String> {
    if comment.is_some_and(|s| s.len() > MAX_RECORD_COMMENT || s.chars().any(|c| c.is_control())) {
        return Err(format!(
            "comment must be at most {MAX_RECORD_COMMENT} bytes with no control characters"
        ));
    }
    if tags.is_some_and(|tags| {
        tags.len() > 20
            || tags
                .iter()
                .any(|s| s.is_empty() || s.len() > 100 || s.chars().any(|c| c.is_control()))
    }) {
        return Err(
            "tags must contain at most 20 nonempty values of at most 100 bytes".to_string(),
        );
    }
    Ok(())
}

fn require_content(content: Option<&str>) -> Result<(), String> {
    match content {
        Some(c) if !c.trim().is_empty() => Ok(()),
        _ => Err("content is required".to_string()),
    }
}

// --- Bulk operations ---
// Bulk requests answer 200 with one result per record; the counts tell the
// caller whether some writes failed.

async fn bulk(state: &AppState, req: &Request, zone_id: &str) -> Result<Response, Response> {
    let body: BulkBody = json_body(req)?;
    if body.ids.is_empty() {
        return Err(bad_request("no record ids supplied"));
    }
    if body.ids.len() > 500 {
        return Err(bad_request(
            "too many records in one bulk operation (max 500)",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for id in &body.ids {
        crate::cloudflare::validate_identifier(id).map_err(cf_error_response)?;
        if !seen.insert(id) {
            return Err(bad_request("duplicate record ids are not allowed"));
        }
    }
    match body.action.as_str() {
        "delete" => Ok(bulk_delete(state, req, zone_id, &body.ids).await),
        "update" => bulk_update(state, req, zone_id, &body).await,
        other => Err(bad_request(&format!("unknown bulk action '{other}'"))),
    }
}

/// The result entry for a write that was not sent because the session ended.
fn unsent(id: &str) -> Value {
    json!({ "id": id, "ok": false, "error": "session expired or revoked; write not sent" })
}

fn bulk_result<T>(id: &str, result: Result<T, ApiFailure>) -> Value {
    match result {
        Ok(_) => json!({ "id": id, "ok": true }),
        Err(e) => json!({ "id": id, "ok": false, "error": e.to_string() }),
    }
}

fn bulk_response(results: Vec<Value>) -> Response {
    let succeeded = results.iter().filter(|r| r["ok"] == true).count();
    let failed = results.len().saturating_sub(succeeded);
    api_json(
        200,
        &json!({ "results": results, "succeeded": succeeded, "failed": failed }),
    )
}

async fn bulk_delete(state: &AppState, req: &Request, zone_id: &str, ids: &[String]) -> Response {
    let mut results = Vec::new();
    for id in ids {
        if !authenticated(state, req) {
            results.push(unsent(id));
            continue;
        }
        results.push(bulk_result(id, state.cf.delete_record(zone_id, id).await));
    }
    bulk_response(results)
}

async fn bulk_update(
    state: &AppState,
    req: &Request,
    zone_id: &str,
    body: &BulkBody,
) -> Result<Response, Response> {
    let patch = body
        .patch
        .as_ref()
        .ok_or_else(|| bad_request("missing patch"))?;
    if patch.ttl.is_none()
        && patch.proxied.is_none()
        && patch.comment.is_none()
        && patch.tags.is_none()
    {
        return Err(bad_request("patch changes nothing"));
    }
    validate_metadata(patch.comment.as_deref(), patch.tags.as_deref())
        .map_err(|e| bad_request(&e))?;
    let ttl = patch
        .ttl
        .map(|ttl| record_ttl(Some(ttl)))
        .transpose()
        .map_err(|e| bad_request(&e))?;

    let (all, _) = state
        .cf
        .list_records(zone_id)
        .await
        .map_err(cf_error_response)?;
    let mut records = Vec::new();
    for id in &body.ids {
        let record = all
            .iter()
            .find(|r| &r.id == id)
            .ok_or_else(|| bad_request(&format!("record id {id} not found in zone")))?;
        if patch.proxied.is_some() && !PROXIABLE_TYPES.contains(&record.record_type.as_str()) {
            return Err(bad_request(&format!(
                "record '{}' is type {} - only A, AAAA and CNAME records can be proxied",
                record.name, record.record_type
            )));
        }
        records.push(record);
    }

    // When enabling proxy, Cloudflare forces TTL to automatic.
    let ttl = if patch.proxied == Some(true) {
        Some(1)
    } else {
        ttl
    };
    let cf_patch = RecordPatch {
        ttl,
        proxied: patch.proxied,
        comment: patch.comment.clone(),
        tags: patch.tags.clone(),
        content: None,
    };

    let mut results = Vec::new();
    for record in records {
        let id = &record.id;
        if !authenticated(state, req) {
            results.push(unsent(id));
            continue;
        }
        let mut record_patch = cf_patch.clone();
        if patch.proxied != Some(false)
            && record.proxied == Some(true)
            && record_patch.ttl.is_some()
        {
            record_patch.ttl = Some(1);
        }
        results.push(bulk_result(
            id,
            state.cf.patch_record(zone_id, id, &record_patch).await,
        ));
    }
    Ok(bulk_response(results))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_config() -> Config {
        Config {
            api_token: "synthetic".into(),
            listen: "127.0.0.1:8888".parse().unwrap(),
            data_dir: String::new(),
            session_ttl: std::time::Duration::from_secs(300),
            update_timeout: std::time::Duration::from_secs(5),
            detection_timeout: std::time::Duration::from_secs(2),
            secure_cookies: false,
            public_origin: None,
            domains: vec![],
            ip4_domains: vec![],
            ip6_domains: vec![],
            ddns_contract: "standalone-v1".into(),
            managed_record_comment: None,
            ip4_provider: "none".into(),
            ip6_provider: "none".into(),
            ttl: 1,
            proxied: false,
            record_comment: None,
            emoji: false,
            quiet: true,
            api_base: None,
        }
    }

    fn fixture_request(host: &str, origin: Option<&str>) -> Request {
        let mut headers = vec![("host".into(), host.into())];
        if let Some(origin) = origin {
            headers.push(("origin".into(), origin.into()));
        }
        Request {
            method: "POST".into(),
            path: "/api/auth/setup".into(),
            query: Default::default(),
            headers,
            body: vec![],
            remote: "127.0.0.1:12345".parse().unwrap(),
        }
    }

    const PASSWORD: &str = "synthetic-password";
    const ZONE: &str = "0123456789abcdef0123456789abcdef";

    /// App state over a temporary data directory. Cloudflare calls go to a
    /// loopback listener that counts connections and closes them unanswered.
    struct Fixture {
        dir: std::path::PathBuf,
        state: Arc<AppState>,
        upstream_hits: Arc<std::sync::atomic::AtomicUsize>,
        upstream: tokio::task::JoinHandle<()>,
    }

    impl Fixture {
        async fn new() -> Self {
            Self::with_config(|_| {}).await
        }

        async fn with_config(change: impl FnOnce(&mut Config)) -> Self {
            let _ = rustls::crypto::ring::default_provider().install_default();
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "ddns-routes-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api_base = format!("http://{}/client/v4", listener.local_addr().unwrap());
            let upstream_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let hits = upstream_hits.clone();
            let upstream = tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    drop(socket);
                }
            });
            let mut cfg = fixture_config();
            cfg.data_dir = dir.to_str().unwrap().to_owned();
            change(&mut cfg);
            let state = Arc::new(AppState {
                cf: CloudflareClient::new("synthetic", cfg.update_timeout, Some(&api_base))
                    .unwrap(),
                detector: ddns::Detector::new(cfg.detection_timeout).unwrap(),
                auth: Auth::new(
                    cfg.session_ttl,
                    dir.join("state.json").to_str().unwrap(),
                    PP::new(false, true),
                )
                .unwrap(),
                ui: UiStore::new(&cfg.data_dir, PP::new(false, true)).unwrap(),
                pp: PP::new(false, true),
                ddns_running: std::sync::atomic::AtomicBool::new(false),
                cfg,
            });
            Self {
                dir,
                state,
                upstream_hits,
                upstream,
            }
        }

        /// Creates the admin account and returns a Cookie header for it.
        fn login(&self) -> String {
            let token = self.state.auth.setup_password_session(PASSWORD).unwrap();
            format!("{}={token}", SESSION_COOKIE)
        }

        fn upstream_hits(&self) -> usize {
            self.upstream_hits.load(std::sync::atomic::Ordering::SeqCst)
        }

        async fn get(&self, path: &str) -> Response {
            self.send("GET", path, None, b"").await
        }

        async fn send(
            &self,
            method: &str,
            path: &str,
            cookie: Option<&str>,
            body: &[u8],
        ) -> Response {
            let mut req = fixture_request("localhost:8888", None);
            req.method = method.into();
            req.path = path.into();
            req.headers
                .push(("x-requested-with".into(), "fetch".into()));
            if let Some(cookie) = cookie {
                req.headers.push(("cookie".into(), cookie.into()));
            }
            req.body = body.to_vec();
            handle(self.state.clone(), req).await
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.upstream.abort();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
        resp.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn body_json(resp: &Response) -> serde_json::Value {
        serde_json::from_slice(&resp.body).unwrap()
    }

    #[tokio::test]
    async fn logout_clears_the_cookie_without_a_valid_session() {
        let fixture = Fixture::new().await;
        fixture.login();
        for cookie in [None, Some("cfddns_session=expired-or-forged")] {
            let resp = fixture.send("POST", "/api/auth/logout", cookie, b"").await;
            assert_eq!(resp.status, 200);
            let cleared = header(&resp, "Set-Cookie").unwrap();
            assert!(cleared.starts_with("cfddns_session=;"), "{cleared}");
            assert!(cleared.contains("Max-Age=0") && cleared.contains("HttpOnly"));
            assert!(cleared.contains("SameSite=Strict") && cleared.contains("Path=/"));
        }
        let mut req = fixture_request("localhost:8888", None);
        req.path = "/api/auth/logout".into();
        assert_eq!(handle(fixture.state.clone(), req).await.status, 403);
    }

    #[tokio::test]
    async fn secure_cookies_use_the_host_prefix_for_issue_read_and_clear() {
        let fixture = Fixture::with_config(|cfg| cfg.secure_cookies = true).await;
        let token = fixture.state.auth.setup_password_session(PASSWORD).unwrap();
        let plain = format!("cfddns_session={token}");
        let prefixed = format!("__Host-cfddns_session={token}");
        assert_eq!(
            fixture
                .send("GET", "/api/auth/me", Some(&plain), b"")
                .await
                .status,
            401
        );
        assert_eq!(
            fixture
                .send("GET", "/api/auth/me", Some(&prefixed), b"")
                .await
                .status,
            200
        );
        let login = fixture
            .send(
                "POST",
                "/api/auth/login",
                None,
                br#"{"password":"synthetic-password"}"#,
            )
            .await;
        let issued = header(&login, "Set-Cookie").unwrap();
        assert!(issued.starts_with("__Host-cfddns_session=") && issued.contains("; Secure"));
        assert!(!issued.contains("Domain"));
        let logout = fixture
            .send("POST", "/api/auth/logout", Some(&prefixed), b"")
            .await;
        let cleared = header(&logout, "Set-Cookie").unwrap();
        assert!(cleared.starts_with("__Host-cfddns_session=;"), "{cleared}");
        assert!(cleared.contains("Max-Age=0") && cleared.contains("; Secure"));
        assert_eq!(
            fixture
                .send("GET", "/api/auth/me", Some(&prefixed), b"")
                .await
                .status,
            401
        );
    }

    #[tokio::test]
    async fn bulk_is_a_post_route_and_never_a_record_id() {
        let fixture = Fixture::new().await;
        let cookie = fixture.login();
        let path = format!("/api/zones/{ZONE}/records/bulk");
        for method in ["DELETE", "PUT", "GET"] {
            let resp = fixture
                .send(
                    method,
                    &path,
                    Some(&cookie),
                    br#"{"type":"A","name":"example.com","content":"192.0.2.1"}"#,
                )
                .await;
            assert_eq!(resp.status, 404, "{method}");
        }
        assert_eq!(fixture.upstream_hits(), 0);
    }

    #[tokio::test]
    async fn bulk_update_rejects_an_empty_patch_before_any_request() {
        let fixture = Fixture::new().await;
        let cookie = fixture.login();
        let path = format!("/api/zones/{ZONE}/records/bulk");
        let body = json!({"action": "update", "ids": [ZONE], "patch": {}}).to_string();
        let resp = fixture
            .send("POST", &path, Some(&cookie), body.as_bytes())
            .await;
        assert_eq!(resp.status, 400);
        assert_eq!(fixture.upstream_hits(), 0);
    }

    #[tokio::test]
    async fn appearance_save_failures_are_server_errors_without_details() {
        let fixture = Fixture::new().await;
        let cookie = fixture.login();
        std::fs::create_dir(fixture.dir.join("ui-settings.json")).unwrap();
        let accent = fixture
            .send(
                "POST",
                "/api/ui/accent",
                Some(&cookie),
                br##"{"accent":"#123456"}"##,
            )
            .await;
        let mut req = fixture_request("localhost:8888", None);
        req.path = "/api/ui/icon".into();
        req.query.insert("mime".into(), "image/png".into());
        req.headers
            .push(("x-requested-with".into(), "fetch".into()));
        req.headers.push(("cookie".into(), cookie.clone()));
        req.body = fixture_png();
        let icon = handle(fixture.state.clone(), req).await;
        let reset = fixture
            .send("DELETE", "/api/ui/icon", Some(&cookie), b"")
            .await;
        for resp in [accent, icon, reset] {
            assert_eq!(resp.status, 500);
            let message = body_json(&resp)["error"].as_str().unwrap().to_owned();
            assert!(
                !message.contains(fixture.dir.to_str().unwrap()),
                "{message}"
            );
            assert!(!message.contains("os error"), "{message}");
        }
    }

    #[tokio::test]
    async fn request_bodies_reject_unknown_fields() {
        let fixture = Fixture::new().await;
        let cookie = fixture.login();
        for (method, path, body) in [
            (
                "POST",
                "/api/ui/accent",
                json!({"accent": "#123456", "extra": 1}),
            ),
            (
                "POST",
                "/api/auth/login",
                json!({"password": PASSWORD, "remember": true}),
            ),
            (
                "POST",
                "/api/auth/password",
                json!({"current_password": PASSWORD, "new_password": "synthetic-new",
                       "confirm": "synthetic-new", "code": null, "admin": true}),
            ),
            (
                "POST",
                &format!("/api/zones/{ZONE}/records"),
                json!({"type": "A", "name": "example.com", "content": "192.0.2.1", "zone": ZONE}),
            ),
            (
                "POST",
                &format!("/api/zones/{ZONE}/records/bulk"),
                json!({"action": "update", "ids": [ZONE], "patch": {"content": "192.0.2.1"}}),
            ),
        ] {
            let resp = fixture
                .send(method, path, Some(&cookie), body.to_string().as_bytes())
                .await;
            assert_eq!(resp.status, 400, "{path}");
        }
        assert_eq!(fixture.state.ui.accent(), None);
        assert_eq!(fixture.upstream_hits(), 0);
    }

    #[tokio::test]
    async fn structured_data_is_rejected_for_other_record_types() {
        let fixture = Fixture::new().await;
        let cookie = fixture.login();
        let body = json!({"type": "A", "name": "example.com", "content": "192.0.2.1",
                          "data": {"priority": 1, "weight": 1, "port": 443, "target": "example.com"}});
        let path = format!("/api/zones/{ZONE}/records");
        let resp = fixture
            .send("POST", &path, Some(&cookie), body.to_string().as_bytes())
            .await;
        assert_eq!(resp.status, 400);
        assert_eq!(fixture.upstream_hits(), 0);
    }

    #[tokio::test]
    async fn public_config_does_not_reveal_two_factor_state() {
        let fixture = Fixture::new().await;
        let config = body_json(&fixture.get("/api/config").await);
        assert!(config.get("totp_enabled").is_none(), "{config}");
        assert_eq!(config["configured"], false);
    }

    #[tokio::test]
    async fn every_response_carries_isolation_headers() {
        let fixture = Fixture::new().await;
        fixture
            .state
            .ui
            .set_icon("image/png", fixture_png())
            .unwrap();
        for path in [
            "/",
            "/static/app.js",
            "/static/favicon.svg",
            "/api/config",
            "/missing",
        ] {
            let resp = fixture.get(path).await;
            assert_eq!(
                header(&resp, "Cross-Origin-Opener-Policy"),
                Some("same-origin"),
                "{path}"
            );
            assert_eq!(
                header(&resp, "Cross-Origin-Resource-Policy"),
                Some("same-origin"),
                "{path}"
            );
            let permissions = header(&resp, "Permissions-Policy").unwrap_or_default();
            for feature in ["camera=()", "microphone=()", "geolocation=()"] {
                assert!(permissions.contains(feature), "{path}: {permissions}");
            }
            assert_eq!(header(&resp, "Strict-Transport-Security"), None, "{path}");
        }
        let favicon = fixture.get("/static/favicon.svg").await;
        assert_eq!(
            (favicon.status, favicon.content_type.as_str()),
            (200, "image/png")
        );
        assert_eq!(favicon.body, fixture_png());
        let policies: Vec<&str> = favicon
            .headers
            .iter()
            .filter(|(name, _)| name == "Content-Security-Policy")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(
            policies,
            [CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'"]
        );
    }

    #[tokio::test]
    async fn every_script_in_index_html_is_served_as_javascript() {
        let fixture = Fixture::new().await;
        let html = String::from_utf8(fixture.get("/").await.body).unwrap();
        let mut listed = Vec::new();
        for tag in html.split("<script").skip(1) {
            let (attributes, rest) = tag.split_once('>').unwrap();
            // Any text before </script> would be an inline script.
            assert!(rest.starts_with("</script>"), "inline script: {tag}");
            let src = attributes
                .split_once(" src=\"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(src, _)| src)
                .unwrap_or_else(|| panic!("script without src: {attributes}"));
            let path = src
                .strip_suffix(&format!("?v={VERSION}"))
                .unwrap_or_else(|| panic!("{src} lacks the version query"));
            let resp = fixture.get(path).await;
            assert_eq!(
                (resp.status, resp.content_type.as_str()),
                (200, JAVASCRIPT),
                "{path}"
            );
            assert!(!resp.body.is_empty(), "{path}");
            assert_eq!(header(&resp, "Cache-Control"), Some("no-cache"), "{path}");
            listed.push(path);
        }
        assert_eq!(listed.last(), Some(&"/static/app.js"));
        let mut served: Vec<&str> = SCRIPTS.iter().map(|(path, _)| *path).collect();
        listed.sort_unstable();
        served.sort_unstable();
        assert_eq!(
            listed, served,
            "index.html and SCRIPTS list different files"
        );
        for path in [
            "/static/js/missing.js",
            "/static/js/",
            "/static/core.js",
            "/js/core.js",
        ] {
            assert_eq!(fixture.get(path).await.status, 404, "{path}");
        }
    }

    #[tokio::test]
    async fn hsts_is_sent_only_for_an_https_public_origin() {
        let fixture = Fixture::with_config(|cfg| {
            cfg.public_origin = Some("https://admin.example.com".parse().unwrap());
            cfg.secure_cookies = true;
        })
        .await;
        let mut req = fixture_request("admin.example.com", None);
        req.method = "GET".into();
        req.path = "/".into();
        let resp = handle(fixture.state.clone(), req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            header(&resp, "Strict-Transport-Security"),
            Some("max-age=31536000")
        );
    }

    fn fixture_png() -> Vec<u8> {
        vec![
            137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1,
            8, 4, 0, 0, 0, 181, 28, 12, 2, 0, 0, 0, 11, 73, 68, 65, 84, 120, 218, 99, 100, 248, 15,
            0, 1, 5, 1, 1, 39, 24, 227, 102, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
        ]
    }

    #[tokio::test]
    async fn appearance_static_accent_is_csp_safe_and_refreshes_after_reset() {
        let fixture = Fixture::new().await;
        fixture.state.ui.set_accent(Some("#123456".into())).unwrap();
        let css = fixture.get("/static/style.css").await;
        assert_eq!(css.status, 200);
        assert!(String::from_utf8(css.body)
            .unwrap()
            .ends_with(":root{--accent:#123456;}"));
        let html = fixture.get("/").await;
        assert!(!String::from_utf8(html.body).unwrap().contains("<style>"));
        let csp = html
            .headers
            .iter()
            .find(|(name, _)| name == "Content-Security-Policy")
            .unwrap();
        assert!(csp.1.contains("style-src 'self'"));
        assert!(!csp.1.contains("unsafe-inline"));
        assert!(fixture
            .state
            .ui
            .set_accent(Some("red;}</style>".into()))
            .is_err());
        fixture.state.ui.set_accent(None).unwrap();
        let reset = fixture.get("/static/style.css").await;
        assert_eq!(reset.body, STYLE_CSS.as_bytes());
    }

    #[tokio::test]
    async fn appearance_default_logo_is_independent_of_uploaded_favicon() {
        let fixture = Fixture::new().await;
        let png = fixture_png();
        fixture.state.ui.set_icon("image/png", png.clone()).unwrap();
        let logo = fixture.get("/static/default-logo.svg").await;
        assert_eq!(logo.status, 200);
        assert_eq!(logo.content_type, "image/svg+xml");
        assert_eq!(logo.body, FAVICON_SVG.as_bytes());
        let favicon = fixture.get("/static/favicon.svg").await;
        assert_eq!(favicon.content_type, "image/png");
        assert_eq!(favicon.body, png);
        fixture.state.ui.reset_icon().unwrap();
        assert_eq!(
            fixture.get("/static/favicon.svg").await.body,
            FAVICON_SVG.as_bytes()
        );
    }

    #[test]
    fn trusted_host_and_same_origin_prevent_bootstrap_rebinding() {
        let cfg = fixture_config();
        for (host, origin, allowed) in [
            ("localhost:8888", Some("http://localhost:8888"), true),
            ("127.0.0.1:8888", None, true),
            (
                "attacker.example:8888",
                Some("http://attacker.example:8888"),
                false,
            ),
            ("localhost:8888", Some("http://attacker.example"), false),
            ("[::1]:8888", Some("http://[::1]:8888"), true),
            ("LOCALHOST:8888", Some("http://localhost:8888"), true),
            ("localhost:8888", Some("null"), false),
            ("[::1]:80", None, false),
            ("127.0.0.1:80", None, false),
            ("127.0.0.1:8888/extra", None, false),
            ("attacker@127.0.0.1:8888", None, false),
        ] {
            assert_eq!(
                request_origin_allowed(&cfg, &fixture_request(host, origin)),
                allowed,
                "{host}"
            );
        }
    }

    #[test]
    fn trusted_proxy_origin_has_exact_host_port_and_scheme() {
        let mut cfg = fixture_config();
        cfg.public_origin = Some("https://admin.example.com".parse().unwrap());
        cfg.secure_cookies = true;
        for (host, origin, allowed) in [
            ("admin.example.com", Some("https://admin.example.com"), true),
            (
                "admin.example.com:443",
                Some("https://admin.example.com"),
                true,
            ),
            ("admin.example.com:80", None, false),
            ("admin.example.com", Some("http://admin.example.com"), false),
            ("attacker.example", None, false),
            ("127.0.0.1:8888", None, false),
            ("ADMIN.example.com", Some("https://admin.example.com"), true),
            ("admin.example.com", Some("null"), false),
        ] {
            assert_eq!(
                request_origin_allowed(&cfg, &fixture_request(host, origin)),
                allowed,
                "{host}"
            );
        }
    }

    #[test]
    fn address_record_payloads_require_matching_family() {
        for (record_type, content) in [
            ("A", "not-an-ip"),
            ("A", "2001:db8::1"),
            ("AAAA", "192.0.2.1"),
        ] {
            let body: RecordBody = serde_json::from_value(
                json!({"type":record_type,"name":"example.com","content":content}),
            )
            .unwrap();
            assert!(
                record_payload(body).is_err(),
                "invalid address accepted for {record_type}"
            );
        }
    }

    #[test]
    fn structured_record_data_reaches_cloudflare_unchanged() {
        for body in [
            json!({"type": "SRV", "name": "_sip._tcp.example.com", "ttl": 300, "proxied": false,
                   "content": "5 5060 sip.example.com",
                   "data": {"priority": 10, "weight": 5, "port": 5060, "target": "sip.example.com"}}),
            json!({"type": "CAA", "name": "example.com", "ttl": 1, "proxied": false,
                   "content": "0 issue \"ca.example.net\"",
                   "data": {"flags": 0, "tag": "issue", "value": "ca.example.net"}}),
            json!({"type": "HTTPS", "name": "example.com", "ttl": 3600, "proxied": false,
                   "content": "1 . alpn=\"h2\"", "comment": "synthetic",
                   "data": {"priority": 1, "target": ".", "value": "alpn=\"h2\""}}),
            json!({"type": "SVCB", "name": "_dns.example.com", "ttl": 60, "proxied": false,
                   "content": "1 dns.example.com", "tags": ["test:svcb"],
                   "data": {"priority": 1, "target": "dns.example.com"}}),
        ] {
            let payload = record_payload(serde_json::from_value(body.clone()).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(payload).unwrap(), body);
        }
    }

    #[test]
    fn record_data_must_match_the_record_type() {
        let srv = json!({"priority": 1, "weight": 1, "port": 443, "target": "example.com"});
        let caa = json!({"flags": 0, "tag": "issue", "value": "ca.example.net"});
        for (record_type, data) in [
            ("A", Some(srv.clone())),
            ("CNAME", Some(srv.clone())),
            ("TXT", Some(json!({}))),
            ("SRV", None),
            ("SRV", Some(caa.clone())),
            (
                "SRV",
                Some(json!({"priority": 1, "weight": 1, "port": 443, "target": ""})),
            ),
            (
                "SRV",
                Some(json!({"priority": 1, "weight": 1, "port": 443, "target": "x", "extra": 1})),
            ),
            ("CAA", Some(srv.clone())),
            (
                "CAA",
                Some(json!({"flags": 0, "tag": "", "value": "ca.example.net"})),
            ),
            (
                "HTTPS",
                Some(json!({"priority": 1, "target": ".", "port": 443})),
            ),
            ("SVCB", Some(json!({"priority": 1, "target": ""}))),
        ] {
            let mut body =
                json!({"type": record_type, "name": "example.com", "content": "192.0.2.1"});
            if let Some(data) = data {
                body["data"] = data;
            }
            let body: RecordBody = serde_json::from_value(body).unwrap();
            assert!(record_payload(body).is_err(), "accepted {record_type} data");
        }
    }

    #[test]
    fn structured_record_numbers_have_protocol_bounds() {
        for (record_type, data) in [
            (
                "SRV",
                json!({"priority":65536,"weight":1,"port":443,"target":"example.com"}),
            ),
            (
                "CAA",
                json!({"flags":256,"tag":"issue","value":"example.com"}),
            ),
            ("HTTPS", json!({"priority":65536,"target":"example.com"})),
        ] {
            let body: RecordBody = serde_json::from_value(
                json!({"type":record_type,"name":"example.com","data":data}),
            )
            .unwrap();
            assert!(record_payload(body).is_err());
        }
    }
}
