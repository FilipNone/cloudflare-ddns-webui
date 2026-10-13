//! HTTP routing: static GUI assets, session auth (first-run setup, 2FA),
//! UI customization, and the JSON API that proxies the Cloudflare API.

use crate::auth::{Auth, Login2faOutcome, LoginStep1Outcome};
use crate::cloudflare::{ApiFailure, CloudflareClient, DnsRecord, RecordPatch, RecordPayload};
use crate::config::Config;
use crate::customize::UiStore;
use crate::ddns;
use crate::http::{Request, Response};
use crate::pp::PP;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SESSION_COOKIE: &str = "cfddns_session";

const INDEX_HTML: &str = include_str!("../web/index.html");
const STYLE_CSS: &str = include_str!("../web/style.css");
const APP_JS: &str = include_str!("../web/app.js");
const FAVICON_SVG: &str = include_str!("../web/favicon.svg");

const PROXIABLE_TYPES: [&str; 3] = ["A", "AAAA", "CNAME"];
pub const GITHUB_URL: &str = "https://github.com/FilipNone/cloudflare-ddns-webui";

pub struct AppState {
    pub cfg: Config,
    pub cf: CloudflareClient,
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

#[derive(Deserialize)]
struct PasswordBody {
    password: String,
}

#[derive(Deserialize)]
struct SetupBody {
    password: String,
    confirm: String,
}

#[derive(Deserialize)]
struct TotpBody {
    code: String,
}

#[derive(Deserialize)]
struct Login2faBody {
    challenge: String,
    code: String,
}

#[derive(Deserialize)]
struct ChangePasswordBody {
    current_password: String,
    code: Option<String>,
    new_password: String,
    confirm: String,
}

#[derive(Deserialize)]
struct AccentBody {
    accent: Option<String>,
}

#[derive(Deserialize)]
struct CreateRecordBody {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: Option<String>,
    proxied: Option<bool>,
    ttl: Option<i64>,
    comment: Option<String>,
    tags: Option<Vec<String>>,
    priority: Option<u16>,
    data: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct BulkBody {
    action: String,
    ids: Vec<String>,
    patch: Option<BulkPatch>,
}

#[derive(Deserialize)]
struct BulkPatch {
    ttl: Option<i64>,
    proxied: Option<bool>,
    comment: Option<String>,
    tags: Option<Vec<String>>,
}

// --- Response helpers ---

fn security_headers(resp: Response) -> Response {
    resp.header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
}

fn api_response(resp: Response) -> Response {
    security_headers(resp.header("Cache-Control", "no-store"))
}

fn bad_request(msg: &str) -> Response {
    api_response(Response::json_error(400, msg))
}

fn cf_error_response(e: ApiFailure) -> Response {
    let status = match e.status {
        400 => 400,
        404 => 404,
        429 => 429,
        _ => 502,
    };
    api_response(Response::json_error(status, &e.to_string()))
}

fn session_cookie(state: &AppState, token: &str) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        state.cfg.session_ttl.as_secs()
    );
    if state.cfg.secure_cookies {
        cookie.push_str("; Secure");
    }
    cookie
}

fn authenticated(state: &AppState, req: &Request) -> bool {
    req.cookie(SESSION_COOKIE)
        .map(|t| state.auth.session_valid(&t))
        .unwrap_or(false)
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

fn normalize_ttl(ttl: Option<i64>) -> Result<i64, String> {
    match ttl.unwrap_or(1) {
        1 => Ok(1),
        v if (30..=86400).contains(&v) => Ok(v),
        _ => Err("TTL must be 1 (auto) or between 30 and 86400 seconds".to_string()),
    }
}

fn auth_error(error: &str) -> Response {
    let status = match error {
        "locked_out" | "too_many_attempts" => 429,
        "persistence_failed" => 500,
        "invalid_password" | "invalid_code" | "challenge_expired" => 401,
        _ => 400,
    };
    api_response(Response::json_error(status, error))
}

// --- Router ---

pub async fn handle(state: Arc<AppState>, req: Request) -> Response {
    if !request_origin_allowed(&state.cfg, &req) {
        return api_response(Response::json_error(403, "untrusted Host or Origin"));
    }
    let method = req.method.clone();
    let method = method.as_str();
    let path = req.path.clone();
    let path = path.as_str();

    if method == "GET" || method == "HEAD" {
        match path {
            "/" => {
                let accent = state
                    .ui
                    .accent()
                    .map(|a| format!("<style>:root{{--accent:{a};}}</style>"))
                    .unwrap_or_default();
                let html = INDEX_HTML
                    .replace("<!--__ACCENT_STYLE__-->", &accent)
                    .replace("__VERSION__", VERSION);
                return security_headers(Response::new(200, "text/html; charset=utf-8", html))
                    .header("Cache-Control", "no-cache");
            }
            "/static/style.css" => {
                return security_headers(Response::new(200, "text/css; charset=utf-8", STYLE_CSS))
                    .header("Cache-Control", "no-cache");
            }
            "/static/app.js" => {
                return security_headers(Response::new(
                    200,
                    "application/javascript; charset=utf-8",
                    APP_JS,
                ))
                .header("Cache-Control", "no-cache");
            }
            "/static/favicon.svg" => {
                if let Some((mime, data)) = state.ui.icon() {
                    return security_headers(Response::new(200, &mime, data))
                        .header("Content-Security-Policy", "sandbox; default-src 'none'")
                        .header("Cache-Control", "no-cache");
                }
                return security_headers(Response::new(200, "image/svg+xml", FAVICON_SVG))
                    .header("Cache-Control", "no-cache");
            }
            _ => {}
        }
    }

    if let Some(rest) = path.strip_prefix("/api/") {
        let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        return handle_api(state, req, &segments).await;
    }

    security_headers(Response::json_error(404, "not found"))
}

fn request_origin_allowed(cfg: &Config, req: &Request) -> bool {
    let Some(host) = req.header("host") else {
        return false;
    };
    let scheme = if cfg
        .public_origin
        .as_deref()
        .is_some_and(|s| s.starts_with("https://"))
    {
        "https"
    } else {
        "http"
    };
    let Ok(host_url) = reqwest::Url::parse(&format!("{scheme}://{host}")) else {
        return false;
    };
    if !host_url.username().is_empty()
        || host_url.password().is_some()
        || host_url.path() != "/"
        || host_url.query().is_some()
        || host_url.fragment().is_some()
    {
        return false;
    }
    let expected_origin = if let Some(origin) = &cfg.public_origin {
        let Ok(trusted) = reqwest::Url::parse(origin) else {
            return false;
        };
        let host_port =
            host_url
                .port()
                .unwrap_or(if trusted.scheme() == "https" { 443 } else { 80 });
        if trusted.host_str() != host_url.host_str()
            || trusted.port_or_known_default() != Some(host_port)
        {
            return false;
        }
        trusted.origin().ascii_serialization()
    } else {
        let Ok(listen) = cfg.listen.parse::<std::net::SocketAddr>() else {
            return false;
        };
        if host_url.port_or_known_default() != Some(listen.port()) {
            return false;
        }
        let host_name = host_url.host_str().unwrap_or("").trim_matches(['[', ']']);
        let address = if host_name == "localhost" {
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        } else {
            host_name.parse::<std::net::IpAddr>().ok()
        };
        let Some(address) = address else {
            return false;
        };
        if !listen.ip().is_unspecified()
            && address != listen.ip()
            && !(listen.ip().is_loopback() && address.is_loopback())
        {
            return false;
        }
        host_url.origin().ascii_serialization()
    };
    req.header("origin")
        .is_none_or(|origin| origin == expected_origin)
}

async fn handle_api(state: Arc<AppState>, req: Request, segments: &[&str]) -> Response {
    let method = req.method.as_str();

    // --- Public endpoints ---
    match (method, segments) {
        ("GET", ["config"]) => {
            let ui = state.ui.status();
            return api_response(Response::json(
                200,
                &json!({
                    "version": VERSION,
                    "languages": [{ "code": "en", "name": "English" }],
                    "ddns_configured": !state.cfg.domains.is_empty(),
                    "configured": state.auth.is_configured(),
                    "totp_enabled": state.auth.totp_enabled(),
                    "accent": ui.accent,
                    "has_icon": ui.has_icon,
                    "github": GITHUB_URL,
                }),
            ));
        }
        ("POST", ["auth", "setup"]) => {
            if state.auth.is_configured() {
                return api_response(Response::json_error(409, "already configured"));
            }
            if !mutation_allowed(&req) {
                return api_response(Response::json_error(403, "missing request header"));
            }
            let body: SetupBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            if body.password != body.confirm {
                return bad_request("passwords do not match");
            }
            match state.auth.setup_password_session(&body.password) {
                Ok(token) => {
                    state.pp.infof(
                        crate::pp::EMOJI_LOCK,
                        "Admin password created (first-run setup)",
                    );
                    return api_response(Response::json(200, &json!({ "ok": true })))
                        .header("Set-Cookie", &session_cookie(&state, &token));
                }
                Err(e) => return bad_request(&e),
            }
        }
        ("POST", ["auth", "login"]) => {
            if !mutation_allowed(&req) {
                return api_response(Response::json_error(403, "missing request header"));
            }
            if !state.auth.is_configured() {
                return api_response(Response::json_error(428, "setup required"));
            }
            let ip = req.remote.ip();
            if state.auth.limiter().is_locked_out(ip) {
                return api_response(Response::json_error(
                    429,
                    "too many failed attempts - try again in a few minutes",
                ));
            }
            let body: PasswordBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            match state.auth.login_step1_session(ip, &body.password) {
                Ok(LoginStep1Outcome::Session(token)) => {
                    state.pp.infof(
                        crate::pp::EMOJI_LOCK,
                        &format!("Successful login from {ip}"),
                    );
                    return api_response(Response::json(
                        200,
                        &json!({ "ok": true, "requires_2fa": false }),
                    ))
                    .header("Set-Cookie", &session_cookie(&state, &token));
                }
                Ok(LoginStep1Outcome::Challenge(challenge)) => {
                    return api_response(Response::json(
                        200,
                        &json!({ "ok": false, "requires_2fa": true, "challenge": challenge }),
                    ));
                }
                Err("locked_out") => {
                    return api_response(Response::json_error(429, "too many failed attempts"));
                }
                Err(_) => {
                    state
                        .pp
                        .warningf(crate::pp::EMOJI_LOCK, &format!("Failed login from {ip}"));
                    return api_response(Response::json_error(401, "invalid password"));
                }
            }
        }
        ("POST", ["auth", "login", "2fa"]) => {
            if !mutation_allowed(&req) {
                return api_response(Response::json_error(403, "missing request header"));
            }
            let ip = req.remote.ip();
            let body: Login2faBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            match state
                .auth
                .login_step2_session(ip, &body.challenge, &body.code)
            {
                Ok((Login2faOutcome::Totp, token)) => {
                    state.pp.infof(
                        crate::pp::EMOJI_LOCK,
                        &format!("Successful 2FA login from {ip}"),
                    );
                    return api_response(Response::json(200, &json!({ "ok": true })))
                        .header("Set-Cookie", &session_cookie(&state, &token));
                }
                Ok((Login2faOutcome::BackupCode { remaining }, token)) => {
                    state.pp.warningf(
                        crate::pp::EMOJI_LOCK,
                        &format!("Backup code used from {ip} ({remaining} remaining)"),
                    );
                    return api_response(Response::json(
                        200,
                        &json!({ "ok": true, "backup_code_used": true, "backup_codes_remaining": remaining }),
                    ))
                    .header("Set-Cookie", &session_cookie(&state, &token));
                }
                Err("challenge_expired") => {
                    return api_response(Response::json_error(
                        401,
                        "login session expired - sign in again",
                    ));
                }
                Err("too_many_attempts" | "locked_out") => {
                    return api_response(Response::json_error(
                        429,
                        "too many attempts - sign in again",
                    ));
                }
                Err("persistence_failed") => return auth_error("persistence_failed"),
                Err(_) => {
                    return api_response(Response::json_error(401, "invalid code"));
                }
            }
        }
        _ => {}
    }

    // --- Auth required below ---
    if !authenticated(&state, &req) {
        return api_response(Response::json_error(401, "authentication required"));
    }
    if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") && !mutation_allowed(&req) {
        return api_response(Response::json_error(403, "missing request header"));
    }

    if let ["zones", zone_id, rest @ ..] = segments {
        if let Err(e) = crate::cloudflare::validate_identifier(zone_id) {
            return cf_error_response(e);
        }
        if let ["records", record_id] = rest {
            if *record_id != "bulk" {
                if let Err(e) = crate::cloudflare::validate_identifier(record_id) {
                    return cf_error_response(e);
                }
            }
        }
    }

    match (method, segments) {
        ("POST", ["auth", "logout"]) => {
            if let Some(token) = req.cookie(SESSION_COOKIE) {
                state.auth.destroy_session(&token);
            }
            api_response(Response::json(200, &json!({ "ok": true }))).header(
                "Set-Cookie",
                &format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
            )
        }
        ("GET", ["auth", "me"]) => api_response(Response::json(
            200,
            &json!({
                "authenticated": true,
                "session_ttl": state.cfg.session_ttl.as_secs(),
                "totp_enabled": state.auth.totp_enabled(),
                "backup_codes_remaining": state.auth.backup_codes_remaining(),
            }),
        )),

        // --- 2FA management ---
        ("POST", ["auth", "2fa", "begin"]) => {
            let body: PasswordBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            match state
                .auth
                .totp_enroll_begin_verified(req.remote.ip(), &body.password)
            {
                Ok((secret, uri, qr)) => api_response(Response::json(
                    200,
                    &json!({ "secret": secret, "uri": uri, "qr_svg": qr }),
                )),
                Err(e) => auth_error(&e),
            }
        }
        ("POST", ["auth", "2fa", "confirm"]) => {
            let body: TotpBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            match state.auth.totp_enroll_confirm_session(&body.code) {
                Ok((codes, token)) => {
                    state.pp.infof(crate::pp::EMOJI_LOCK, "2FA enabled");
                    api_response(Response::json(200, &json!({ "backup_codes": codes })))
                        .header("Set-Cookie", &session_cookie(&state, &token))
                }
                Err(e) => auth_error(&e),
            }
        }
        ("POST", ["auth", "2fa", "cancel"]) => {
            state.auth.totp_enroll_cancel();
            api_response(Response::json(200, &json!({ "ok": true })))
        }
        ("POST", ["auth", "2fa", "disable"]) => {
            let body: TotpBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            if !state.auth.totp_enabled() {
                return bad_request("2FA is not enabled");
            }
            match state
                .auth
                .totp_disable_verified(req.remote.ip(), &body.code)
            {
                Ok(token) => {
                    state.pp.infof(crate::pp::EMOJI_LOCK, "2FA disabled");
                    api_response(Response::json(200, &json!({ "ok": true })))
                        .header("Set-Cookie", &session_cookie(&state, &token))
                }
                Err(e) => auth_error(e),
            }
        }

        // --- Password change ---
        ("POST", ["auth", "password"]) => {
            let body: ChangePasswordBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            if body.new_password != body.confirm {
                return bad_request("passwords do not match");
            }
            match state.auth.change_password_verified(
                req.remote.ip(),
                &body.current_password,
                body.code.as_deref(),
                &body.new_password,
            ) {
                Ok(token) => {
                    state
                        .pp
                        .infof(crate::pp::EMOJI_LOCK, "Admin password changed");
                    // Issue a fresh session for the current caller.
                    api_response(Response::json(200, &json!({ "ok": true })))
                        .header("Set-Cookie", &session_cookie(&state, &token))
                }
                Err(e) => auth_error(&e),
            }
        }

        // --- UI customization ---
        ("POST", ["ui", "accent"]) => {
            let body: AccentBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            match state
                .ui
                .set_accent(body.accent.filter(|a| !a.trim().is_empty()))
            {
                Ok(()) => api_response(Response::json(200, &json!({ "ok": true }))),
                Err(e) => bad_request(&e),
            }
        }
        ("POST", ["ui", "icon"]) => {
            let mime = req
                .query
                .get("mime")
                .cloned()
                .unwrap_or_else(|| "image/png".to_string());
            if req.body.is_empty() {
                return bad_request("empty image");
            }
            match state.ui.set_icon(&mime, req.body) {
                Ok(()) => api_response(Response::json(200, &json!({ "ok": true }))),
                Err(e) => bad_request(&e),
            }
        }
        ("DELETE", ["ui", "icon"]) => match state.ui.reset_icon() {
            Ok(()) => api_response(Response::json(200, &json!({ "ok": true }))),
            Err(e) => api_response(Response::json_error(500, &e)),
        },

        // --- Zones / records (unchanged behavior) ---
        ("GET", ["zones"]) => match state.cf.list_zones().await {
            Ok(zones) => api_response(Response::json(200, &zones)),
            Err(e) => cf_error_response(e),
        },
        ("GET", ["zones", zone_id, "records"]) => match state.cf.list_records(zone_id).await {
            Ok((records, total)) => api_response(Response::json(
                200,
                &json!({ "records": records, "total": total }),
            )),
            Err(e) => cf_error_response(e),
        },
        ("POST", ["zones", zone_id, "records"]) => {
            let body: CreateRecordBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            if let Err(e) = validate_record_payload(&body) {
                return bad_request(&e);
            }
            let proxied = body.proxied.unwrap_or(false);
            // Cloudflare forces TTL to automatic when a record is proxied.
            let ttl = if proxied { 1 } else { body.ttl.unwrap_or(1) };
            let payload = RecordPayload {
                record_type: body.record_type,
                name: body.name,
                content: body.content,
                proxied: Some(proxied),
                ttl,
                comment: body.comment,
                tags: body.tags,
                priority: body.priority,
                data: body.data,
            };
            match state.cf.create_record(zone_id, &payload).await {
                Ok(record) => api_response(Response::json(201, &record)),
                Err(e) => cf_error_response(e),
            }
        }
        ("PUT", ["zones", zone_id, "records", record_id]) => {
            let body: CreateRecordBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            if let Err(e) = validate_record_payload(&body) {
                return bad_request(&e);
            }
            let proxied = body.proxied.unwrap_or(false);
            let ttl = if proxied { 1 } else { body.ttl.unwrap_or(1) };
            let payload = RecordPayload {
                record_type: body.record_type,
                name: body.name,
                content: body.content,
                proxied: Some(proxied),
                ttl,
                comment: body.comment,
                tags: body.tags,
                priority: body.priority,
                data: body.data,
            };
            match state.cf.update_record(zone_id, record_id, &payload).await {
                Ok(record) => api_response(Response::json(200, &record)),
                Err(e) => cf_error_response(e),
            }
        }
        ("DELETE", ["zones", zone_id, "records", record_id]) => {
            match state.cf.delete_record(zone_id, record_id).await {
                Ok(()) => api_response(Response::json(200, &json!({ "ok": true }))),
                Err(e) => cf_error_response(e),
            }
        }
        ("POST", ["zones", zone_id, "records", "bulk"]) => {
            let body: BulkBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            if body.ids.is_empty() {
                return bad_request("no record ids supplied");
            }
            if body.ids.len() > 500 {
                return bad_request("too many records in one bulk operation (max 500)");
            }
            let mut seen = std::collections::HashSet::new();
            for id in &body.ids {
                if let Err(e) = crate::cloudflare::validate_identifier(id) {
                    return cf_error_response(e);
                }
                if !seen.insert(id) {
                    return bad_request("duplicate record ids are not allowed");
                }
            }
            match body.action.as_str() {
                "delete" => bulk_delete(&state, &req, zone_id, &body.ids).await,
                "update" => bulk_update(&state, &req, zone_id, &body).await,
                other => bad_request(&format!("unknown bulk action '{other}'")),
            }
        }
        ("GET", ["zones", zone_id, "export"]) => match state.cf.export_records(zone_id).await {
            Ok(bind) => api_response(Response::new(200, "text/plain; charset=utf-8", bind))
                .header("Content-Disposition", "attachment; filename=\"zone.txt\""),
            Err(e) => cf_error_response(e),
        },
        ("POST", ["zones", zone_id, "import"]) => {
            if req.body.is_empty() {
                return bad_request("empty zone file");
            }
            if let Err(error) = crate::bind::validate(&req.body) {
                return bad_request(&error);
            }
            let filename = req
                .query
                .get("filename")
                .cloned()
                .unwrap_or_else(|| "zone.txt".to_string());
            match state.cf.import_records(zone_id, &filename, req.body).await {
                Ok(result) => api_response(Response::json(200, &result)),
                Err(e) => cf_error_response(e),
            }
        }

        // --- DDNS ---
        ("GET", ["ddns", "status"]) => {
            let status = ddns::status(&state.cfg, &state.cf).await;
            api_response(Response::json(200, &status))
        }
        ("POST", ["ddns", "update"]) => {
            if state.cfg.domains.is_empty() {
                return bad_request("no DDNS domains configured (set DOMAINS)");
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
                return api_response(Response::json_error(
                    409,
                    "a DDNS update is already running",
                ));
            }
            let _cycle = DdnsCycleGuard(&state.ddns_running);
            let result =
                ddns::update_now(&state.cfg, &state.cf, || authenticated(&state, &req)).await;
            for line in &result.log {
                state.pp.infof("", line);
            }
            api_response(Response::json(200, &result))
        }

        _ => api_response(Response::json_error(404, "not found")),
    }
}

// --- Validation of record payloads (server-side mirrors frontend checks) ---

fn validate_record_payload(body: &CreateRecordBody) -> Result<(), String> {
    if !valid_record_type(&body.record_type) {
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
    if proxied && !PROXIABLE_TYPES.contains(&body.record_type.as_str()) {
        return Err("only A, AAAA and CNAME records can be proxied".to_string());
    }
    normalize_ttl(body.ttl)?;
    match body.record_type.as_str() {
        "A" | "AAAA" => {
            let ip = body
                .content
                .as_deref()
                .ok_or("content is required")?
                .parse::<std::net::IpAddr>()
                .map_err(|_| "invalid IP address")?;
            if ip.is_ipv6() != (body.record_type == "AAAA") {
                return Err("IP address does not match the record type".to_string());
            }
        }
        "MX" => {
            if body.priority.is_none() {
                return Err("MX records require a priority".to_string());
            }
            require_content(body)?;
        }
        "SRV" => {
            let d = body
                .data
                .as_ref()
                .ok_or("SRV records require data fields")?;
            for k in ["priority", "weight", "port"] {
                if !d
                    .get(k)
                    .and_then(|v| v.as_u64())
                    .is_some_and(|n| n <= 65535)
                {
                    return Err(format!("SRV data requires numeric '{k}'"));
                }
            }
            if d.get("target")
                .and_then(|v| v.as_str())
                .map(|s| s.is_empty())
                .unwrap_or(true)
            {
                return Err("SRV data requires a target".to_string());
            }
        }
        "CAA" => {
            let d = body
                .data
                .as_ref()
                .ok_or("CAA records require data fields")?;
            if !d
                .get("flags")
                .and_then(|v| v.as_u64())
                .is_some_and(|n| n <= 255)
            {
                return Err("CAA data requires numeric 'flags'".to_string());
            }
            for k in ["tag", "value"] {
                if d.get(k)
                    .and_then(|v| v.as_str())
                    .map(|s| s.is_empty())
                    .unwrap_or(true)
                {
                    return Err(format!("CAA data requires '{k}'"));
                }
            }
        }
        "HTTPS" | "SVCB" => {
            let d = body
                .data
                .as_ref()
                .ok_or("HTTPS/SVCB records require data fields")?;
            if !d
                .get("priority")
                .and_then(|v| v.as_u64())
                .is_some_and(|n| n <= 65535)
            {
                return Err("HTTPS/SVCB data requires numeric 'priority'".to_string());
            }
            if d.get("target")
                .and_then(|v| v.as_str())
                .map(|s| s.is_empty())
                .unwrap_or(true)
            {
                return Err("HTTPS/SVCB data requires a target".to_string());
            }
        }
        _ => {
            require_content(body)?;
        }
    }
    Ok(())
}

fn validate_metadata(comment: Option<&str>, tags: Option<&[String]>) -> Result<(), String> {
    if comment.is_some_and(|s| s.len() > 500 || s.chars().any(|c| c.is_control())) {
        return Err("comment must be at most 500 bytes with no control characters".to_string());
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

fn require_content(body: &CreateRecordBody) -> Result<(), String> {
    match &body.content {
        Some(c) if !c.trim().is_empty() => Ok(()),
        _ => Err("content is required".to_string()),
    }
}

// --- Bulk operations ---

async fn bulk_delete(state: &AppState, req: &Request, zone_id: &str, ids: &[String]) -> Response {
    let mut results = Vec::new();
    for id in ids {
        if !authenticated(state, req) {
            results.push(json!({ "id": id, "ok": false, "error": "session expired or revoked; write not sent" }));
            continue;
        }
        match state.cf.delete_record(zone_id, id).await {
            Ok(()) => results.push(json!({ "id": id, "ok": true })),
            Err(e) => results.push(json!({ "id": id, "ok": false, "error": e.to_string() })),
        }
    }
    let succeeded = results.iter().filter(|r| r["ok"] == true).count();
    api_response(Response::json(
        200,
        &json!({ "results": results, "succeeded": succeeded, "failed": results.len() - succeeded }),
    ))
}

async fn bulk_update(state: &AppState, req: &Request, zone_id: &str, body: &BulkBody) -> Response {
    let patch = match &body.patch {
        Some(p) => p,
        None => return bad_request("missing patch"),
    };
    if let Err(e) = validate_metadata(patch.comment.as_deref(), patch.tags.as_deref()) {
        return bad_request(&e);
    }
    let ttl = match patch.ttl {
        Some(t) => match normalize_ttl(Some(t)) {
            Ok(v) => Some(v),
            Err(e) => return bad_request(&e),
        },
        None => None,
    };

    let mut records: Vec<DnsRecord> = Vec::new();
    {
        match state.cf.list_records(zone_id).await {
            Ok((all, _)) => {
                for id in &body.ids {
                    match all.iter().find(|r| &r.id == id) {
                        Some(r) => {
                            if patch.proxied.is_some()
                                && !PROXIABLE_TYPES.contains(&r.record_type.as_str())
                            {
                                return bad_request(&format!(
                                    "record '{}' is type {} - only A, AAAA and CNAME records can be proxied",
                                    r.name, r.record_type
                                ));
                            }
                            records.push(r.clone());
                        }
                        None => return bad_request(&format!("record id {id} not found in zone")),
                    }
                }
            }
            Err(e) => return cf_error_response(e),
        }
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
        let id = record.id;
        if !authenticated(state, req) {
            results.push(json!({ "id": id, "ok": false, "error": "session expired or revoked; write not sent" }));
            continue;
        }
        let mut record_patch = cf_patch.clone();
        if patch.proxied != Some(false)
            && record.proxied == Some(true)
            && record_patch.ttl.is_some()
        {
            record_patch.ttl = Some(1);
        }
        match state.cf.patch_record(zone_id, &id, &record_patch).await {
            Ok(_) => results.push(json!({ "id": id, "ok": true })),
            Err(e) => results.push(json!({ "id": id, "ok": false, "error": e.to_string() })),
        }
    }
    let succeeded = results.iter().filter(|r| r["ok"] == true).count();
    api_response(Response::json(
        200,
        &json!({ "results": results, "succeeded": succeeded, "failed": results.len() - succeeded }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_config() -> Config {
        Config {
            api_token: "synthetic".into(),
            listen: "127.0.0.1:8888".into(),
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
        cfg.public_origin = Some("https://admin.example.com".into());
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
            let body: CreateRecordBody = serde_json::from_value(
                json!({"type":record_type,"name":"example.com","content":content}),
            )
            .unwrap();
            assert!(
                validate_record_payload(&body).is_err(),
                "invalid address accepted for {record_type}"
            );
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
            let body: CreateRecordBody = serde_json::from_value(
                json!({"type":record_type,"name":"example.com","data":data}),
            )
            .unwrap();
            assert!(validate_record_payload(&body).is_err());
        }
    }
}
