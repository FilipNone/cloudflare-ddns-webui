//! HTTP routing: static GUI assets, session auth, and the JSON API that the
//! frontend talks to. Every mutation is proxied to the Cloudflare API.

use crate::auth::{LoginLimiter, PasswordHash, SessionStore};
use crate::cloudflare::{ApiFailure, CloudflareClient, DnsRecord, RecordPatch, RecordPayload};
use crate::config::Config;
use crate::ddns;
use crate::http::{Request, Response};
use crate::pp::PP;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SESSION_COOKIE: &str = "cfddns_session";

const INDEX_HTML: &str = include_str!("../web/index.html");
const STYLE_CSS: &str = include_str!("../web/style.css");
const APP_JS: &str = include_str!("../web/app.js");
const FAVICON_SVG: &str = include_str!("../web/favicon.svg");

/// Record types eligible for Cloudflare proxying.
const PROXIABLE_TYPES: [&str; 3] = ["A", "AAAA", "CNAME"];

pub struct AppState {
    pub cfg: Config,
    pub cf: CloudflareClient,
    pub password: PasswordHash,
    pub sessions: SessionStore,
    pub limiter: LoginLimiter,
    pub pp: PP,
}

// --- Request/response DTOs ---

#[derive(Deserialize)]
struct LoginBody {
    password: String,
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
    #[serde(default)]
    comment_set: bool,
}

#[derive(Serialize)]
struct BulkItemResult {
    id: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct BulkResponse {
    results: Vec<BulkItemResult>,
    succeeded: usize,
    failed: usize,
}

// --- Helpers ---

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
        .map(|t| state.sessions.is_valid(&t))
        .unwrap_or(false)
}

/// CSRF defense-in-depth: mutations must carry the custom header set by our
/// frontend (cross-site forms cannot set custom headers).
fn mutation_allowed(req: &Request) -> bool {
    req.header("x-requested-with")
        .map(|v| v == "fetch")
        .unwrap_or(false)
}

fn cf_error_response(e: ApiFailure) -> Response {
    let status = match e.status {
        400 => 400,
        401 | 403 => 502, // upstream auth problem — do not leak to client as 401/403
        404 => 404,
        429 => 429,
        _ => 502,
    };
    api_response(Response::json_error(status, &e.to_string()))
}

fn bad_request(msg: &str) -> Response {
    api_response(Response::json_error(400, msg))
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

// --- Main router ---

pub async fn handle(state: Arc<AppState>, req: Request) -> Response {
    let method = req.method.clone();
    let method = method.as_str();
    let path = req.path.clone();
    let path = path.as_str();

    // Static assets (public)
    if method == "GET" || method == "HEAD" {
        match path {
            "/" => {
                let html = INDEX_HTML.replace("__VERSION__", VERSION);
                return security_headers(Response::new(200, "text/html; charset=utf-8", html))
                    .header("Cache-Control", "no-cache");
            }
            "/static/style.css" => {
                return security_headers(Response::new(200, "text/css; charset=utf-8", STYLE_CSS))
                    .header("Cache-Control", "no-cache");
            }
            "/static/app.js" => {
                return security_headers(
                    Response::new(200, "application/javascript; charset=utf-8", APP_JS),
                )
                .header("Cache-Control", "no-cache");
            }
            "/static/favicon.svg" => {
                return security_headers(Response::new(200, "image/svg+xml", FAVICON_SVG))
                    .header("Cache-Control", "no-cache");
            }
            _ => {}
        }
    }

    // API routes
    if let Some(rest) = path.strip_prefix("/api/") {
        let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        return handle_api(state, req, &segments).await;
    }

    security_headers(Response::json_error(404, "not found"))
}

async fn handle_api(state: Arc<AppState>, req: Request, segments: &[&str]) -> Response {
    let method = req.method.as_str();

    // --- Public API endpoints ---
    match (method, segments) {
        ("GET", ["config"]) => {
            return api_response(Response::json(
                200,
                &serde_json::json!({
                    "version": VERSION,
                    "languages": [{ "code": "en", "name": "English" }],
                    "ddns_configured": !state.cfg.domains.is_empty(),
                }),
            ));
        }
        ("POST", ["auth", "login"]) => {
            let ip = req.remote.ip();
            if state.limiter.is_locked_out(ip) {
                return api_response(Response::json_error(
                    429,
                    "too many failed attempts — try again in a few minutes",
                ));
            }
            let body: LoginBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            if !state.password.verify(&body.password) {
                state.limiter.record_failure(ip);
                state
                    .pp
                    .warningf(crate::pp::EMOJI_LOCK, &format!("Failed login from {ip}"));
                return api_response(Response::json_error(401, "invalid password"));
            }
            state.limiter.record_success(ip);
            let token = state.sessions.create();
            state
                .pp
                .infof(crate::pp::EMOJI_LOCK, &format!("Successful login from {ip}"));
            return api_response(Response::json(200, &serde_json::json!({ "ok": true })))
                .header("Set-Cookie", &session_cookie(&state, &token));
        }
        _ => {}
    }

    // --- Everything below requires a session ---
    if !authenticated(&state, &req) {
        return api_response(Response::json_error(401, "authentication required"));
    }

    // --- Mutations require the CSRF header ---
    if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") && !mutation_allowed(&req) {
        return api_response(Response::json_error(403, "missing request header"));
    }

    match (method, segments) {
        ("POST", ["auth", "logout"]) => {
            if let Some(token) = req.cookie(SESSION_COOKIE) {
                state.sessions.destroy(&token);
            }
            api_response(Response::json(200, &serde_json::json!({ "ok": true })))
                .header("Set-Cookie", &format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"))
        }
        ("GET", ["auth", "me"]) => api_response(Response::json(
            200,
            &serde_json::json!({
                "authenticated": true,
                "session_ttl": state.cfg.session_ttl.as_secs(),
            }),
        )),

        // --- Zones ---
        ("GET", ["zones"]) => match state.cf.list_zones().await {
            Ok(zones) => api_response(Response::json(200, &zones)),
            Err(e) => cf_error_response(e),
        },

        // --- DNS records ---
        ("GET", ["zones", zone_id, "records"]) => {
            match state.cf.list_records(zone_id).await {
                Ok((records, total)) => api_response(Response::json(
                    200,
                    &serde_json::json!({ "records": records, "total": total }),
                )),
                Err(e) => cf_error_response(e),
            }
        }
        ("POST", ["zones", zone_id, "records"]) => {
            let body: CreateRecordBody = match req.json() {
                Ok(b) => b,
                Err(e) => return bad_request(&e),
            };
            if !valid_record_type(&body.record_type) {
                return bad_request("unsupported record type");
            }
            let ttl = match normalize_ttl(body.ttl) {
                Ok(t) => t,
                Err(e) => return bad_request(&e),
            };
            let proxied = body.proxied.unwrap_or(false);
            if proxied && !PROXIABLE_TYPES.contains(&body.record_type.as_str()) {
                return bad_request("only A, AAAA and CNAME records can be proxied");
            }
            let payload = RecordPayload {
                record_type: body.record_type,
                name: body.name,
                content: body.content,
                proxied: Some(proxied),
                ttl,
                comment: body.comment.filter(|c| !c.trim().is_empty()),
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
            if !valid_record_type(&body.record_type) {
                return bad_request("unsupported record type");
            }
            let ttl = match normalize_ttl(body.ttl) {
                Ok(t) => t,
                Err(e) => return bad_request(&e),
            };
            let proxied = body.proxied.unwrap_or(false);
            if proxied && !PROXIABLE_TYPES.contains(&body.record_type.as_str()) {
                return bad_request("only A, AAAA and CNAME records can be proxied");
            }
            let payload = RecordPayload {
                record_type: body.record_type,
                name: body.name,
                content: body.content,
                proxied: Some(proxied),
                ttl,
                comment: body.comment.filter(|c| !c.trim().is_empty()),
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
                Ok(()) => api_response(Response::json(200, &serde_json::json!({ "ok": true }))),
                Err(e) => cf_error_response(e),
            }
        }

        // --- Bulk operations ---
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

            match body.action.as_str() {
                "delete" => {
                    let mut results = Vec::new();
                    for id in &body.ids {
                        match state.cf.delete_record(zone_id, id).await {
                            Ok(()) => results.push(BulkItemResult {
                                id: id.clone(),
                                ok: true,
                                error: None,
                            }),
                            Err(e) => results.push(BulkItemResult {
                                id: id.clone(),
                                ok: false,
                                error: Some(e.to_string()),
                            }),
                        }
                    }
                    let succeeded = results.iter().filter(|r| r.ok).count();
                    let failed = results.len() - succeeded;
                    api_response(Response::json(
                        200,
                        &BulkResponse {
                            results,
                            succeeded,
                            failed,
                        },
                    ))
                }
                "update" => {
                    let patch = match body.patch {
                        Some(p) => p,
                        None => return bad_request("missing patch"),
                    };
                    let ttl = match patch.ttl {
                        Some(t) => Some(match normalize_ttl(Some(t)) {
                            Ok(v) => v,
                            Err(e) => return bad_request(&e),
                        }),
                        None => None,
                    };

                    // DNS type check: proxied changes only apply when every
                    // selected record is of a proxiable type.
                    let mut records: Vec<DnsRecord> = Vec::new();
                    if patch.proxied.is_some() {
                        match state.cf.list_records(zone_id).await {
                            Ok((all, _)) => {
                                for id in &body.ids {
                                    match all.iter().find(|r| &r.id == id) {
                                        Some(r) => {
                                            if !PROXIABLE_TYPES
                                                .contains(&r.record_type.as_str())
                                            {
                                                return bad_request(&format!(
                                                    "record '{}' is type {} — only A, AAAA and CNAME records can be proxied",
                                                    r.name, r.record_type
                                                ));
                                            }
                                            records.push(r.clone());
                                        }
                                        None => {
                                            return bad_request(&format!(
                                                "record id {id} not found in zone"
                                            ))
                                        }
                                    }
                                }
                            }
                            Err(e) => return cf_error_response(e),
                        }
                    }

                    let cf_patch = RecordPatch {
                        ttl,
                        proxied: patch.proxied,
                        comment: if patch.comment_set {
                            patch.comment.filter(|c| !c.trim().is_empty())
                        } else {
                            None
                        },
                        content: None,
                    };

                    // For proxied patches we must include the content field on
                    // some API paths — PATCH handles partial updates fine.
                    let mut results = Vec::new();
                    for id in &body.ids {
                        // If the patch is a no-op for this record, skip.
                        if cf_patch.ttl.is_none()
                            && cf_patch.proxied.is_none()
                            && !patch.comment_set
                        {
                            break;
                        }
                        match state.cf.patch_record(zone_id, id, &cf_patch).await {
                            Ok(_) => results.push(BulkItemResult {
                                id: id.clone(),
                                ok: true,
                                error: None,
                            }),
                            Err(e) => results.push(BulkItemResult {
                                id: id.clone(),
                                ok: false,
                                error: Some(e.to_string()),
                            }),
                        }
                    }
                    let succeeded = results.iter().filter(|r| r.ok).count();
                    let failed = results.len() - succeeded;
                    api_response(Response::json(
                        200,
                        &BulkResponse {
                            results,
                            succeeded,
                            failed,
                        },
                    ))
                }
                other => bad_request(&format!("unknown bulk action '{other}'")),
            }
        }

        // --- Import / export (Cloudflare-compatible BIND zone files) ---
        ("GET", ["zones", zone_id, "export"]) => {
            match state.cf.export_records(zone_id).await {
                Ok(bind) => api_response(Response::new(200, "text/plain; charset=utf-8", bind))
                    .header("Content-Disposition", "attachment; filename=\"zone.txt\""),
                Err(e) => cf_error_response(e),
            }
        }
        ("POST", ["zones", zone_id, "import"]) => {
            if req.body.is_empty() {
                return bad_request("empty zone file");
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

        // --- DDNS features ---
        ("GET", ["ddns", "status"]) => {
            let status = ddns::status(&state.cfg, &state.cf).await;
            api_response(Response::json(200, &status))
        }
        ("POST", ["ddns", "update"]) => {
            if state.cfg.domains.is_empty() {
                return bad_request("no DDNS domains configured (set DOMAINS)");
            }
            let log = ddns::update_now(&state.cfg, &state.cf).await;
            for line in &log {
                state.pp.infof("", line);
            }
            api_response(Response::json(200, &serde_json::json!({ "log": log })))
        }

        _ => api_response(Response::json_error(404, "not found")),
    }
}
