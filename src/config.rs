//! Configuration via environment variables, following the cloudflare-ddns
//! philosophy: everything is configured with env vars, with `*_FILE` variants
//! for secrets (Docker secrets compatible).

use crate::pp::PP;
use std::time::Duration;

pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
pub const DEFAULT_SESSION_TTL_SECS: u64 = 24 * 60 * 60; // 24h
pub const DEFAULT_UPDATE_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_DETECTION_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub struct Config {
    /// Cloudflare API token (Bearer).
    pub api_token: String,
    /// Admin password for the web GUI login.
    pub admin_password: String,
    /// Address the HTTP server binds to.
    pub listen: String,
    /// How long a login session stays valid.
    pub session_ttl: Duration,
    /// Timeout for Cloudflare API requests.
    pub update_timeout: Duration,
    /// Timeout for public IP detection requests.
    pub detection_timeout: Duration,
    /// Add the `Secure` attribute to session cookies (enable behind HTTPS).
    pub secure_cookies: bool,
    /// Domains managed by the companion cloudflare-ddns service (for the
    /// dashboard sync status and on-demand updates).
    pub domains: Vec<String>,
    /// IPv4 detection provider for the dashboard (ipify, cloudflare.trace, url:, literal:, none).
    pub ip4_provider: String,
    /// IPv6 detection provider for the dashboard.
    pub ip6_provider: String,
    /// Default TTL applied by on-demand DDNS updates (1 = auto).
    pub ttl: i64,
    /// Default proxied flag applied by on-demand DDNS updates.
    pub proxied: bool,
    /// Comment attached to records written by on-demand DDNS updates.
    pub record_comment: Option<String>,
    /// Pretty output.
    pub emoji: bool,
    pub quiet: bool,
    /// Override the Cloudflare API base URL (testing only).
    pub api_base: Option<String>,
}

fn bool_env(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => default,
    }
}

fn duration_env_secs(name: &str, default_secs: u64) -> Duration {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            // Accept "300", "300s", "5m", "1h"
            let (num, mult) = if let Some(n) = v.strip_suffix('s') {
                (n, 1u64)
            } else if let Some(n) = v.strip_suffix('m') {
                (n, 60u64)
            } else if let Some(n) = v.strip_suffix('h') {
                (n, 3600u64)
            } else {
                (v, 1u64)
            };
            num.parse::<u64>()
                .map(|n| Duration::from_secs(n * mult))
                .unwrap_or(Duration::from_secs(default_secs))
        }
        Err(_) => Duration::from_secs(default_secs),
    }
}

/// Read a secret from `NAME`, falling back to reading a file from `NAME_FILE`.
fn secret_env(name: &str) -> Option<String> {
    if let Ok(v) = std::env::var(name) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    let file_var = format!("{name}_FILE");
    if let Ok(path) = std::env::var(&file_var) {
        match std::fs::read_to_string(&path) {
            Ok(v) => {
                let v = v.trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
            Err(e) => {
                eprintln!("Failed to read {file_var}={path}: {e}");
            }
        }
    }
    None
}

fn list_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

pub fn load_config() -> Result<Config, String> {
    let emoji = bool_env("EMOJI", true);
    let quiet = bool_env("QUIET", false);

    let api_token = secret_env("CLOUDFLARE_API_TOKEN")
        .ok_or("CLOUDFLARE_API_TOKEN (or CLOUDFLARE_API_TOKEN_FILE) must be set")?;
    let admin_password = secret_env("ADMIN_PASSWORD")
        .ok_or("ADMIN_PASSWORD (or ADMIN_PASSWORD_FILE) must be set")?;
    if admin_password.len() < 8 {
        return Err("ADMIN_PASSWORD must be at least 8 characters long".to_string());
    }

    let listen = std::env::var("LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let session_ttl = duration_env_secs("SESSION_TTL", DEFAULT_SESSION_TTL_SECS);
    let update_timeout = duration_env_secs("UPDATE_TIMEOUT", DEFAULT_UPDATE_TIMEOUT_SECS);
    let detection_timeout = duration_env_secs("DETECTION_TIMEOUT", DEFAULT_DETECTION_TIMEOUT_SECS);
    let secure_cookies = bool_env("SECURE_COOKIES", false);

    let domains = list_env("DOMAINS");
    let ip4_provider =
        std::env::var("IP4_PROVIDER").unwrap_or_else(|_| "ipify".to_string());
    let ip6_provider =
        std::env::var("IP6_PROVIDER").unwrap_or_else(|_| "cloudflare.trace".to_string());

    let ttl = std::env::var("TTL")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .map(|v| if v < 30 { 1 } else { v })
        .unwrap_or(1);
    let proxied = bool_env("PROXIED", false);
    let record_comment = std::env::var("RECORD_COMMENT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    Ok(Config {
        api_token,
        admin_password,
        listen,
        session_ttl,
        update_timeout,
        detection_timeout,
        secure_cookies,
        domains,
        ip4_provider,
        ip6_provider,
        ttl,
        proxied,
        record_comment,
        emoji,
        quiet,
        api_base: std::env::var("CLOUDFLARE_API_BASE").ok().filter(|v| !v.is_empty()),
    })
}

pub fn print_config_summary(cfg: &Config, ppfmt: &PP) {
    if cfg.quiet {
        return;
    }
    ppfmt.infof("", &format!("Listen address: {}", cfg.listen));
    ppfmt.infof("", &format!("Session TTL: {}s", cfg.session_ttl.as_secs()));
    ppfmt.infof("", &format!("Secure cookies: {}", cfg.secure_cookies));
    if cfg.domains.is_empty() {
        ppfmt.infof("", "DDNS domains: (none configured — dashboard DDNS features disabled)");
    } else {
        ppfmt.infof("", &format!("DDNS domains: {}", cfg.domains.join(", ")));
        ppfmt.infof("", &format!("IPv4 provider: {}", cfg.ip4_provider));
        ppfmt.infof("", &format!("IPv6 provider: {}", cfg.ip6_provider));
    }
}
