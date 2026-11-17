//! Configuration via environment variables, following the cloudflare-ddns
//! philosophy: everything is configured with env vars, with `*_FILE` variants
//! for secrets (Docker secrets compatible).
//!
//! There is deliberately NO admin-password env var: the web UI asks for a
//! password on first access and stores only a PBKDF2 hash in the data dir.

use crate::pp::PP;
use reqwest::Url;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
pub const DEFAULT_DATA_DIR: &str = "/data";
pub const DEFAULT_SESSION_TTL_SECS: u64 = 24 * 60 * 60; // 24h
pub const DEFAULT_UPDATE_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_DETECTION_TIMEOUT_SECS: u64 = 5;
pub const DDNS_UPSTREAM_COMMIT: &str = "3f1a7220645a3f56eac94a6975b167bfd0f4ac5e";
const MAX_TOKEN_FILE_BYTES: usize = 4096;
/// Longest record comment the GUI accepts, in bytes, for record edits and
/// RECORD_COMMENT. Cloudflare allows 500 characters on paid plans and 100 on
/// Free, and rejects longer comments itself. Counting bytes is stricter for
/// non-ASCII text, where 500 bytes hold fewer than 500 characters.
pub(crate) const MAX_RECORD_COMMENT: usize = 500;

/// Cloudflare accepts TTL 1 (automatic) or 30 to 86400 seconds. Zones
/// outside Enterprise may need at least 60, which Cloudflare checks.
pub(crate) fn valid_ttl(ttl: u32) -> bool {
    ttl == 1 || (30..=86400).contains(&ttl)
}

/// The address in a URL's host when the host is an IP literal.
pub(crate) fn host_ip(url: &Url) -> Option<IpAddr> {
    url.host_str()?.trim_matches(['[', ']']).parse().ok()
}

/// True for `localhost` and loopback IP literals. URL parsing lowercases
/// host names, so `LOCALHOST` matches too.
pub(crate) fn is_loopback_host(url: &Url) -> bool {
    url.host_str() == Some("localhost") || host_ip(url).is_some_and(|ip| ip.is_loopback())
}

/// True when a URL has no user name, password, query or fragment.
pub(crate) fn bare_url(url: &Url) -> bool {
    url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

#[derive(Clone)]
pub struct Config {
    /// Cloudflare API token (Bearer).
    pub api_token: String,
    /// Address the HTTP server binds to.
    pub listen: SocketAddr,
    /// Directory holding state.json, ui settings and uploaded icon.
    pub data_dir: String,
    /// How long a login session stays valid.
    pub session_ttl: Duration,
    /// Timeout for Cloudflare API requests.
    pub update_timeout: Duration,
    /// Timeout for public IP detection requests.
    pub detection_timeout: Duration,
    /// Add the `Secure` attribute to session cookies (enable behind HTTPS).
    pub secure_cookies: bool,
    /// Trusted browser origin for a reverse proxy; HTTPS requires secure cookies.
    pub public_origin: Option<Url>,
    /// Union of configured names for independent DNS status and manual updates.
    pub domains: Vec<String>,
    /// Effective domain sets, including DOMAINS, for each family.
    pub ip4_domains: Vec<String>,
    pub ip6_domains: Vec<String>,
    /// standalone-v1 or shared-v1; neither observes or controls a daemon.
    pub ddns_contract: String,
    /// Exact comment required on existing records, if ownership is restricted.
    pub managed_record_comment: Option<String>,
    /// IPv4 provider under the bounded GUI contract, not daemon configuration.
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

// Written by hand so a debug print can never show the API token.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("data_dir", &self.data_dir)
            .field("ddns_contract", &self.ddns_contract)
            .field("domains", &self.domains)
            .finish_non_exhaustive()
    }
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err("expected true/false, yes/no or 1/0".into()),
    }
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    let (number, multiplier) = if let Some(v) = value.strip_suffix('h') {
        (v, 3600)
    } else if let Some(v) = value.strip_suffix('m') {
        (v, 60)
    } else {
        (value.strip_suffix('s').unwrap_or(value), 1)
    };
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected a positive integer with optional s, m or h suffix".into());
    }
    let seconds = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|n| (1..=31_536_000).contains(n))
        .ok_or("duration must be between 1 second and 365 days")?;
    Ok(Duration::from_secs(seconds))
}

/// Reads the API token from `CLOUDFLARE_API_TOKEN`, or from the file named by
/// `CLOUDFLARE_API_TOKEN_FILE` when the first is unset.
fn api_token(get: &impl Fn(&str) -> Result<Option<String>, String>) -> Result<String, String> {
    let token = match get("CLOUDFLARE_API_TOKEN")?.filter(|v| !v.trim().is_empty()) {
        Some(v) => v,
        None => {
            let path = get("CLOUDFLARE_API_TOKEN_FILE")?
                .filter(|v| !v.trim().is_empty())
                .ok_or("CLOUDFLARE_API_TOKEN (or CLOUDFLARE_API_TOKEN_FILE) must be set")?;
            read_token_file(&path)?
        }
    };
    let token = token.trim();
    if token.is_empty()
        || token == "YOUR-CLOUDFLARE-API-TOKEN"
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err("Invalid CLOUDFLARE_API_TOKEN (value omitted)".into());
    }
    Ok(token.to_string())
}

/// Reads a token file of at most `MAX_TOKEN_FILE_BYTES`. A failed read
/// reports the I/O error, such as a missing file or denied permission, and
/// never the file content.
fn read_token_file(path: &str) -> Result<String, String> {
    let failed = |error: std::io::Error| format!("Cannot read CLOUDFLARE_API_TOKEN_FILE: {error}");
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(failed)?
        .take(MAX_TOKEN_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if bytes.len() > MAX_TOKEN_FILE_BYTES {
        return Err(format!(
            "CLOUDFLARE_API_TOKEN_FILE is larger than {MAX_TOKEN_FILE_BYTES} bytes"
        ));
    }
    String::from_utf8(bytes).map_err(|_| "CLOUDFLARE_API_TOKEN_FILE is not UTF-8 text".into())
}

fn parse_domains(value: &str) -> Result<Vec<String>, String> {
    let mut domains = Vec::new();
    for entry in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let domain = entry
            .strip_suffix('.')
            .unwrap_or(entry)
            .to_ascii_lowercase();
        let name = domain.strip_prefix("*.").unwrap_or(&domain);
        if domain.len() > 253
            || !name.contains('.')
            || name.parse::<std::net::IpAddr>().is_ok()
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err("expected fully qualified ASCII DNS names (optional leading *.)".into());
        }
        if !domains.contains(&domain) {
            domains.push(domain);
        }
        if domains.len() > 100 {
            return Err("at most 100 DDNS names are supported".into());
        }
    }
    Ok(domains)
}

fn validate_provider(provider: &str, ipv6: bool) -> Result<(), String> {
    if matches!(provider, "none" | "ipify" | "cloudflare.trace") {
        return Ok(());
    }
    if let Some(list) = provider.strip_prefix("literal:") {
        let mut matching = 0;
        for entry in list.split(',') {
            // ddns.rs treats ::ffff:a.b.c.d as IPv4, so count it as IPv4 here.
            let address = entry
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| "invalid literal provider address")?
                .to_canonical();
            if address.is_ipv6() == ipv6 {
                matching += 1;
            }
        }
        if matching != 1 {
            return Err("literal provider requires exactly one address of its family".into());
        }
        return Ok(());
    }
    let Some(endpoint) = provider
        .strip_prefix("url:")
        .or_else(|| provider.strip_prefix("cloudflare.trace:"))
    else {
        return Err("unsupported provider; use ipify, cloudflare.trace, \
                    cloudflare.trace:<url>, url:<url>, literal:<ip> or none"
            .into());
    };
    let url = Url::parse(endpoint).map_err(|_| "invalid provider URL")?;
    // Provider URLs may carry a query, so `bare_url` is too strict here.
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || endpoint.contains('@')
        || url.fragment().is_some()
    {
        return Err("provider requires an http(s) URL without credentials, \
                    interface binding or fragment"
            .into());
    }
    Ok(())
}

fn exact_comment_filter(value: &str) -> Result<String, String> {
    let body = value
        .strip_prefix('^')
        .and_then(|v| v.strip_suffix('$'))
        .ok_or("only an anchored exact-comment regex (^literal$) is supported")?;
    let mut comment = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let escaped = chars
                .next()
                .filter(|c| ".^$*+?()[]{}|\\".contains(*c))
                .ok_or("only escaped regex punctuation is supported")?;
            comment.push(escaped);
        } else if ".^$*+?()[]{}|".contains(c) || c.is_control() {
            return Err("only an anchored exact-comment regex (^literal$) is supported".into());
        } else {
            comment.push(c);
        }
    }
    if comment.is_empty() {
        return Err("managed comment must not be empty".into());
    }
    Ok(comment)
}

fn unsupported_setting(name: &str) -> bool {
    const REJECTED: &[&str] = &[
        "UPDATE_CRON",
        "UPDATE_ON_START",
        "DELETE_ON_STOP",
        "DELETE_ON_FAILURE",
        "WAF_LISTS",
        "WAF_LIST_DESCRIPTION",
        "WAF_LIST_ITEM_COMMENT",
        "MANAGED_WAF_LIST_ITEMS_COMMENT_REGEX",
        "SHOUTRRR",
        "HEALTHCHECKS",
        "UPTIMEKUMA",
        "CONFIG_PATH",
        "CF_API_TOKEN",
        "CF_API_TOKEN_FILE",
        "IP4_POLICY",
        "IP6_POLICY",
        "CF_ACCOUNT_ID",
        "PUID",
        "PGID",
    ];
    REJECTED.contains(&name)
        || name.starts_with("CF_DDNS_")
        || [
            "DOMAINS_",
            "IP4_DOMAINS_",
            "IP6_DOMAINS_",
            "IP4_PROVIDER_",
            "IP6_PROVIDER_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

pub fn load_config() -> Result<Config, String> {
    let names = std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .collect::<Vec<_>>();
    load_config_from(
        |name| match std::env::var(name) {
            Ok(v) => Ok(Some(v)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(format!("{name}: expected UTF-8 text")),
        },
        &names,
    )
}

fn load_config_from(
    get_raw: impl Fn(&str) -> Result<Option<String>, String>,
    names: &[String],
) -> Result<Config, String> {
    // Names are checked whatever their value, so an empty updater setting
    // still stops startup.
    for name in names {
        if unsupported_setting(name) {
            return Err(format!("{name} is unsupported by the GUI DDNS v1 contract; use a separate companion environment"));
        }
    }
    // As in cloudflare-ddns, a variable set to an empty string counts as unset.
    let get = |name: &str| -> Result<Option<String>, String> {
        Ok(get_raw(name)?.filter(|v| !v.is_empty()))
    };
    let value = |name: &str, default: &str| -> Result<String, String> {
        Ok(get(name)?.unwrap_or_else(|| default.into()))
    };
    let boolean = |name: &str, default: bool| -> Result<bool, String> {
        match get(name)? {
            Some(v) => parse_bool(&v).map_err(|e| format!("{name}: {e}")),
            None => Ok(default),
        }
    };
    let duration = |name: &str, default: u64| -> Result<Duration, String> {
        match get(name)? {
            Some(v) => parse_duration(&v).map_err(|e| format!("{name}: {e}")),
            None => Ok(Duration::from_secs(default)),
        }
    };
    let emoji = boolean("EMOJI", true)?;
    let quiet = boolean("QUIET", false)?;
    let api_token = api_token(&get)?;
    let listen: SocketAddr = value("LISTEN", DEFAULT_LISTEN)?
        .parse()
        .map_err(|_| "LISTEN: expected IP:port")?;
    let data_dir = value("DATA_DIR", DEFAULT_DATA_DIR)?;
    if data_dir.trim().is_empty() {
        return Err("DATA_DIR must not be empty".into());
    }
    let session_ttl = duration("SESSION_TTL", DEFAULT_SESSION_TTL_SECS)?;
    let update_timeout = duration("UPDATE_TIMEOUT", DEFAULT_UPDATE_TIMEOUT_SECS)?;
    let detection_timeout = duration("DETECTION_TIMEOUT", DEFAULT_DETECTION_TIMEOUT_SECS)?;
    let secure_cookies = boolean("SECURE_COOKIES", false)?;
    let public_origin = get("PUBLIC_ORIGIN")?
        .map(|v| {
            let url = Url::parse(&v).map_err(|_| "PUBLIC_ORIGIN: expected an HTTP(S) origin")?;
            if url.host_str().is_none()
                || !bare_url(&url)
                || url.path() != "/"
                || !(url.scheme() == "https" || url.scheme() == "http" && is_loopback_host(&url))
            {
                return Err("PUBLIC_ORIGIN: HTTPS origin required (HTTP allowed only on loopback)");
            }
            if url.scheme() == "https" && !secure_cookies {
                return Err("PUBLIC_ORIGIN: HTTPS requires SECURE_COOKIES=true");
            }
            // Parsing already lowercased the host and dropped a default port.
            Ok(url)
        })
        .transpose()?;
    let common = parse_domains(&value("DOMAINS", "")?).map_err(|e| format!("DOMAINS: {e}"))?;
    let mut ip4_domains = common.clone();
    let mut ip6_domains = common;
    for (name, domains) in [
        ("IP4_DOMAINS", &mut ip4_domains),
        ("IP6_DOMAINS", &mut ip6_domains),
    ] {
        for domain in parse_domains(&value(name, "")?).map_err(|e| format!("{name}: {e}"))? {
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }
    }
    let mut domains = ip4_domains.clone();
    for domain in &ip6_domains {
        if !domains.contains(domain) {
            domains.push(domain.clone());
        }
    }
    if domains.len() > 100 {
        return Err("at most 100 DDNS names are supported".into());
    }
    let ip4_provider = value("IP4_PROVIDER", "ipify")?;
    let ip6_provider = value("IP6_PROVIDER", "cloudflare.trace")?;
    validate_provider(&ip4_provider, false).map_err(|e| format!("IP4_PROVIDER: {e}"))?;
    validate_provider(&ip6_provider, true).map_err(|e| format!("IP6_PROVIDER: {e}"))?;
    if !boolean("REJECT_CLOUDFLARE_IPS", true)? {
        return Err(
            "REJECT_CLOUDFLARE_IPS=false is unsupported by the GUI v1 address policy".into(),
        );
    }
    let ttl_text = value("TTL", "1")?;
    // `parse` alone would also accept a leading `+`.
    let ttl = Some(ttl_text.trim())
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse::<u32>().ok())
        .filter(|&t| valid_ttl(t))
        .ok_or("TTL: expected 1 or 30..86400")?;
    let proxied = boolean("PROXIED", false)?;
    let record_comment = get("RECORD_COMMENT")?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if record_comment
        .as_ref()
        .is_some_and(|v| v.len() > MAX_RECORD_COMMENT || v.chars().any(char::is_control))
    {
        return Err(format!(
            "RECORD_COMMENT: at most {MAX_RECORD_COMMENT} bytes, without control characters"
        ));
    }
    let managed_record_comment = get("MANAGED_RECORDS_COMMENT_REGEX")?
        .map(|v| exact_comment_filter(&v))
        .transpose()
        .map_err(|e| format!("MANAGED_RECORDS_COMMENT_REGEX: {e}"))?;
    if managed_record_comment.is_some() && managed_record_comment != record_comment {
        return Err("RECORD_COMMENT must match the exact managed comment filter".into());
    }
    let ddns_contract = value("GUI_DDNS_CONTRACT", "standalone-v1")?;
    if !matches!(ddns_contract.as_str(), "standalone-v1" | "shared-v1") {
        return Err("GUI_DDNS_CONTRACT: expected standalone-v1 or shared-v1".into());
    }
    if ddns_contract == "shared-v1" && managed_record_comment.is_none() {
        return Err(
            "shared-v1 requires RECORD_COMMENT and an exact MANAGED_RECORDS_COMMENT_REGEX".into(),
        );
    }
    let shared_updater_paused = boolean("GUI_SHARED_UPDATER_PAUSED", false)?;
    if ddns_contract == "shared-v1" && !shared_updater_paused {
        return Err("shared-v1 requires the companion to be paused and GUI_SHARED_UPDATER_PAUSED=true; concurrent updater coordination is unavailable".into());
    }
    let api_base = get("CLOUDFLARE_API_BASE")?;
    if let Some(base) = &api_base {
        let url = Url::parse(base).map_err(|_| "invalid CLOUDFLARE_API_BASE")?;
        // The API token goes to this URL, so only an IP literal counts as
        // loopback here. A name could resolve elsewhere.
        if !host_ip(&url).is_some_and(|ip| ip.is_loopback())
            || !matches!(url.scheme(), "http" | "https")
            || !bare_url(&url)
        {
            return Err(
                "CLOUDFLARE_API_BASE is restricted to credential-free loopback test URLs".into(),
            );
        }
    }

    Ok(Config {
        api_token,
        listen,
        data_dir,
        session_ttl,
        update_timeout,
        detection_timeout,
        secure_cookies,
        public_origin,
        domains,
        ip4_domains,
        ip6_domains,
        ddns_contract,
        managed_record_comment,
        ip4_provider,
        ip6_provider,
        ttl: if proxied { 1 } else { i64::from(ttl) },
        proxied,
        record_comment,
        emoji,
        quiet,
        api_base,
    })
}

pub fn print_config_summary(cfg: &Config, ppfmt: &PP) {
    if cfg.quiet {
        return;
    }
    ppfmt.infof("", format!("Listen address: {}", cfg.listen));
    ppfmt.infof("", format!("Data directory: {}", cfg.data_dir));
    ppfmt.infof("", format!("Session TTL: {}s", cfg.session_ttl.as_secs()));
    ppfmt.infof("", format!("Secure cookies: {}", cfg.secure_cookies));
    ppfmt.infof("", format!("GUI DDNS contract: {} (upstream comparison {DDNS_UPSTREAM_COMMIT}; daemon not observed)", cfg.ddns_contract));
    if cfg.domains.is_empty() {
        ppfmt.infof(
            "",
            "DDNS domains: (none configured - dashboard DDNS features disabled)",
        );
    } else {
        ppfmt.infof("", format!("DDNS domains: {}", cfg.domains.join(", ")));
        for (family, provider) in [("IPv4", &cfg.ip4_provider), ("IPv6", &cfg.ip6_provider)] {
            let kind = provider
                .split_once(':')
                .map_or(provider.as_str(), |(kind, _)| kind);
            ppfmt.infof("", format!("{family} provider: {kind} (details omitted)"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(values: &[(&str, &str)]) -> Result<Config, String> {
        let mut vars = std::collections::BTreeMap::from([(
            "CLOUDFLARE_API_TOKEN".to_string(),
            "dummy-test-token".to_string(),
        )]);
        for (name, value) in values {
            vars.insert(name.to_string(), value.to_string());
        }
        load_config_from(
            |name| Ok(vars.get(name).cloned()),
            &vars.keys().cloned().collect::<Vec<_>>(),
        )
    }

    #[test]
    fn malformed_booleans_fail_closed() {
        for value in ["", "tru", "on", "off", "2", "false junk"] {
            assert!(parse_bool(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn malformed_zero_and_overflowing_durations_fail_closed() {
        for value in [
            "",
            "0",
            "-1",
            "junk",
            "1h30m",
            "18446744073709551615h",
            "18446744073709551616s",
        ] {
            assert!(parse_duration(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn duration_overflow_is_an_error_not_a_panic() {
        assert!(parse_duration("18446744073709551615h").is_err());
    }

    #[test]
    fn strict_values_are_used_by_every_config_field() {
        for name in [
            "EMOJI",
            "QUIET",
            "SECURE_COOKIES",
            "PROXIED",
            "REJECT_CLOUDFLARE_IPS",
        ] {
            assert!(config(&[(name, "typo")]).unwrap_err().contains(name));
            assert!(config(&[(name, " ")]).unwrap_err().contains(name));
        }
        for name in ["SESSION_TTL", "UPDATE_TIMEOUT", "DETECTION_TIMEOUT"] {
            for value in ["0", "junk", "18446744073709551615h", "31536001"] {
                assert!(config(&[(name, value)]).unwrap_err().contains(name));
            }
        }
        for (text, expected) in [
            ("YES", true),
            (" true ", true),
            ("1", true),
            ("No", false),
            ("0", false),
            ("false", false),
        ] {
            assert_eq!(parse_bool(text).unwrap(), expected);
        }
        for (text, expected) in [
            ("1", 1),
            ("2s", 2),
            ("3m", 180),
            ("4h", 14400),
            ("31536000s", 31536000),
        ] {
            assert_eq!(parse_duration(text).unwrap().as_secs(), expected);
        }
    }

    #[test]
    fn ttl_is_validated_before_proxy_normalization() {
        for value in [
            " ",
            "junk",
            "0",
            "2",
            "29",
            "-1",
            "86401",
            "+300",
            "9223372036854775808",
        ] {
            for proxied in ["true", "false"] {
                assert!(config(&[("TTL", value), ("PROXIED", proxied)])
                    .unwrap_err()
                    .contains("TTL"));
            }
        }
        for value in ["1", "30", "60", "300", "86400"] {
            assert_eq!(
                config(&[("TTL", value)]).unwrap().ttl,
                value.parse::<i64>().unwrap()
            );
            assert_eq!(
                config(&[("TTL", value), ("PROXIED", "true")]).unwrap().ttl,
                1
            );
        }
    }

    #[test]
    fn domain_sets_are_normalized_deduplicated_and_family_specific() {
        let cfg = config(&[
            ("DOMAINS", "Example.COM,example.com.,*.example.com"),
            ("IP4_DOMAINS", "v4.example.com,example.com"),
            ("IP6_DOMAINS", "v6.example.com"),
        ])
        .unwrap();
        assert_eq!(
            cfg.domains,
            [
                "example.com",
                "*.example.com",
                "v4.example.com",
                "v6.example.com"
            ]
        );
        assert_eq!(
            cfg.ip4_domains,
            ["example.com", "*.example.com", "v4.example.com"]
        );
        assert_eq!(
            cfg.ip6_domains,
            ["example.com", "*.example.com", "v6.example.com"]
        );
        for domain in [
            "localhost",
            "https://example.com",
            "example.com?query",
            "../example.com",
            "foo..com",
            "foo.com..",
            "-foo.com",
            "foo-.com",
            "192.0.2.1",
            "foo_underscore.com",
        ] {
            assert!(config(&[("DOMAINS", domain)]).is_err(), "accepted {domain}");
        }
    }

    #[test]
    fn providers_are_bounded_and_invalid_names_fail_at_startup() {
        for provider in [
            "none",
            "ipify",
            "cloudflare.trace",
            "url:http://127.0.0.1:1234/ip",
            "cloudflare.trace:https://provider.example/trace",
            "literal:192.0.2.1",
            "literal:192.0.2.1,2001:db8::1",
            "literal:10.0.0.1",
        ] {
            assert!(
                config(&[("IP4_PROVIDER", provider)]).is_ok(),
                "rejected {provider}"
            );
        }
        for provider in [
            " ",
            "typo",
            "cloudflare.doh",
            "local",
            "local.iface:eth0",
            "local.iface.stable:eth0",
            "ipify@eth0",
            "url:http://provider.example/ip@eth0",
            "url:file:///etc/passwd",
            "url:https://dummy-user:dummy-pass@provider.example/ip",
            "cloudflare.trace:",
            "literal:",
            "literal:2001:db8::1",
            "literal:192.0.2.1,192.0.2.2",
            "literal:192.0.2.1,junk",
        ] {
            assert!(
                config(&[("IP4_PROVIDER", provider)])
                    .unwrap_err()
                    .contains("IP4_PROVIDER"),
                "accepted {provider}"
            );
        }
        assert!(config(&[("IP6_PROVIDER", "literal:2001:db8::1")]).is_ok());
        assert!(config(&[("IP6_PROVIDER", "literal:192.0.2.1")]).is_err());
        assert!(config(&[("REJECT_CLOUDFLARE_IPS", "false")]).is_err());
    }

    #[test]
    fn unsupported_companion_settings_are_never_silently_ignored() {
        for name in [
            "UPDATE_CRON",
            "UPDATE_ON_START",
            "DELETE_ON_STOP",
            "DELETE_ON_FAILURE",
            "WAF_LISTS",
            "WAF_LIST_DESCRIPTION",
            "WAF_LIST_ITEM_COMMENT",
            "MANAGED_WAF_LIST_ITEMS_COMMENT_REGEX",
            "SHOUTRRR",
            "HEALTHCHECKS",
            "UPTIMEKUMA",
            "CONFIG_PATH",
            "CF_API_TOKEN",
            "CF_API_TOKEN_FILE",
            "IP4_POLICY",
            "IP6_POLICY",
            "CF_ACCOUNT_ID",
            "PUID",
            "PGID",
            "CF_DDNS_SOMETHING",
            "DOMAINS_2",
            "IP4_DOMAINS_2",
            "IP6_DOMAINS_2",
            "IP4_PROVIDER_2",
            "IP6_PROVIDER_2",
        ] {
            for value in ["", "dummy-sensitive-marker"] {
                let error = config(&[(name, value)]).unwrap_err();
                assert!(error.contains(name));
                assert!(!error.contains("dummy-sensitive-marker"));
            }
        }
    }

    #[test]
    fn shared_contract_requires_exact_matching_ownership() {
        assert_eq!(config(&[]).unwrap().ddns_contract, "standalone-v1");
        assert!(config(&[("GUI_DDNS_CONTRACT", "shared-v1")]).is_err());
        assert!(config(&[("GUI_DDNS_CONTRACT", "future-v2")]).is_err());
        let values = [
            ("GUI_DDNS_CONTRACT", "shared-v1"),
            ("GUI_SHARED_UPDATER_PAUSED", "true"),
            ("RECORD_COMMENT", "managed by GUI"),
            ("MANAGED_RECORDS_COMMENT_REGEX", "^managed by GUI$"),
        ];
        assert_eq!(
            config(&values).unwrap().managed_record_comment,
            Some("managed by GUI".into())
        );
        for pattern in [
            "managed by GUI",
            ".*",
            "^.*$",
            "^(foo|bar)$",
            "^foo\\sbar$",
            "^$",
            "^wrong$",
        ] {
            assert!(config(&[
                ("RECORD_COMMENT", "managed by GUI"),
                ("MANAGED_RECORDS_COMMENT_REGEX", pattern)
            ])
            .is_err());
        }
        assert_eq!(
            exact_comment_filter(r"^managed\.GUI\[v1\]$").unwrap(),
            "managed.GUI[v1]"
        );
    }

    #[test]
    fn trusted_origin_and_api_override_are_confined() {
        for origin in [
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com/path",
            "https://example.com?query",
            "https://example.com#fragment",
            "file:///tmp/test",
        ] {
            assert!(config(&[("PUBLIC_ORIGIN", origin), ("SECURE_COOKIES", "true")]).is_err());
        }
        assert!(config(&[("PUBLIC_ORIGIN", "https://example.com")]).is_err());
        assert_eq!(
            config(&[
                ("PUBLIC_ORIGIN", "https://EXAMPLE.com:443/"),
                ("SECURE_COOKIES", "true")
            ])
            .unwrap()
            .public_origin
            .map(|url| url.origin().ascii_serialization()),
            Some("https://example.com".into())
        );
        for origin in [
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://localhost:8080",
        ] {
            assert!(config(&[("PUBLIC_ORIGIN", origin)]).is_ok());
        }
        for base in [
            "http://api.example/client/v4",
            "https://api.example",
            "http://dummy-user@127.0.0.1",
            "http://127.0.0.1?query",
        ] {
            assert!(config(&[("CLOUDFLARE_API_BASE", base)]).is_err());
        }
        assert!(config(&[("CLOUDFLARE_API_BASE", "http://127.0.0.1:1234/client/v4")]).is_ok());
    }

    #[test]
    fn empty_values_count_as_unset() {
        let cfg = config(&[
            ("PUBLIC_ORIGIN", ""),
            ("LISTEN", ""),
            ("DATA_DIR", ""),
            ("SESSION_TTL", ""),
            ("SECURE_COOKIES", ""),
            ("TTL", ""),
            ("PROXIED", ""),
            ("IP4_PROVIDER", ""),
            ("IP6_PROVIDER", ""),
            ("RECORD_COMMENT", ""),
            ("GUI_DDNS_CONTRACT", ""),
            ("CLOUDFLARE_API_BASE", ""),
            ("REJECT_CLOUDFLARE_IPS", ""),
        ])
        .unwrap();
        assert!(cfg.public_origin.is_none());
        assert_eq!(cfg.listen.to_string(), DEFAULT_LISTEN);
        assert_eq!(cfg.data_dir, DEFAULT_DATA_DIR);
        assert_eq!(cfg.session_ttl.as_secs(), DEFAULT_SESSION_TTL_SECS);
        assert!(!cfg.secure_cookies && !cfg.proxied);
        assert_eq!(cfg.ttl, 1);
        assert_eq!(
            (cfg.ip4_provider.as_str(), cfg.ip6_provider.as_str()),
            ("ipify", "cloudflare.trace")
        );
        assert_eq!(cfg.record_comment, None);
        assert_eq!(cfg.ddns_contract, "standalone-v1");
        assert_eq!(cfg.api_base, None);
    }

    #[test]
    fn record_comment_has_the_api_comment_limit() {
        let comment = "c".repeat(MAX_RECORD_COMMENT);
        assert!(config(&[("RECORD_COMMENT", &comment)]).is_ok());
        let longer = comment + "c";
        assert!(config(&[("RECORD_COMMENT", &longer)])
            .unwrap_err()
            .contains("RECORD_COMMENT"));
    }

    #[test]
    fn mapped_ipv4_literals_are_checked_as_ipv4() {
        assert!(config(&[("IP4_PROVIDER", "literal:::ffff:192.0.2.1")]).is_ok());
        assert!(config(&[("IP6_PROVIDER", "literal:::ffff:192.0.2.1")]).is_err());
        assert!(config(&[("IP6_PROVIDER", "literal:::ffff:192.0.2.1,2001:db8::1")]).is_ok());
    }

    #[test]
    fn token_file_read_is_bounded_and_reports_why_it_failed() {
        let dir = std::env::temp_dir().join(format!(
            "ddns-config-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("token");
        let file = |path: &std::path::Path| {
            config(&[
                ("CLOUDFLARE_API_TOKEN", ""),
                ("CLOUDFLARE_API_TOKEN_FILE", path.to_str().unwrap()),
            ])
        };
        std::fs::write(&path, "dummy-file-token\n").unwrap();
        assert_eq!(file(&path).unwrap().api_token, "dummy-file-token");

        let mut oversized = b"dummy-file-token".to_vec();
        oversized.resize(MAX_TOKEN_FILE_BYTES + 1, b'\n');
        std::fs::write(&path, &oversized).unwrap();
        let error = file(&path).unwrap_err();
        assert!(error.contains("CLOUDFLARE_API_TOKEN_FILE") && !error.contains("dummy-file-token"));

        let missing = dir.join("missing");
        let expected = std::fs::File::open(&missing).unwrap_err().to_string();
        let error = file(&missing).unwrap_err();
        assert!(error.contains(&expected), "{error}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&path, "dummy-file-token").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            // Root ignores file modes, so the check only runs as a normal user.
            if let Err(denied) = std::fs::File::open(&path) {
                let error = file(&path).unwrap_err();
                assert!(error.contains(&denied.to_string()), "{error}");
                assert!(!error.contains("dummy-file-token"));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_output_never_includes_the_token() {
        let cfg = config(&[("CLOUDFLARE_API_TOKEN", "dummy-debug-marker")]).unwrap();
        assert!(!format!("{cfg:?}").contains("dummy-debug-marker"));
    }

    #[test]
    fn secret_validation_errors_never_include_values() {
        for token in [
            "dummy sensitive marker",
            "\"dummy-sensitive-marker\"",
            "YOUR-CLOUDFLARE-API-TOKEN",
        ] {
            let error = config(&[("CLOUDFLARE_API_TOKEN", token)]).unwrap_err();
            assert!(!error.contains(token));
        }
    }
}
