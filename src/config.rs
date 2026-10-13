//! Configuration via environment variables, following the cloudflare-ddns
//! philosophy: everything is configured with env vars, with `*_FILE` variants
//! for secrets (Docker secrets compatible).
//!
//! There is deliberately NO admin-password env var: the web UI asks for a
//! password on first access and stores only a PBKDF2 hash in the data dir.

use crate::pp::PP;
use std::time::Duration;

pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
pub const DEFAULT_DATA_DIR: &str = "/data";
pub const DEFAULT_SESSION_TTL_SECS: u64 = 24 * 60 * 60; // 24h
pub const DEFAULT_UPDATE_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_DETECTION_TIMEOUT_SECS: u64 = 5;
pub const DDNS_UPSTREAM_COMMIT: &str = "3f1a7220645a3f56eac94a6975b167bfd0f4ac5e";

#[derive(Debug, Clone)]
pub struct Config {
    /// Cloudflare API token (Bearer).
    pub api_token: String,
    /// Address the HTTP server binds to.
    pub listen: String,
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
    pub public_origin: Option<String>,
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

/// Read a secret from `NAME`, falling back to reading a file from `NAME_FILE`.
fn secret_env(get: &impl Fn(&str) -> Result<Option<String>, String>) -> Result<String, String> {
    let token = match get("CLOUDFLARE_API_TOKEN")?.filter(|v| !v.trim().is_empty()) {
        Some(v) => v,
        None => {
            let path = get("CLOUDFLARE_API_TOKEN_FILE")?
                .filter(|v| !v.trim().is_empty())
                .ok_or("CLOUDFLARE_API_TOKEN (or CLOUDFLARE_API_TOKEN_FILE) must be set")?;
            std::fs::read_to_string(path).map_err(|_| "Cannot read CLOUDFLARE_API_TOKEN_FILE")?
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
    match provider {
        "none" | "ipify" | "cloudflare.trace" => Ok(()),
        _ if provider.starts_with("literal:") => {
            let mut matching = 0;
            for entry in provider[8..].split(',') {
                let address = entry.trim().parse::<std::net::IpAddr>()
                    .map_err(|_| "invalid literal provider address")?;
                if address.is_ipv6() == ipv6 { matching += 1; }
            }
            if matching != 1 { return Err("literal provider requires exactly one address of its family".into()); }
            Ok(())
        }
        _ if provider.starts_with("url:") || provider.starts_with("cloudflare.trace:") => {
            let (_, endpoint) = provider.split_once(':').unwrap();
            let url = reqwest::Url::parse(endpoint).map_err(|_| "invalid provider URL")?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
                || !url.username().is_empty() || url.password().is_some()
                || endpoint.contains('@') || url.fragment().is_some() {
                return Err("provider requires an http(s) URL without credentials, interface binding or fragment".into());
            }
            Ok(())
        }
        _ => Err("unsupported provider; use ipify, cloudflare.trace, cloudflare.trace:<url>, url:<url>, literal:<ip> or none".into()),
    }
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
    get: impl Fn(&str) -> Result<Option<String>, String>,
    names: &[String],
) -> Result<Config, String> {
    for name in names {
        if unsupported_setting(name) {
            return Err(format!("{name} is unsupported by the GUI DDNS v1 contract; use a separate companion environment"));
        }
    }
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
    let api_token = secret_env(&get)?;
    let listen = value("LISTEN", DEFAULT_LISTEN)?;
    listen
        .parse::<std::net::SocketAddr>()
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
            let url =
                reqwest::Url::parse(&v).map_err(|_| "PUBLIC_ORIGIN: expected an HTTP(S) origin")?;
            let loopback = url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
                || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            {
                return Err("PUBLIC_ORIGIN: HTTPS origin required (HTTP allowed only on loopback)");
            }
            if url.scheme() == "https" && !secure_cookies {
                return Err("PUBLIC_ORIGIN: HTTPS requires SECURE_COOKIES=true");
            }
            Ok(url.origin().ascii_serialization())
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
    if ttl_text.trim().is_empty() || !ttl_text.trim().bytes().all(|b| b.is_ascii_digit()) {
        return Err("TTL: expected 1 or 30..86400".into());
    }
    let ttl = ttl_text
        .trim()
        .parse::<i64>()
        .map_err(|_| "TTL: expected 1 or 30..86400")?;
    if ttl != 1 && !(30..=86400).contains(&ttl) {
        return Err("TTL: expected 1 or 30..86400".into());
    }
    let proxied = boolean("PROXIED", false)?;
    let record_comment = get("RECORD_COMMENT")?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if record_comment
        .as_ref()
        .is_some_and(|v| v.len() > 1024 || v.chars().any(char::is_control))
    {
        return Err("RECORD_COMMENT: at most 1024 bytes, without control characters".into());
    }
    let managed_record_comment = get("MANAGED_RECORDS_COMMENT_REGEX")?
        .filter(|v| !v.is_empty())
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
    let api_base = get("CLOUDFLARE_API_BASE")?.filter(|v| !v.is_empty());
    if let Some(base) = &api_base {
        let url = reqwest::Url::parse(base).map_err(|_| "invalid CLOUDFLARE_API_BASE")?;
        let loopback = url
            .host_str()
            .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if !loopback
            || !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
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
        ttl: if proxied { 1 } else { ttl },
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
    ppfmt.infof("", &format!("Listen address: {}", cfg.listen));
    ppfmt.infof("", &format!("Data directory: {}", cfg.data_dir));
    ppfmt.infof("", &format!("Session TTL: {}s", cfg.session_ttl.as_secs()));
    ppfmt.infof("", &format!("Secure cookies: {}", cfg.secure_cookies));
    ppfmt.infof("", &format!("GUI DDNS contract: {} (upstream comparison {DDNS_UPSTREAM_COMMIT}; daemon not observed)", cfg.ddns_contract));
    if cfg.domains.is_empty() {
        ppfmt.infof(
            "",
            "DDNS domains: (none configured - dashboard DDNS features disabled)",
        );
    } else {
        ppfmt.infof("", &format!("DDNS domains: {}", cfg.domains.join(", ")));
        for (family, provider) in [("IPv4", &cfg.ip4_provider), ("IPv6", &cfg.ip6_provider)] {
            let kind = provider
                .split_once(':')
                .map_or(provider.as_str(), |(kind, _)| kind);
            ppfmt.infof("", &format!("{family} provider: {kind} (details omitted)"));
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
            assert!(config(&[(name, "")]).unwrap_err().contains(name));
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
            "",
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
            "",
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
            .public_origin,
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
