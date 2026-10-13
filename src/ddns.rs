//! Independent manual DDNS updates under the bounded GUI v1 contract.
//! This module neither observes nor controls a companion daemon.

use crate::cloudflare::{CloudflareClient, DnsRecord, RecordPatch, RecordPayload};
use crate::config::Config;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[derive(Debug, Serialize, Clone)]
pub struct DomainStatus {
    pub domain: String,
    pub record_type: String, // "A" or "AAAA"
    pub detected_ip: Option<String>,
    pub dns_ips: Vec<String>,
    pub in_sync: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DdnsStatus {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub ipv4_error: Option<String>,
    pub ipv6_error: Option<String>,
    pub domains: Vec<DomainStatus>,
    pub configured: bool,
    pub contract_version: String,
    pub manual_updates_enabled: bool,
    pub daemon_status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct DdnsOutcome {
    pub domain: String,
    pub record_type: String,
    pub status: &'static str,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DdnsUpdate {
    pub success: bool,
    pub outcomes: Vec<DdnsOutcome>,
    pub log: Vec<String>,
}

/// Detect the public IP using a cloudflare-ddns style provider string.
pub async fn detect_ip(
    provider: &str,
    family: &str, // "ipv4" or "ipv6"
    timeout: Duration,
) -> Result<Option<String>, String> {
    let ipv6 = match family {
        "ipv4" => false,
        "ipv6" => true,
        _ => return Err("invalid IP family (expected ipv4 or ipv6)".to_string()),
    };
    // Prefixed providers: url:<endpoint>, literal:<ips>
    if let Some(url) = provider.strip_prefix("url:") {
        return fetch_ip(url, false, ipv6, timeout).await;
    }
    if let Some(url) = provider.strip_prefix("cloudflare.trace:") {
        return fetch_ip(url, true, ipv6, timeout).await;
    }
    if let Some(ips) = provider.strip_prefix("literal:") {
        let mut selected = None;
        for entry in ips.split(',') {
            let ip = entry
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| "invalid IP address in literal provider".to_string())?;
            // literal: is an explicit opt-in to private/test addresses, not Cloudflare anycast.
            if ip.is_unspecified()
                || ip.is_multicast()
                || matches!(ip,IpAddr::V4(v4) if v4.is_broadcast())
                || cloudflare_address(ip)
            {
                return Err("literal provider address rejected by GUI v1 address policy".into());
            }
            if ip.is_ipv6() == ipv6 && selected.is_none() {
                selected = Some(ip.to_string());
            }
        }
        return selected
            .map(Some)
            .ok_or_else(|| "no matching IP family in literal provider".to_string());
    }

    match provider {
        "none" => Ok(None),
        "ipify" => {
            let url = if ipv6 {
                "https://api6.ipify.org"
            } else {
                "https://api.ipify.org"
            };
            fetch_ip(url, false, ipv6, timeout).await
        }
        "cloudflare.trace" => {
            fetch_ip(
                "https://www.cloudflare.com/cdn-cgi/trace",
                true,
                ipv6,
                timeout,
            )
            .await
        }
        _ => Err("provider is unsupported by the GUI v1 contract".into()),
    }
}

// Snapshot from https://www.cloudflare.com/ips-v4 and /ips-v6 on 2026-10-12.
// This bounded policy does not claim upstream's live-range refresh behavior.
fn cloudflare_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let address = u32::from(ip);
            [
                ([173, 245, 48, 0], 20),
                ([103, 21, 244, 0], 22),
                ([103, 22, 200, 0], 22),
                ([103, 31, 4, 0], 22),
                ([141, 101, 64, 0], 18),
                ([108, 162, 192, 0], 18),
                ([190, 93, 240, 0], 20),
                ([188, 114, 96, 0], 20),
                ([197, 234, 240, 0], 22),
                ([198, 41, 128, 0], 17),
                ([162, 158, 0, 0], 15),
                ([104, 16, 0, 0], 13),
                ([104, 24, 0, 0], 14),
                ([172, 64, 0, 0], 13),
                ([131, 0, 72, 0], 22),
            ]
            .iter()
            .any(|(network, prefix)| {
                address >> (32 - prefix) == u32::from(Ipv4Addr::from(*network)) >> (32 - prefix)
            })
        }
        IpAddr::V6(ip) => {
            let high = (u128::from(ip) >> 96) as u32;
            [
                0x2400cb00, 0x26064700, 0x2803f800, 0x2405b500, 0x24058100, 0x2c0ff248,
            ]
            .contains(&high)
                || high >> 3 == 0x2a0698c0 >> 3
        }
    }
}

fn public_address(ip: IpAddr, allow_documentation: bool) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            let documentation = (a == 192 && b == 0 && c == 2)
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113);
            if documentation {
                return allow_documentation;
            }
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19)))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            if segments[0] == 0x2001 && segments[1] == 0xdb8 {
                return allow_documentation;
            }
            segments[0] & 0xe000 == 0x2000
                && !(segments[0] == 0x2001 && segments[1] < 0x200)
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && segments[1] < 0x1000)
        }
    }
}

fn parse_ip(text: &str, ipv6: bool, allow_documentation: bool) -> Result<Option<String>, String> {
    let ip = text
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| "invalid IP address from IP provider".to_string())?;
    if ip.is_ipv6() != ipv6 {
        return Err("IP provider returned the wrong IP family".to_string());
    }
    if !public_address(ip, allow_documentation) || cloudflare_address(ip) {
        return Err(
            "IP provider address rejected by GUI v1 public/Cloudflare address policy".into(),
        );
    }
    Ok(Some(ip.to_string()))
}

async fn fetch_ip(
    url: &str,
    trace_format: bool,
    ipv6: bool,
    timeout: Duration,
) -> Result<Option<String>, String> {
    if url.is_empty() {
        return Err("empty URL provider".to_string());
    }
    let endpoint = reqwest::Url::parse(url).map_err(|_| "invalid provider URL")?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        return Err("provider requires a credential-free http(s) URL".into());
    }
    // Only loopback test endpoints may return RFC 5737/3849 documentation fixtures.
    let allow_documentation = endpoint
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    let client = reqwest::Client::builder()
        .timeout(timeout)
        // Bind to the requested family; a proxy could otherwise bypass this.
        .local_address(if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        })
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.without_url().to_string())?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("detection request failed: {}", e.without_url()))?
        .error_for_status()
        .map_err(|e| format!("detection request failed: {}", e.without_url()))?;
    if !response.status().is_success() {
        return Err(format!(
            "detection request failed: HTTP {}",
            response.status()
        ));
    }
    const MAX_PROVIDER_BYTES: usize = 16 * 1024;
    if response
        .content_length()
        .is_some_and(|n| n > MAX_PROVIDER_BYTES as u64)
    {
        return Err("IP provider response exceeds 16 KiB".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("detection read failed: {}", e.without_url()))?
    {
        if chunk.len() > MAX_PROVIDER_BYTES - body.len() {
            return Err("IP provider response exceeds 16 KiB".into());
        }
        body.extend_from_slice(&chunk);
    }
    let text = std::str::from_utf8(&body).map_err(|_| "IP provider response must be UTF-8")?;
    if trace_format {
        // cloudflare.trace: parse key=value lines, extract ip=
        for line in text.lines() {
            if let Some(ip) = line.strip_prefix("ip=") {
                return parse_ip(ip, ipv6, allow_documentation);
            }
        }
        Err("no ip= field in trace response".to_string())
    } else if text.trim().is_empty() {
        Err("empty response from IP provider".to_string())
    } else {
        parse_ip(text, ipv6, allow_documentation)
    }
}

fn wanted_types(cfg: &Config, domain: &str) -> Vec<(&'static str, &'static str)> {
    // (family, record type)
    let mut out = Vec::new();
    if cfg.ip4_provider != "none" && cfg.ip4_domains.iter().any(|d| d == domain) {
        out.push(("ipv4", "A"));
    }
    if cfg.ip6_provider != "none" && cfg.ip6_domains.iter().any(|d| d == domain) {
        out.push(("ipv6", "AAAA"));
    }
    out
}

fn manual_updates_enabled(cfg: &Config) -> bool {
    let contract_supported = cfg.ddns_contract == "standalone-v1"
        || cfg.ddns_contract == "shared-v1"
            && cfg.managed_record_comment.is_some()
            && cfg.managed_record_comment == cfg.record_comment;
    contract_supported
        && cfg
            .domains
            .iter()
            .any(|domain| !wanted_types(cfg, domain).is_empty())
}

fn owned_record<'a>(
    records: &'a [DnsRecord],
    cfg: &Config,
    rtype: &str,
) -> Result<Option<&'a DnsRecord>, String> {
    if records.len() > 1 {
        return Err(
            "duplicate records: manual updates disabled for this name/family; no records changed"
                .into(),
        );
    }
    if let Some(record) = records.first() {
        if record.record_type != rtype {
            return Err("unexpected record type; no records changed".into());
        }
        if cfg
            .managed_record_comment
            .as_ref()
            .is_some_and(|comment| record.comment.as_ref() != Some(comment))
        {
            return Err(
                "record is outside the configured comment ownership; no records changed".into(),
            );
        }
        Ok(Some(record))
    } else {
        Ok(None)
    }
}

/// Compute the sync status of every configured DDNS domain.
pub async fn status(cfg: &Config, cf: &CloudflareClient) -> DdnsStatus {
    let (ipv4, ipv6, ipv4_error, ipv6_error) = detect_both(cfg).await;

    let mut domains = Vec::new();
    for domain in &cfg.domains {
        for (family, rtype) in wanted_types(cfg, domain) {
            let detected = if family == "ipv4" { &ipv4 } else { &ipv6 };
            let detected_err = if family == "ipv4" {
                &ipv4_error
            } else {
                &ipv6_error
            };
            let mut entry = DomainStatus {
                domain: domain.clone(),
                record_type: rtype.to_string(),
                detected_ip: detected.clone(),
                dns_ips: Vec::new(),
                in_sync: false,
                error: detected_err.clone(),
            };
            if entry.error.is_none() {
                match cf.zone_for_domain(domain).await {
                    Ok(Some(zone)) => {
                        match cf.list_records_by_name(&zone.id, rtype, domain).await {
                            Ok(records) => {
                                entry.dns_ips = records.iter().map(|r| r.content.clone()).collect();
                                match owned_record(&records, cfg, rtype) {
                                    Ok(Some(record)) => {
                                        entry.in_sync = entry
                                            .detected_ip
                                            .as_ref()
                                            .is_some_and(|ip| record.content == *ip)
                                    }
                                    Ok(None) => {}
                                    Err(e) => entry.error = Some(e),
                                }
                            }
                            Err(e) => entry.error = Some(e.to_string()),
                        }
                    }
                    Ok(None) => entry.error = Some("no matching Cloudflare zone".to_string()),
                    Err(e) => entry.error = Some(e.to_string()),
                }
            }
            domains.push(entry);
        }
    }

    DdnsStatus {
        ipv4,
        ipv6,
        ipv4_error,
        ipv6_error,
        domains,
        configured: !cfg.domains.is_empty(),
        contract_version: cfg.ddns_contract.clone(),
        manual_updates_enabled: manual_updates_enabled(cfg),
        daemon_status: "not_observed",
    }
}

async fn detect_both(
    cfg: &Config,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let mut ipv4 = None;
    let mut ipv6 = None;
    let mut ipv4_error = None;
    let mut ipv6_error = None;

    if cfg.ip4_provider != "none" && !cfg.ip4_domains.is_empty() {
        match detect_ip(&cfg.ip4_provider, "ipv4", cfg.detection_timeout).await {
            Ok(ip) => ipv4 = ip,
            Err(e) => ipv4_error = Some(e),
        }
    }
    if cfg.ip6_provider != "none" && !cfg.ip6_domains.is_empty() {
        match detect_ip(&cfg.ip6_provider, "ipv6", cfg.detection_timeout).await {
            Ok(ip) => ipv6 = ip,
            Err(e) => ipv6_error = Some(e),
        }
    }
    (ipv4, ipv6, ipv4_error, ipv6_error)
}

/// Run one independent manual cycle. Failures preserve the affected records;
/// duplicate reconciliation and daemon coordination are deliberately unsupported.
pub async fn update_now(
    cfg: &Config,
    cf: &CloudflareClient,
    authorized: impl Fn() -> bool,
) -> DdnsUpdate {
    if !manual_updates_enabled(cfg) {
        return DdnsUpdate {
            success: false,
            outcomes: cfg.domains.iter().flat_map(|domain| wanted_types(cfg, domain).into_iter().map(|(_,rtype)| DdnsOutcome {
                domain: domain.clone(), record_type: rtype.into(), status: "failed",
                error: Some("manual updates disabled by the GUI DDNS contract".into()),
            })).collect(),
            log: vec!["Manual updates disabled: no active domain-family or unsupported ownership contract.".into()],
        };
    }
    let mut log = Vec::new();
    let mut outcomes = Vec::new();
    let (ipv4, ipv6, ipv4_error, ipv6_error) = detect_both(cfg).await;
    if let Some(e) = &ipv4_error {
        log.push(format!("⚠️ IPv4 detection failed, skipping A records: {e}"));
    }
    if let Some(e) = &ipv6_error {
        log.push(format!(
            "⚠️ IPv6 detection failed, skipping AAAA records: {e}"
        ));
    }

    for domain in &cfg.domains {
        let zone = match cf.zone_for_domain(domain).await {
            Ok(Some(z)) => z,
            Ok(None) => {
                for (_, rtype) in wanted_types(cfg, domain) {
                    outcomes.push(DdnsOutcome {
                        domain: domain.clone(),
                        record_type: rtype.into(),
                        status: "failed",
                        error: Some("no matching Cloudflare zone".into()),
                    });
                }
                log.push(format!("{domain}: no matching Cloudflare zone"));
                continue;
            }
            Err(e) => {
                for (_, rtype) in wanted_types(cfg, domain) {
                    outcomes.push(DdnsOutcome {
                        domain: domain.clone(),
                        record_type: rtype.into(),
                        status: "failed",
                        error: Some(format!("zone lookup failed: {e}")),
                    });
                }
                log.push(format!("{domain}: zone lookup failed: {e}"));
                continue;
            }
        };

        for (family, rtype) in wanted_types(cfg, domain) {
            let detected = if family == "ipv4" { &ipv4 } else { &ipv6 };
            let ip = match detected {
                Some(ip) => ip.clone(),
                None => {
                    let error = if family == "ipv4" {
                        &ipv4_error
                    } else {
                        &ipv6_error
                    };
                    outcomes.push(DdnsOutcome {
                        domain: domain.clone(),
                        record_type: rtype.into(),
                        status: if error.is_some() { "failed" } else { "skipped" },
                        error: error.clone(),
                    });
                    continue; // transient failure or disabled - preserve records
                }
            };
            let result = async {
                if !authorized() {
                    return Err("session expired or revoked; write not sent".into());
                }
                let records = cf
                    .list_records_by_name(&zone.id, rtype, domain)
                    .await
                    .map_err(|e| format!("lookup failed: {e}"))?;
                match owned_record(&records, cfg, rtype)? {
                    None => {
                        let payload = RecordPayload {
                            record_type: rtype.to_string(),
                            name: domain.clone(),
                            content: Some(ip.clone()),
                            proxied: Some(cfg.proxied),
                            ttl: if cfg.proxied { 1 } else { cfg.ttl },
                            comment: cfg.record_comment.clone(),
                            tags: None,
                            priority: None,
                            data: None,
                        };
                        if !authorized() {
                            return Err("session expired or revoked; write not sent".into());
                        }
                        cf.create_record(&zone.id, &payload)
                            .await
                            .map_err(|e| format!("create failed: {e}"))?;
                        Ok("created")
                    }
                    Some(rec) => {
                        let ttl = if cfg.proxied { 1 } else { cfg.ttl };
                        if rec.content == ip
                            && rec.ttl == Some(ttl)
                            && rec.proxied == Some(cfg.proxied)
                            && cfg
                                .record_comment
                                .as_ref()
                                .is_none_or(|comment| rec.comment.as_ref() == Some(comment))
                        {
                            Ok("unchanged")
                        } else {
                            let patch = RecordPatch {
                                content: Some(ip.clone()),
                                ttl: Some(ttl),
                                proxied: Some(cfg.proxied),
                                comment: cfg.record_comment.clone(),
                                ..Default::default()
                            };
                            if !authorized() {
                                return Err("session expired or revoked; write not sent".into());
                            }
                            cf.patch_record(&zone.id, &rec.id, &patch)
                                .await
                                .map_err(|e| format!("update failed: {e}"))?;
                            Ok("updated")
                        }
                    }
                }
            }
            .await;
            let (outcome, error) = match result {
                Ok(outcome) => {
                    log.push(format!("{domain} {rtype}: {outcome} ({ip})"));
                    (outcome, None)
                }
                Err(e) => {
                    log.push(format!("{domain} {rtype}: {e}"));
                    ("failed", Some(e))
                }
            };
            outcomes.push(DdnsOutcome {
                domain: domain.clone(),
                record_type: rtype.into(),
                status: outcome,
                error,
            });
        }
    }

    if log.is_empty() {
        log.push("ℹ️ Nothing to do.".to_string());
    }
    DdnsUpdate {
        success: !outcomes.iter().any(|outcome| outcome.status == "failed"),
        outcomes,
        log,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TIMEOUT: Duration = Duration::from_secs(2);

    struct MockHttp {
        url: String,
        requests: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl MockHttp {
        async fn new(ipv6: bool, status: u16, body: &str) -> Self {
            let body = body.to_string();
            Self::with_handler(ipv6, move |_| (status, body.clone())).await
        }

        async fn with_handler(
            ipv6: bool,
            handler: impl Fn(&str) -> (u16, String) + Send + 'static,
        ) -> Self {
            Self::with_response(ipv6, move |request| {
                let (status, body) = handler(request);
                format!("HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
            }).await
        }

        async fn with_response(
            ipv6: bool,
            handler: impl Fn(&str) -> String + Send + 'static,
        ) -> Self {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let listener = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
                .await
                .expect("bind loopback HTTP mock");
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            let task = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let request = tokio::time::timeout(TIMEOUT, async {
                        let mut request = Vec::new();
                        let mut buffer = [0; 1024];
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                            let count = stream.read(&mut buffer).await.unwrap();
                            assert!(count > 0, "incomplete mock HTTP request");
                            request.extend_from_slice(&buffer[..count]);
                            assert!(request.len() <= 16384, "oversized mock HTTP request");
                        }
                        let header_end =
                            request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                        let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                        let body_length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        assert!(body_length <= 16384);
                        while request.len() < header_end + body_length {
                            let count = stream.read(&mut buffer).await.unwrap();
                            assert!(count > 0);
                            request.extend_from_slice(&buffer[..count]);
                        }
                        String::from_utf8(request).unwrap()
                    })
                    .await
                    .unwrap();
                    let response = handler(&request);
                    recorded.lock().unwrap().push(request);
                    stream.write_all(response.as_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            Self {
                url,
                requests,
                task,
            }
        }
    }

    impl Drop for MockHttp {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn config() -> Config {
        Config {
            api_token: String::new(),
            listen: String::new(),
            data_dir: String::new(),
            session_ttl: TIMEOUT,
            update_timeout: TIMEOUT,
            detection_timeout: TIMEOUT,
            secure_cookies: false,
            public_origin: None,
            domains: vec!["example.com".into()],
            ip4_domains: vec!["example.com".into()],
            ip6_domains: Vec::new(),
            ddns_contract: "shared-v1".into(),
            managed_record_comment: Some("managed by GUI".into()),
            ip4_provider: "literal:192.0.2.1".into(),
            ip6_provider: "none".into(),
            ttl: 300,
            proxied: false,
            record_comment: Some("managed by GUI".into()),
            emoji: false,
            quiet: true,
            api_base: None,
        }
    }

    async fn record_api(records: serde_json::Value, fail_write: bool) -> MockHttp {
        MockHttp::with_handler(false, move |request| {
            if request.starts_with("GET /zones?") {
                (200, r#"{"success":true,"result":[{"id":"test-zone","name":"example.com"}]}"#.into())
            } else if request.starts_with("GET ") {
                (200, serde_json::json!({"success":true,"result":records}).to_string())
            } else if fail_write {
                (503, r#"{"success":false,"errors":[{"message":"synthetic write failure"}]}"#.into())
            } else {
                (200, r#"{"success":true,"result":{"id":"test-record","name":"example.com","type":"A","content":"192.0.2.1"}}"#.into())
            }
        }).await
    }

    #[tokio::test]
    async fn exact_comment_ownership_blocks_unowned_records_and_mixed_duplicates() {
        for records in [
            serde_json::json!([{"id":"one","name":"example.com","type":"A","content":"192.0.2.2"}]),
            serde_json::json!([{"id":"one","name":"example.com","type":"A","content":"192.0.2.2","comment":"owned by another tool"}]),
            serde_json::json!([{"id":"one","name":"example.com","type":"A","content":"192.0.2.2","comment":"managed by GUI"},
                {"id":"two","name":"example.com","type":"A","content":"192.0.2.3","comment":"owned by another tool"}]),
        ] {
            let api = record_api(records, false).await;
            let cf = CloudflareClient::new("dummy-test-token", TIMEOUT, Some(&api.url));
            let outcome = update_now(&config(), &cf, || true).await;
            assert!(!outcome.success);
            assert_eq!(outcome.outcomes.len(), 1);
            assert_eq!(outcome.outcomes[0].status, "failed");
            assert!(api
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.starts_with("GET ")));
            let status = status(&config(), &cf).await;
            assert!(!status.domains[0].in_sync);
            assert!(status.domains[0].error.is_some());
            assert_eq!(status.daemon_status, "not_observed");
        }
    }

    #[tokio::test]
    async fn structured_outcomes_cover_create_update_unchanged_and_write_failure() {
        for (records, expected, fail_write) in [
            (serde_json::json!([]), "created", false),
            (
                serde_json::json!([{"id":"one","name":"example.com","type":"A","content":"192.0.2.2","ttl":300,"proxied":false,"comment":"managed by GUI"}]),
                "updated",
                false,
            ),
            (
                serde_json::json!([{"id":"one","name":"example.com","type":"A","content":"192.0.2.1","ttl":300,"proxied":false,"comment":"managed by GUI"}]),
                "unchanged",
                false,
            ),
            (serde_json::json!([]), "failed", true),
            (
                serde_json::json!([{"id":"one","name":"example.com","type":"A","content":"192.0.2.2","comment":"managed by GUI"}]),
                "failed",
                true,
            ),
        ] {
            let api = record_api(records, fail_write).await;
            let cf = CloudflareClient::new("dummy-test-token", TIMEOUT, Some(&api.url));
            let result = update_now(&config(), &cf, || true).await;
            assert_eq!(result.success, !fail_write);
            assert_eq!(result.outcomes[0].status, expected);
            assert_eq!(result.outcomes[0].error.is_some(), fail_write);
            let wire = serde_json::to_value(&result).unwrap();
            assert_eq!(wire["success"], !fail_write);
            assert!(wire["log"].is_array());
            assert_eq!(wire["outcomes"][0]["record_type"], "A");
            if expected == "unchanged" {
                assert!(api
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|r| r.starts_with("GET ")));
            }
        }
    }

    #[tokio::test]
    async fn metadata_updates_respect_proxy_auto_ttl_and_preserve_tags() {
        let api = record_api(serde_json::json!([{"id":"one","name":"example.com","type":"A","content":"192.0.2.1","ttl":300,"proxied":false,"comment":"managed by GUI","tags":["synthetic:keep"]}]),false).await;
        let cf = CloudflareClient::new("dummy-test-token", TIMEOUT, Some(&api.url));
        let mut cfg = config();
        cfg.proxied = true;
        let result = update_now(&cfg, &cf, || true).await;
        assert!(result.success);
        assert_eq!(result.outcomes[0].status, "updated");
        let requests = api.requests.lock().unwrap();
        let patch = requests.iter().find(|r| r.starts_with("PATCH ")).unwrap();
        let body: serde_json::Value =
            serde_json::from_str(patch.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["ttl"], 1);
        assert_eq!(body["proxied"], true);
        assert_eq!(body["comment"], "managed by GUI");
        assert!(body.get("tags").is_none());
    }

    #[tokio::test]
    async fn family_specific_updates_report_partial_detection_failure() {
        let api = record_api(serde_json::json!([]), false).await;
        let cf = CloudflareClient::new("dummy-test-token", TIMEOUT, Some(&api.url));
        let mut cfg = config();
        cfg.domains.push("v6.example.com".into());
        cfg.ip6_domains.push("v6.example.com".into());
        cfg.ip6_provider = "literal:192.0.2.1".into();
        let result = update_now(&cfg, &cf, || true).await;
        assert!(!result.success);
        assert_eq!(result.outcomes.len(), 2);
        assert_eq!(result.outcomes[0].domain, "example.com");
        assert_eq!(result.outcomes[0].record_type, "A");
        assert_eq!(result.outcomes[0].status, "created");
        assert_eq!(result.outcomes[1].domain, "v6.example.com");
        assert_eq!(result.outcomes[1].record_type, "AAAA");
        assert_eq!(result.outcomes[1].status, "failed");
        assert_eq!(
            api.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.starts_with("POST "))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn invalid_shared_contract_is_disabled_before_any_requests() {
        let api = record_api(serde_json::json!([]), false).await;
        let cf = CloudflareClient::new("dummy-test-token", TIMEOUT, Some(&api.url));
        let mut cfg = config();
        cfg.managed_record_comment = None;
        let result = update_now(&cfg, &cf, || true).await;
        assert!(!result.success);
        assert!(!manual_updates_enabled(&cfg));
        assert!(api.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn address_policy_rejects_reserved_and_cloudflare_but_preserves_documentation_fixtures() {
        for text in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.1.1",
            "192.168.1.1",
            "192.0.0.1",
            "192.88.99.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:192.0.2.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001::1",
            "2001:2::1",
            "3fff::1",
        ] {
            let ip = text.parse::<IpAddr>().unwrap();
            assert!(!public_address(ip, false), "accepted {text}");
        }
        for text in ["192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"] {
            let ip = text.parse::<IpAddr>().unwrap();
            assert!(!public_address(ip, false));
            assert!(public_address(ip, true));
        }
        for text in [
            "173.245.48.1",
            "103.21.244.1",
            "103.22.200.1",
            "103.31.4.1",
            "141.101.64.1",
            "108.162.192.1",
            "190.93.240.1",
            "188.114.96.1",
            "197.234.240.1",
            "198.41.128.1",
            "162.158.0.1",
            "104.16.0.1",
            "104.24.0.1",
            "172.64.0.1",
            "131.0.72.1",
            "2400:cb00::1",
            "2606:4700::1",
            "2803:f800::1",
            "2405:b500::1",
            "2405:8100::1",
            "2a06:98c7::1",
            "2c0f:f248::1",
        ] {
            assert!(cloudflare_address(text.parse().unwrap()), "missed {text}");
        }
        assert!(!cloudflare_address("192.0.2.1".parse().unwrap()));
        assert!(!cloudflare_address("2001:db8::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn provider_response_size_and_literal_cloudflare_policy_fail_closed() {
        let body = format!("ip=192.0.2.1\n{}", "x".repeat(16 * 1024));
        let mock = MockHttp::new(false, 200, &body).await;
        let error = fetch_ip(&mock.url, true, false, TIMEOUT).await.unwrap_err();
        assert!(error.contains("16 KiB"));
        for (provider, family) in [
            ("literal:104.16.1.1", "ipv4"),
            ("literal:2606:4700::1", "ipv6"),
            ("literal:0.0.0.0", "ipv4"),
            ("literal:ff02::1", "ipv6"),
        ] {
            assert!(detect_ip(provider, family, TIMEOUT).await.is_err());
        }
    }

    #[tokio::test]
    async fn invalid_family_is_rejected_for_every_provider() {
        for provider in [
            "none",
            "ipify",
            "cloudflare.trace",
            "url:",
            "literal:127.0.0.1",
        ] {
            for family in ["", "IPv4", "ipv5"] {
                let error = detect_ip(provider, family, TIMEOUT).await.unwrap_err();
                assert!(error.contains("invalid IP family"));
            }
        }
    }

    #[tokio::test]
    async fn literal_lists_select_family_and_canonicalize() {
        let provider = "literal: 2001:0DB8:0000:0000:0000:0000:0000:0001 , 192.0.2.1, 127.0.0.1";
        assert_eq!(
            detect_ip(provider, "ipv4", TIMEOUT).await.unwrap(),
            Some("192.0.2.1".to_string())
        );
        assert_eq!(
            detect_ip(provider, "ipv6", TIMEOUT).await.unwrap(),
            Some("2001:db8::1".to_string())
        );
        for (provider, family, expected) in [
            ("literal:10.0.0.1", "ipv4", "10.0.0.1"),
            ("literal:127.0.0.1", "ipv4", "127.0.0.1"),
            ("literal:fd00:0:0:0:0:0:0:1", "ipv6", "fd00::1"),
            ("literal:::1", "ipv6", "::1"),
        ] {
            assert_eq!(
                detect_ip(provider, family, TIMEOUT).await.unwrap(),
                Some(expected.to_string())
            );
        }
    }

    #[tokio::test]
    async fn literal_lists_reject_malformed_entries_and_missing_family() {
        for provider in [
            "literal:",
            "literal: ",
            "literal:,192.0.2.1",
            "literal:192.0.2.1,",
            "literal:192.0.2.1,,::1",
            "literal:192.0.2.1,not-an-ip",
            "literal:not-an-ip,::1",
            "literal:999.0.0.1",
            "literal:192.0.2.1:80",
            "literal:[::1]",
        ] {
            for family in ["ipv4", "ipv6"] {
                let error = detect_ip(provider, family, TIMEOUT).await.unwrap_err();
                assert!(error.contains("invalid IP address"), "{provider}: {error}");
            }
        }
        for (provider, family) in [("literal:::1", "ipv4"), ("literal:192.0.2.1", "ipv6")] {
            let error = detect_ip(provider, family, TIMEOUT).await.unwrap_err();
            assert!(error.contains("no matching IP family"));
        }
    }

    #[tokio::test]
    async fn disabled_provider_returns_no_address() {
        for family in ["ipv4", "ipv6"] {
            assert_eq!(detect_ip("none", family, TIMEOUT).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn fetched_private_and_cloudflare_addresses_are_rejected() {
        for body in [
            "10.0.0.1",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "104.16.1.1",
        ] {
            let mock = MockHttp::new(false, 200, body).await;
            assert!(
                detect_ip(&format!("url:{}", mock.url), "ipv4", TIMEOUT)
                    .await
                    .is_err(),
                "accepted {body}"
            );
        }
        for body in ["::1", "fd00::1", "fe80::1", "2606:4700::1"] {
            let mock = MockHttp::new(true, 200, body).await;
            assert!(
                detect_ip(&format!("url:{}", mock.url), "ipv6", TIMEOUT)
                    .await
                    .is_err(),
                "accepted {body}"
            );
        }
    }

    #[tokio::test]
    async fn url_responses_must_be_valid_matching_addresses() {
        for (body, expected) in [
            (" 192.0.2.1\n", Some("192.0.2.1")),
            ("", None),
            (" \n", None),
            ("not-an-ip", None),
            ("<html>192.0.2.1</html>", None),
            ("192.0.2.1\n192.0.2.2", None),
            ("2001:db8::1", None),
        ] {
            let mock = MockHttp::new(false, 200, body).await;
            let result = detect_ip(&format!("url:{}", mock.url), "ipv4", TIMEOUT).await;
            if let Some(ip) = expected {
                assert_eq!(result.unwrap(), Some(ip.to_string()));
            } else {
                assert!(result.is_err(), "accepted invalid response: {body:?}");
            }
            assert_eq!(mock.requests.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn ipv6_fetches_canonicalize_and_reject_wrong_family() {
        for (body, expected) in [
            (
                "2001:0DB8:0000:0000:0000:0000:0000:0001\n",
                Some("2001:db8::1"),
            ),
            ("192.0.2.1", None),
            ("malformed", None),
        ] {
            let mock = MockHttp::new(true, 200, body).await;
            let result = detect_ip(&format!("url:{}", mock.url), "ipv6", TIMEOUT).await;
            if let Some(ip) = expected {
                assert_eq!(result.unwrap(), Some(ip.to_string()));
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn trace_responses_validate_only_the_ip_field() {
        // Exercise the same fetch path as cloudflare.trace without contacting it.
        for (ipv6, body, expected) in [
            (
                false,
                "fl=123\nip= 192.0.2.1 \ncolo=TEST\n",
                Some("192.0.2.1"),
            ),
            (
                true,
                "ip=2001:0DB8:0:0:0:0:0:1\nloc=TEST\n",
                Some("2001:db8::1"),
            ),
            (false, "fl=123\ncolo=TEST\n", None),
            (false, "ip=\n", None),
            (false, "ip=invalid\n", None),
            (false, "ip=2001:db8::1\n", None),
            (true, "ip=192.0.2.1\n", None),
            (false, "other_ip=192.0.2.1\n", None),
        ] {
            let mock = MockHttp::new(ipv6, 200, body).await;
            let result = fetch_ip(&mock.url, true, ipv6, TIMEOUT).await;
            if let Some(ip) = expected {
                assert_eq!(result.unwrap(), Some(ip.to_string()));
            } else {
                assert!(result.is_err(), "accepted invalid trace: {body:?}");
            }
        }
    }

    #[tokio::test]
    async fn non_success_status_rejects_valid_ip_and_scrubs_url() {
        for status in [302, 400, 404, 429, 500, 503] {
            for trace in [false, true] {
                let body = if trace { "ip=192.0.2.1\n" } else { "192.0.2.1" };
                let mock = MockHttp::new(false, status, body).await;
                let url = format!("{}/private-provider?key=dummy-sensitive-marker", mock.url);
                let error = fetch_ip(&url, trace, false, TIMEOUT).await.unwrap_err();
                assert!(error.contains(&status.to_string()), "{error}");
                assert!(!error.contains(&mock.url));
                assert!(!error.contains("private-provider"));
                assert!(!error.contains("dummy-sensitive-marker"));
            }
        }
    }

    #[tokio::test]
    async fn requests_cannot_fall_back_to_the_other_family() {
        for ipv6 in [false, true] {
            let mock = MockHttp::new(!ipv6, 200, if ipv6 { "::1" } else { "127.0.0.1" }).await;
            for trace in [false, true] {
                let url = format!("{}/private-provider?key=dummy-sensitive-marker", mock.url);
                let error = fetch_ip(&url, trace, ipv6, TIMEOUT).await.unwrap_err();
                assert!(error.contains("detection request failed"));
                assert!(!error.contains(&mock.url));
                assert!(!error.contains("dummy-sensitive-marker"));
            }
            assert!(mock.requests.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn detection_failure_never_reads_or_writes_dns_records() {
        let api = MockHttp::new(
            false,
            200,
            r#"{"success":true,"result":[{"id":"test-zone","name":"example.com"}]}"#,
        )
        .await;
        let cf = CloudflareClient::new("dummy-test-token", TIMEOUT, Some(&api.url));
        let detection = MockHttp::new(false, 503, "192.0.2.1").await;
        let cfg = Config {
            api_token: String::new(),
            listen: String::new(),
            data_dir: String::new(),
            session_ttl: TIMEOUT,
            update_timeout: TIMEOUT,
            detection_timeout: TIMEOUT,
            secure_cookies: false,
            public_origin: None,
            domains: vec!["example.com".to_string()],
            ip4_domains: vec!["example.com".to_string()],
            ip6_domains: vec!["example.com".to_string()],
            ddns_contract: "standalone-v1".into(),
            managed_record_comment: None,
            ip4_provider: format!("url:{}", detection.url),
            ip6_provider: "literal:192.0.2.1".to_string(),
            ttl: 1,
            proxied: false,
            record_comment: None,
            emoji: false,
            quiet: true,
            api_base: None,
        };
        let result = update_now(&cfg, &cf, || true).await;
        assert!(!result.success);
        assert_eq!(result.outcomes.len(), 2);
        let log = result.log;
        assert_eq!(log.len(), 2, "{log:?}");
        assert!(log[0].contains("IPv4 detection failed"));
        assert!(log[1].contains("IPv6 detection failed"));
        let requests = api.requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(requests[0].starts_with("GET /zones?name=example.com "));
        assert!(!requests[0].contains("dns_records"));
    }

    #[tokio::test]
    async fn duplicate_records_never_cause_mutations() {
        let api = MockHttp::new(false, 200,
            r#"{"success":true,"result":[{"id":"one","name":"example.com","type":"A","content":"192.0.2.2"},{"id":"two","name":"example.com","type":"A","content":"192.0.2.3"}]}"#).await;
        let cf = CloudflareClient::new("dummy-test-token", TIMEOUT, Some(&api.url));
        let cfg = Config {
            api_token: String::new(),
            listen: String::new(),
            data_dir: String::new(),
            session_ttl: TIMEOUT,
            update_timeout: TIMEOUT,
            detection_timeout: TIMEOUT,
            secure_cookies: false,
            domains: vec!["example.com".into()],
            public_origin: None,
            ip4_domains: vec!["example.com".into()],
            ip6_domains: Vec::new(),
            ddns_contract: "standalone-v1".into(),
            managed_record_comment: None,
            ip4_provider: "literal:192.0.2.1".into(),
            ip6_provider: "none".into(),
            ttl: 1,
            proxied: false,
            record_comment: None,
            emoji: false,
            quiet: true,
            api_base: None,
        };
        update_now(&cfg, &cf, || true).await;
        assert!(api
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.starts_with("GET ")));
    }

    #[tokio::test]
    async fn revoked_session_stops_unsent_ddns_writes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let authorized = Arc::new(AtomicBool::new(true));
        let revoke = authorized.clone();
        let api = MockHttp::with_handler(false, move |request| {
            if request.starts_with("GET /zones?") {
                (200, r#"{"success":true,"result":[{"id":"test-zone","name":"example.com"}]}"#.into())
            } else if request.starts_with("GET ") {
                (200, r#"{"success":true,"result":[]}"#.into())
            } else {
                revoke.store(false, Ordering::SeqCst);
                (200, r#"{"success":true,"result":{"id":"test-record","name":"example.com","type":"A","content":"192.0.2.1"}}"#.into())
            }
        }).await;
        let cf = CloudflareClient::new("synthetic-token", TIMEOUT, Some(&api.url));
        let mut cfg = config();
        cfg.ip6_domains = cfg.domains.clone();
        cfg.ip6_provider = "literal:2001:db8::1".into();
        let result = update_now(&cfg, &cf, || authorized.load(Ordering::SeqCst)).await;
        assert!(!result.success);
        assert_eq!(result.outcomes[0].status, "created");
        assert_eq!(result.outcomes[1].status, "failed");
        assert!(result.outcomes[1]
            .error
            .as_ref()
            .unwrap()
            .contains("session"));
        assert_eq!(
            api.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.starts_with("POST "))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn redirects_never_contact_the_destination() {
        let destination = MockHttp::new(false, 200, "192.0.2.1").await;
        let location = destination.url.clone();
        let redirect = MockHttp::with_response(false,move |_| format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")).await;
        let error = fetch_ip(&redirect.url, false, false, TIMEOUT)
            .await
            .unwrap_err();
        assert!(error.contains("302"));
        assert_eq!(redirect.requests.lock().unwrap().len(), 1);
        assert!(destination.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn chunked_provider_body_cannot_bypass_the_size_bound() {
        let body = format!("ip=192.0.2.1\n{}", "x".repeat(16 * 1024));
        let response = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",body.len());
        let mock = MockHttp::with_response(false, move |_| response.clone()).await;
        let error = fetch_ip(&mock.url, true, false, TIMEOUT).await.unwrap_err();
        assert!(error.contains("16 KiB"));
    }
}
