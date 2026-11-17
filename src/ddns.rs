//! Independent manual DDNS updates under the bounded GUI v1 contract.
//! This module neither observes nor controls a companion daemon.

use crate::cloudflare::{
    read_limited, BodyError, CloudflareClient, DnsRecord, RecordPatch, RecordPayload, Zone,
};
use crate::config::Config;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

const MAX_PROVIDER_BYTES: usize = 16 * 1024;
const SESSION_REVOKED: &str = "session expired or revoked; write not sent";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    const ALL: [Family; 2] = [Family::V4, Family::V6];

    fn record_type(self) -> &'static str {
        match self {
            Family::V4 => "A",
            Family::V6 => "AAAA",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        }
    }

    fn matches(self, ip: IpAddr) -> bool {
        match self {
            Family::V4 => ip.is_ipv4(),
            Family::V6 => ip.is_ipv6(),
        }
    }

    /// The provider and domain list configured for this family.
    fn settings(self, cfg: &Config) -> (&str, &[String]) {
        match self {
            Family::V4 => (&cfg.ip4_provider, &cfg.ip4_domains),
            Family::V6 => (&cfg.ip6_provider, &cfg.ip6_domains),
        }
    }
}

/// Detection result for one family. `Ok(None)` means detection is off.
type Detected = Result<Option<IpAddr>, String>;

struct Detection {
    ipv4: Detected,
    ipv6: Detected,
}

impl Detection {
    fn get(&self, family: Family) -> &Detected {
        match family {
            Family::V4 => &self.ipv4,
            Family::V6 => &self.ipv6,
        }
    }
}

/// HTTP clients for IP detection, one bound to each address family. They
/// are built once at startup and shared by every status and update call.
pub struct Detector {
    ipv4: reqwest::Client,
    ipv6: reqwest::Client,
}

fn detection_client(local: IpAddr, timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(timeout)
        // Bind to the requested family; a proxy could otherwise bypass this.
        .local_address(local)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        // A reused connection could still report the address from before a
        // WAN or IPv6 prefix change.
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|e| {
            format!(
                "cannot create the IP detection HTTP client: {}",
                e.without_url()
            )
        })
}

impl Detector {
    pub fn new(timeout: Duration) -> Result<Self, String> {
        Ok(Detector {
            ipv4: detection_client(IpAddr::V4(Ipv4Addr::UNSPECIFIED), timeout)?,
            ipv6: detection_client(IpAddr::V6(Ipv6Addr::UNSPECIFIED), timeout)?,
        })
    }

    /// Detect the public IP using a cloudflare-ddns style provider string.
    async fn detect(&self, provider: &str, family: Family) -> Detected {
        // Prefixed providers: url:<endpoint>, literal:<ips>
        if let Some(url) = provider.strip_prefix("url:") {
            return self.fetch(url, false, family).await.map(Some);
        }
        if let Some(url) = provider.strip_prefix("cloudflare.trace:") {
            return self.fetch(url, true, family).await.map(Some);
        }
        if let Some(ips) = provider.strip_prefix("literal:") {
            return literal_ip(ips, family).map(Some);
        }

        match provider {
            "none" => Ok(None),
            "ipify" => {
                let url = match family {
                    Family::V4 => "https://api.ipify.org",
                    Family::V6 => "https://api6.ipify.org",
                };
                self.fetch(url, false, family).await.map(Some)
            }
            "cloudflare.trace" => self
                .fetch("https://www.cloudflare.com/cdn-cgi/trace", true, family)
                .await
                .map(Some),
            _ => Err("provider is unsupported by the GUI v1 contract".into()),
        }
    }

    async fn fetch(&self, url: &str, trace_format: bool, family: Family) -> Result<IpAddr, String> {
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
        // Only loopback test endpoints may return RFC 5737/3849/9637 documentation fixtures.
        let allow_documentation = endpoint
            .host_str()
            .and_then(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        let client = match family {
            Family::V4 => &self.ipv4,
            Family::V6 => &self.ipv6,
        };
        let response = client
            .get(endpoint)
            .send()
            .await
            .map_err(|e| format!("detection request failed: {}", e.without_url()))?;
        // Redirects are not followed, so this also rejects 3xx responses.
        if !response.status().is_success() {
            return Err(format!(
                "detection request failed: HTTP {}",
                response.status()
            ));
        }
        let body =
            read_limited(response, MAX_PROVIDER_BYTES)
                .await
                .map_err(|error| match error {
                    BodyError::TooLarge => "IP provider response exceeds 16 KiB".to_string(),
                    BodyError::Read(e) => format!("detection read failed: {}", e.without_url()),
                })?;
        let text = std::str::from_utf8(&body).map_err(|_| "IP provider response must be UTF-8")?;
        if trace_format {
            // cloudflare.trace: parse key=value lines, extract ip=
            for line in text.lines() {
                if let Some(ip) = line.strip_prefix("ip=") {
                    return parse_ip(ip, family, allow_documentation);
                }
            }
            Err("no ip= field in trace response".to_string())
        } else if text.trim().is_empty() {
            Err("empty response from IP provider".to_string())
        } else {
            parse_ip(text, family, allow_documentation)
        }
    }
}

/// Pick the first address of `family` from a `literal:` list.
fn literal_ip(list: &str, family: Family) -> Result<IpAddr, String> {
    let mut selected = None;
    for entry in list.split(',') {
        // ::ffff:a.b.c.d is an IPv4 address, so check it as one.
        let ip = entry
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "invalid IP address in literal provider".to_string())?
            .to_canonical();
        // literal: is an explicit opt-in to private/test addresses, not Cloudflare anycast.
        if ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
            || cloudflare_address(ip)
        {
            return Err("literal provider address rejected by GUI v1 address policy".into());
        }
        if family.matches(ip) && selected.is_none() {
            selected = Some(ip);
        }
    }
    selected.ok_or_else(|| "no matching IP family in literal provider".to_string())
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
            let [first, second, ..] = ip.segments();
            // 2001:db8::/32 (RFC 3849) and 3fff::/20 (RFC 9637).
            let documentation =
                (first == 0x2001 && second == 0xdb8) || (first == 0x3fff && second < 0x1000);
            if documentation {
                return allow_documentation;
            }
            first & 0xe000 == 0x2000 && !(first == 0x2001 && second < 0x200) && first != 0x2002
        }
    }
}

fn parse_ip(text: &str, family: Family, allow_documentation: bool) -> Result<IpAddr, String> {
    let ip = text
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| "invalid IP address from IP provider".to_string())?;
    if !family.matches(ip) {
        return Err("IP provider returned the wrong IP family".to_string());
    }
    if !public_address(ip, allow_documentation) || cloudflare_address(ip) {
        return Err(
            "IP provider address rejected by GUI v1 public/Cloudflare address policy".into(),
        );
    }
    Ok(ip)
}

async fn detect_family(cfg: &Config, detector: &Detector, family: Family) -> Detected {
    let (provider, domains) = family.settings(cfg);
    if provider == "none" || domains.is_empty() {
        return Ok(None);
    }
    detector.detect(provider, family).await
}

async fn detect_all(cfg: &Config, detector: &Detector) -> Detection {
    let (ipv4, ipv6) = tokio::join!(
        detect_family(cfg, detector, Family::V4),
        detect_family(cfg, detector, Family::V6)
    );
    Detection { ipv4, ipv6 }
}

fn wanted_families(cfg: &Config, domain: &str) -> Vec<Family> {
    Family::ALL
        .into_iter()
        .filter(|family| {
            let (provider, domains) = family.settings(cfg);
            provider != "none" && domains.iter().any(|d| d == domain)
        })
        .collect()
}

fn manual_updates_enabled(cfg: &Config) -> bool {
    let contract_supported = cfg.ddns_contract == "standalone-v1"
        || (cfg.ddns_contract == "shared-v1"
            && cfg.managed_record_comment.is_some()
            && cfg.managed_record_comment == cfg.record_comment);
    contract_supported
        && cfg
            .domains
            .iter()
            .any(|domain| !wanted_families(cfg, domain).is_empty())
}

/// The single record the GUI may change. `records` already has the right
/// type and name, because `list_records_by_name` filters them.
fn owned_record<'a>(
    records: &'a [DnsRecord],
    cfg: &Config,
) -> Result<Option<&'a DnsRecord>, String> {
    match records {
        [] => Ok(None),
        [record]
            if cfg
                .managed_record_comment
                .as_ref()
                .is_some_and(|comment| record.comment.as_ref() != Some(comment)) =>
        {
            Err("record is outside the configured comment ownership; no records changed".into())
        }
        [record] => Ok(Some(record)),
        _ => Err(
            "duplicate records: manual updates disabled for this name/family; no records changed"
                .into(),
        ),
    }
}

/// Whether `record` already holds what Update now would write. The dashboard
/// and Update now both use this, so they agree on what "in sync" means.
fn record_matches(record: &DnsRecord, ip: IpAddr, cfg: &Config) -> bool {
    // Compare addresses, so 2001:db8:0::1 and 2001:db8::1 count as equal.
    record
        .content
        .parse::<IpAddr>()
        .is_ok_and(|content| content == ip)
        && record.ttl == Some(cfg.ttl)
        && record.proxied == Some(cfg.proxied)
        && cfg
            .record_comment
            .as_ref()
            .is_none_or(|comment| record.comment.as_ref() == Some(comment))
}

async fn find_zone(cf: &CloudflareClient, domain: &str) -> Result<Zone, String> {
    match cf.zone_for_domain(domain).await {
        Ok(Some(zone)) => Ok(zone),
        Ok(None) => Err("no matching Cloudflare zone".to_string()),
        Err(e) => Err(format!("zone lookup failed: {e}")),
    }
}

/// Compute the sync status of every configured DDNS domain.
pub async fn status(cfg: &Config, cf: &CloudflareClient, detector: &Detector) -> DdnsStatus {
    let detection = detect_all(cfg, detector).await;

    let mut domains = Vec::new();
    for domain in &cfg.domains {
        // Each domain's zone is looked up at most once per call.
        let mut zone_lookup = None;
        for family in wanted_families(cfg, domain) {
            let detected = detection.get(family);
            let mut entry = DomainStatus {
                domain: domain.clone(),
                record_type: family.record_type().to_string(),
                detected_ip: address_text(detected),
                dns_ips: Vec::new(),
                in_sync: false,
                error: detected.as_ref().err().cloned(),
            };
            if let Ok(Some(ip)) = detected {
                let zone = match &zone_lookup {
                    Some(found) => found,
                    None => zone_lookup.insert(find_zone(cf, domain).await),
                };
                let records = match zone {
                    Ok(zone) => cf
                        .list_records_by_name(&zone.id, family.record_type(), domain)
                        .await
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(e.clone()),
                };
                match records {
                    Ok(records) => {
                        entry.dns_ips = records.iter().map(|r| r.content.clone()).collect();
                        match owned_record(&records, cfg) {
                            Ok(record) => {
                                entry.in_sync =
                                    record.is_some_and(|record| record_matches(record, *ip, cfg))
                            }
                            Err(e) => entry.error = Some(e),
                        }
                    }
                    Err(e) => entry.error = Some(e),
                }
            }
            domains.push(entry);
        }
    }

    DdnsStatus {
        ipv4: address_text(&detection.ipv4),
        ipv6: address_text(&detection.ipv6),
        ipv4_error: detection.ipv4.err(),
        ipv6_error: detection.ipv6.err(),
        domains,
        configured: !cfg.domains.is_empty(),
        contract_version: cfg.ddns_contract.clone(),
        manual_updates_enabled: manual_updates_enabled(cfg),
        daemon_status: "not_observed",
    }
}

fn address_text(detected: &Detected) -> Option<String> {
    detected
        .as_ref()
        .ok()
        .copied()
        .flatten()
        .map(|ip| ip.to_string())
}

/// Run one independent manual cycle. Failures preserve the affected records;
/// duplicate reconciliation and daemon coordination are deliberately unsupported.
pub async fn update_now(
    cfg: &Config,
    cf: &CloudflareClient,
    detector: &Detector,
    authorized: impl Fn() -> bool,
) -> DdnsUpdate {
    if !manual_updates_enabled(cfg) {
        let outcomes = cfg
            .domains
            .iter()
            .flat_map(|domain| {
                wanted_families(cfg, domain)
                    .into_iter()
                    .map(move |family| DdnsOutcome {
                        domain: domain.clone(),
                        record_type: family.record_type().into(),
                        status: "failed",
                        error: Some("manual updates disabled by the GUI DDNS contract".into()),
                    })
            })
            .collect();
        return DdnsUpdate {
            success: false,
            outcomes,
            log: vec![
                "Manual updates disabled: no active domain-family or unsupported ownership contract."
                    .into(),
            ],
        };
    }
    let mut log = Vec::new();
    let mut outcomes = Vec::new();
    let detection = detect_all(cfg, detector).await;
    for family in Family::ALL {
        if let Err(e) = detection.get(family) {
            log.push(format!(
                "⚠️ {} detection failed, skipping {} records: {e}",
                family.label(),
                family.record_type()
            ));
        }
    }

    for domain in &cfg.domains {
        // Look the zone up only when a family has an address to write, and
        // at most once per domain, so a zone error cannot replace a
        // detection error.
        let mut zone_lookup = None;
        for family in wanted_families(cfg, domain) {
            let rtype = family.record_type();
            let (status, error) = match detection.get(family) {
                // transient failure or disabled - preserve records
                Err(e) => ("failed", Some(e.clone())),
                Ok(None) => ("skipped", None),
                Ok(Some(ip)) => {
                    let zone = match &zone_lookup {
                        Some(found) => found,
                        None => zone_lookup.insert(find_zone(cf, domain).await),
                    };
                    let result = match zone {
                        Ok(zone) => {
                            write_record(cfg, cf, &zone.id, domain, family, *ip, &authorized).await
                        }
                        Err(e) => Err(e.clone()),
                    };
                    match result {
                        Ok(outcome) => {
                            log.push(format!("{domain} {rtype}: {outcome} ({ip})"));
                            (outcome, None)
                        }
                        Err(e) => {
                            log.push(format!("{domain} {rtype}: {e}"));
                            ("failed", Some(e))
                        }
                    }
                }
            };
            outcomes.push(DdnsOutcome {
                domain: domain.clone(),
                record_type: rtype.into(),
                status,
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

/// Create or update the record for one domain and family. The session is
/// checked again before each write.
async fn write_record(
    cfg: &Config,
    cf: &CloudflareClient,
    zone_id: &str,
    domain: &str,
    family: Family,
    ip: IpAddr,
    authorized: &impl Fn() -> bool,
) -> Result<&'static str, String> {
    if !authorized() {
        return Err(SESSION_REVOKED.into());
    }
    let records = cf
        .list_records_by_name(zone_id, family.record_type(), domain)
        .await
        .map_err(|e| format!("lookup failed: {e}"))?;
    // config.rs already sets the TTL to 1 (Auto) when PROXIED is on.
    let Some(record) = owned_record(&records, cfg)? else {
        let payload = RecordPayload {
            record_type: family.record_type().to_string(),
            name: domain.to_string(),
            content: Some(ip.to_string()),
            proxied: Some(cfg.proxied),
            ttl: cfg.ttl,
            comment: cfg.record_comment.clone(),
            tags: None,
            priority: None,
            data: None,
        };
        if !authorized() {
            return Err(SESSION_REVOKED.into());
        }
        cf.create_record(zone_id, &payload)
            .await
            .map_err(|e| format!("create failed: {e}"))?;
        return Ok("created");
    };
    if record_matches(record, ip, cfg) {
        return Ok("unchanged");
    }
    let patch = RecordPatch {
        content: Some(ip.to_string()),
        ttl: Some(cfg.ttl),
        proxied: Some(cfg.proxied),
        comment: cfg.record_comment.clone(),
        ..Default::default()
    };
    if !authorized() {
        return Err(SESSION_REVOKED.into());
    }
    cf.patch_record(zone_id, &record.id, &patch)
        .await
        .map_err(|e| format!("update failed: {e}"))?;
    Ok("updated")
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
                format!(
                    "HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            })
            .await
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

        fn all_reads(&self) -> bool {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.starts_with("GET "))
        }

        fn zone_lookups(&self) -> usize {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.starts_with("GET /zones?"))
                .count()
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
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
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

    fn detector() -> Detector {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Detector::new(TIMEOUT).unwrap()
    }

    fn cloudflare(url: &str) -> CloudflareClient {
        let _ = rustls::crypto::ring::default_provider().install_default();
        CloudflareClient::new("dummy-test-token", TIMEOUT, Some(url)).unwrap()
    }

    async fn detect_text(provider: &str, family: Family) -> Result<Option<String>, String> {
        let ip = detector().detect(provider, family).await?;
        Ok(ip.map(|ip| ip.to_string()))
    }

    async fn fetch_text(url: &str, trace: bool, family: Family) -> Result<String, String> {
        let ip = detector().fetch(url, trace, family).await?;
        Ok(ip.to_string())
    }

    /// A one-page record listing, with the result_info Cloudflare sends.
    fn listing(records: &serde_json::Value) -> String {
        let count = records.as_array().map_or(0, Vec::len);
        serde_json::json!({
            "success": true,
            "result": records,
            "result_info": {"page": 1, "per_page": 100, "total_pages": 1, "total_count": count},
        })
        .to_string()
    }

    async fn record_api(records: serde_json::Value, fail_write: bool) -> MockHttp {
        MockHttp::with_handler(false, move |request| {
            if request.starts_with("GET /zones?") {
                (200, r#"{"success":true,"result":[{"id":"test-zone","name":"example.com"}]}"#.into())
            } else if request.starts_with("GET ") {
                (200, listing(&records))
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
            let cf = cloudflare(&api.url);
            let outcome = update_now(&config(), &cf, &detector(), || true).await;
            assert!(!outcome.success);
            assert_eq!(outcome.outcomes.len(), 1);
            assert_eq!(outcome.outcomes[0].status, "failed");
            assert!(api.all_reads());
            let status = status(&config(), &cf, &detector()).await;
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
            let cf = cloudflare(&api.url);
            let result = update_now(&config(), &cf, &detector(), || true).await;
            assert_eq!(result.success, !fail_write);
            assert_eq!(result.outcomes[0].status, expected);
            assert_eq!(result.outcomes[0].error.is_some(), fail_write);
            let wire = serde_json::to_value(&result).unwrap();
            assert_eq!(wire["success"], !fail_write);
            assert!(wire["log"].is_array());
            assert_eq!(wire["outcomes"][0]["record_type"], "A");
            if expected == "unchanged" {
                assert!(api.all_reads());
            }
        }
    }

    #[tokio::test]
    async fn metadata_updates_respect_proxy_auto_ttl_and_preserve_tags() {
        let api = record_api(serde_json::json!([{"id":"one","name":"example.com","type":"A","content":"192.0.2.1","ttl":300,"proxied":false,"comment":"managed by GUI","tags":["synthetic:keep"]}]),false).await;
        let cf = cloudflare(&api.url);
        let mut cfg = config();
        cfg.proxied = true;
        // load_config always pairs PROXIED=true with TTL 1 (Auto).
        cfg.ttl = 1;
        let result = update_now(&cfg, &cf, &detector(), || true).await;
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
        let cf = cloudflare(&api.url);
        let mut cfg = config();
        cfg.domains.push("v6.example.com".into());
        cfg.ip6_domains.push("v6.example.com".into());
        cfg.ip6_provider = "literal:192.0.2.1".into();
        let result = update_now(&cfg, &cf, &detector(), || true).await;
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
        // v6.example.com has no address to write, so its zone is never looked up.
        assert_eq!(api.zone_lookups(), 1);
    }

    #[tokio::test]
    async fn invalid_shared_contract_is_disabled_before_any_requests() {
        let api = record_api(serde_json::json!([]), false).await;
        let cf = cloudflare(&api.url);
        let mut cfg = config();
        cfg.managed_record_comment = None;
        let result = update_now(&cfg, &cf, &detector(), || true).await;
        assert!(!result.success);
        assert!(!manual_updates_enabled(&cfg));
        assert!(api.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn zone_is_looked_up_once_per_domain() {
        let api = record_api(serde_json::json!([]), false).await;
        let cf = cloudflare(&api.url);
        let mut cfg = config();
        cfg.ip6_domains = cfg.domains.clone();
        cfg.ip6_provider = "literal:2001:db8::1".into();
        let report = status(&cfg, &cf, &detector()).await;
        assert_eq!(report.domains.len(), 2);
        assert_eq!(api.zone_lookups(), 1);
        let result = update_now(&cfg, &cf, &detector(), || true).await;
        assert!(result.success, "{:?}", result.log);
        assert_eq!(result.outcomes.len(), 2);
        assert_eq!(api.zone_lookups(), 2);
    }

    #[tokio::test]
    async fn equivalent_ipv6_spellings_are_in_sync_and_unchanged() {
        let api = record_api(serde_json::json!([{"id":"one","name":"example.com","type":"AAAA","content":"2001:db8:0::1","ttl":300,"proxied":false,"comment":"managed by GUI"}]), false).await;
        let cf = cloudflare(&api.url);
        let mut cfg = config();
        cfg.ip4_provider = "none".into();
        cfg.ip4_domains.clear();
        cfg.ip6_domains = cfg.domains.clone();
        cfg.ip6_provider = "literal:2001:db8::1".into();
        let report = status(&cfg, &cf, &detector()).await;
        assert!(report.domains[0].in_sync, "{:?}", report.domains[0]);
        let result = update_now(&cfg, &cf, &detector(), || true).await;
        assert_eq!(result.outcomes[0].status, "unchanged");
        assert!(api.all_reads());
    }

    #[tokio::test]
    async fn dashboard_and_update_agree_on_metadata_drift() {
        let api = record_api(serde_json::json!([{"id":"one","name":"example.com","type":"A","content":"192.0.2.1","ttl":600,"proxied":false,"comment":"managed by GUI"}]), false).await;
        let cf = cloudflare(&api.url);
        let report = status(&config(), &cf, &detector()).await;
        assert!(!report.domains[0].in_sync);
        assert!(report.domains[0].error.is_none());
        let result = update_now(&config(), &cf, &detector(), || true).await;
        assert_eq!(result.outcomes[0].status, "updated");
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
        for text in [
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "3fff::1",
            "3fff:fff::1",
        ] {
            let ip = text.parse::<IpAddr>().unwrap();
            assert!(!public_address(ip, false), "{text}");
            assert!(public_address(ip, true), "{text}");
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
        let error = fetch_text(&mock.url, true, Family::V4).await.unwrap_err();
        assert!(error.contains("16 KiB"));
        for (provider, family) in [
            ("literal:104.16.1.1", Family::V4),
            ("literal:2606:4700::1", Family::V6),
            ("literal:0.0.0.0", Family::V4),
            ("literal:ff02::1", Family::V6),
            ("literal:::ffff:104.16.1.1", Family::V4),
            ("literal:::ffff:0.0.0.0", Family::V4),
        ] {
            assert!(detect_text(provider, family).await.is_err(), "{provider}");
        }
    }

    #[tokio::test]
    async fn literal_lists_select_family_and_canonicalize() {
        let provider = "literal: 2001:0DB8:0000:0000:0000:0000:0000:0001 , 192.0.2.1, 127.0.0.1";
        assert_eq!(
            detect_text(provider, Family::V4).await.unwrap(),
            Some("192.0.2.1".to_string())
        );
        assert_eq!(
            detect_text(provider, Family::V6).await.unwrap(),
            Some("2001:db8::1".to_string())
        );
        for (provider, family, expected) in [
            ("literal:10.0.0.1", Family::V4, "10.0.0.1"),
            ("literal:127.0.0.1", Family::V4, "127.0.0.1"),
            ("literal:fd00:0:0:0:0:0:0:1", Family::V6, "fd00::1"),
            ("literal:::1", Family::V6, "::1"),
        ] {
            assert_eq!(
                detect_text(provider, family).await.unwrap(),
                Some(expected.to_string())
            );
        }
    }

    #[tokio::test]
    async fn mapped_ipv4_literals_count_as_ipv4() {
        assert_eq!(
            detect_text("literal:::ffff:192.0.2.1", Family::V4)
                .await
                .unwrap(),
            Some("192.0.2.1".to_string())
        );
        let error = detect_text("literal:::ffff:192.0.2.1", Family::V6)
            .await
            .unwrap_err();
        assert!(error.contains("no matching IP family"), "{error}");
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
            for family in Family::ALL {
                let error = detect_text(provider, family).await.unwrap_err();
                assert!(error.contains("invalid IP address"), "{provider}: {error}");
            }
        }
        for (provider, family) in [
            ("literal:::1", Family::V4),
            ("literal:192.0.2.1", Family::V6),
        ] {
            let error = detect_text(provider, family).await.unwrap_err();
            assert!(error.contains("no matching IP family"));
        }
    }

    #[tokio::test]
    async fn disabled_provider_returns_no_address() {
        for family in Family::ALL {
            assert_eq!(detect_text("none", family).await.unwrap(), None);
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
                detect_text(&format!("url:{}", mock.url), Family::V4)
                    .await
                    .is_err(),
                "accepted {body}"
            );
        }
        for body in ["::1", "fd00::1", "fe80::1", "2606:4700::1"] {
            let mock = MockHttp::new(true, 200, body).await;
            assert!(
                detect_text(&format!("url:{}", mock.url), Family::V6)
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
            let result = detect_text(&format!("url:{}", mock.url), Family::V4).await;
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
            let result = detect_text(&format!("url:{}", mock.url), Family::V6).await;
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
        for (family, body, expected) in [
            (
                Family::V4,
                "fl=123\nip= 192.0.2.1 \ncolo=TEST\n",
                Some("192.0.2.1"),
            ),
            (
                Family::V6,
                "ip=2001:0DB8:0:0:0:0:0:1\nloc=TEST\n",
                Some("2001:db8::1"),
            ),
            (Family::V4, "fl=123\ncolo=TEST\n", None),
            (Family::V4, "ip=\n", None),
            (Family::V4, "ip=invalid\n", None),
            (Family::V4, "ip=2001:db8::1\n", None),
            (Family::V6, "ip=192.0.2.1\n", None),
            (Family::V4, "other_ip=192.0.2.1\n", None),
        ] {
            let mock = MockHttp::new(family == Family::V6, 200, body).await;
            let result = fetch_text(&mock.url, true, family).await;
            if let Some(ip) = expected {
                assert_eq!(result.unwrap(), ip);
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
                let error = fetch_text(&url, trace, Family::V4).await.unwrap_err();
                assert!(error.contains(&status.to_string()), "{error}");
                assert!(!error.contains(&mock.url));
                assert!(!error.contains("private-provider"));
                assert!(!error.contains("dummy-sensitive-marker"));
            }
        }
    }

    #[tokio::test]
    async fn requests_cannot_fall_back_to_the_other_family() {
        for family in Family::ALL {
            let ipv6 = family == Family::V6;
            let mock = MockHttp::new(!ipv6, 200, if ipv6 { "::1" } else { "127.0.0.1" }).await;
            for trace in [false, true] {
                let url = format!("{}/private-provider?key=dummy-sensitive-marker", mock.url);
                let error = fetch_text(&url, trace, family).await.unwrap_err();
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
        let cf = cloudflare(&api.url);
        let detection = MockHttp::new(false, 503, "192.0.2.1").await;
        let cfg = Config {
            api_token: String::new(),
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
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
        let result = update_now(&cfg, &cf, &detector(), || true).await;
        assert!(!result.success);
        assert_eq!(result.outcomes.len(), 2);
        for outcome in &result.outcomes {
            let error = outcome.error.as_deref().unwrap_or_default();
            assert_eq!(outcome.status, "failed");
            assert!(!error.contains("zone"), "{error}");
        }
        let log = result.log;
        assert_eq!(log.len(), 2, "{log:?}");
        assert!(log[0].contains("IPv4 detection failed"));
        assert!(log[1].contains("IPv6 detection failed"));
        let report = status(&cfg, &cf, &detector()).await;
        assert!(report
            .domains
            .iter()
            .all(|d| d.error.is_some() && d.dns_ips.is_empty()));
        // No family has an address, so Cloudflare is never contacted.
        let requests = api.requests.lock().unwrap();
        assert!(requests.is_empty(), "{requests:?}");
    }

    #[tokio::test]
    async fn duplicate_records_never_cause_mutations() {
        let api = record_api(
            serde_json::json!([
                {"id":"one","name":"example.com","type":"A","content":"192.0.2.2"},
                {"id":"two","name":"example.com","type":"A","content":"192.0.2.3"},
            ]),
            false,
        )
        .await;
        let cf = cloudflare(&api.url);
        let cfg = Config {
            api_token: String::new(),
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
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
        let result = update_now(&cfg, &cf, &detector(), || true).await;
        assert_eq!(result.outcomes[0].status, "failed");
        let error = result.outcomes[0].error.as_deref().unwrap_or_default();
        assert!(error.contains("duplicate"), "{error}");
        assert!(api.all_reads());
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
                (200, listing(&serde_json::json!([])))
            } else {
                revoke.store(false, Ordering::SeqCst);
                (200, r#"{"success":true,"result":{"id":"test-record","name":"example.com","type":"A","content":"192.0.2.1"}}"#.into())
            }
        }).await;
        let cf = cloudflare(&api.url);
        let mut cfg = config();
        cfg.ip6_domains = cfg.domains.clone();
        cfg.ip6_provider = "literal:2001:db8::1".into();
        let result = update_now(&cfg, &cf, &detector(), || authorized.load(Ordering::SeqCst)).await;
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
        let redirect = MockHttp::with_response(false, move |_| {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        })
        .await;
        let error = fetch_text(&redirect.url, false, Family::V4)
            .await
            .unwrap_err();
        assert!(error.contains("302"));
        assert_eq!(redirect.requests.lock().unwrap().len(), 1);
        assert!(destination.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn chunked_provider_body_cannot_bypass_the_size_bound() {
        let body = format!("ip=192.0.2.1\n{}", "x".repeat(16 * 1024));
        let response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        );
        let mock = MockHttp::with_response(false, move |_| response.clone()).await;
        let error = fetch_text(&mock.url, true, Family::V4).await.unwrap_err();
        assert!(error.contains("16 KiB"));
    }

    #[tokio::test]
    async fn detection_never_reuses_a_kept_alive_connection() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&connections);
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                // Keep the connection open and answer every request sent on it.
                tokio::spawn(async move {
                    let mut buffer = [0; 1024];
                    let mut pending = Vec::new();
                    while let Ok(count @ 1..) = stream.read(&mut buffer).await {
                        pending.extend_from_slice(&buffer[..count]);
                        while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                            pending.drain(..end + 4);
                            let reply = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n192.0.2.1";
                            if stream.write_all(reply.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        let detector = detector();
        for _ in 0..2 {
            let ip = detector.fetch(&url, false, Family::V4).await.unwrap();
            assert_eq!(ip.to_string(), "192.0.2.1");
        }
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn both_families_are_detected_concurrently() {
        // Each provider answers only once both requests have arrived, so
        // detecting one family after the other would time out.
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut providers = Vec::new();
        let mut servers = Vec::new();
        for (address, body) in [("127.0.0.1:0", "192.0.2.1"), ("[::1]:0", "2001:db8::1")] {
            let listener = TcpListener::bind(address).await.unwrap();
            providers.push(format!("url:http://{}", listener.local_addr().unwrap()));
            let barrier = Arc::clone(&barrier);
            servers.push(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 1024];
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                }
                barrier.wait().await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }));
        }
        let mut cfg = config();
        cfg.ip4_provider = providers[0].clone();
        cfg.ip6_provider = providers[1].clone();
        cfg.ip6_domains = cfg.domains.clone();
        let detection = detect_all(&cfg, &detector()).await;
        assert_eq!(detection.ipv4, Ok(Some("192.0.2.1".parse().unwrap())));
        assert_eq!(detection.ipv6, Ok(Some("2001:db8::1".parse().unwrap())));
        for server in servers {
            server.await.unwrap();
        }
    }
}
