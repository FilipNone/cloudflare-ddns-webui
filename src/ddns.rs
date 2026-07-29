//! DDNS features surfaced in the GUI: public IP detection (same providers as
//! cloudflare-ddns), sync status of configured domains, and on-demand updates
//! that follow the same create-or-update behavior as the cloudflare-ddns
//! updater.

use crate::cloudflare::{CloudflareClient, RecordPatch, RecordPayload};
use crate::config::Config;
use serde::Serialize;
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
}

/// Detect the public IP using a cloudflare-ddns style provider string.
pub async fn detect_ip(
    provider: &str,
    family: &str, // "ipv4" or "ipv6"
    timeout: Duration,
) -> Result<Option<String>, String> {
    // Prefixed providers: url:<endpoint>, literal:<ips>
    if let Some(url) = provider.strip_prefix("url:") {
        return fetch_ip(url, false, timeout).await;
    }
    if let Some(ips) = provider.strip_prefix("literal:") {
        return Ok(ips
            .split(',')
            .map(|s| s.trim().to_string())
            .find(|s| !s.is_empty()));
    }

    match provider {
        "none" => Ok(None),
        "ipify" => {
            let url = if family == "ipv6" {
                "https://api6.ipify.org"
            } else {
                "https://api.ipify.org"
            };
            fetch_ip(url, false, timeout).await
        }
        "cloudflare.trace" => fetch_ip("https://www.cloudflare.com/cdn-cgi/trace", true, timeout).await,
        other => Err(format!(
            "provider '{other}' is not supported by the web UI (use ipify, cloudflare.trace, url:…, literal:… or none)"
        )),
    }
}

async fn fetch_ip(url: &str, trace_format: bool, timeout: Duration) -> Result<Option<String>, String> {
    if url.is_empty() {
        return Err("empty URL provider".to_string());
    }
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let text = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("detection request failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("detection read failed: {e}"))?;
    if trace_format {
        // cloudflare.trace: parse key=value lines, extract ip=
        for line in text.lines() {
            if let Some(ip) = line.strip_prefix("ip=") {
                return Ok(Some(ip.trim().to_string()));
            }
        }
        Err("no ip= field in trace response".to_string())
    } else {
        let ip = text.trim().to_string();
        if ip.is_empty() {
            Err("empty response from IP provider".to_string())
        } else {
            Ok(Some(ip))
        }
    }
}

fn wanted_types(cfg: &Config) -> Vec<(&'static str, &'static str)> {
    // (family, record type)
    let mut out = Vec::new();
    if cfg.ip4_provider != "none" {
        out.push(("ipv4", "A"));
    }
    if cfg.ip6_provider != "none" {
        out.push(("ipv6", "AAAA"));
    }
    out
}

/// Compute the sync status of every configured DDNS domain.
pub async fn status(cfg: &Config, cf: &CloudflareClient) -> DdnsStatus {
    let (ipv4, ipv6, ipv4_error, ipv6_error) = detect_both(cfg).await;

    let mut domains = Vec::new();
    for domain in &cfg.domains {
        for (family, rtype) in wanted_types(cfg) {
            let detected = if family == "ipv4" { &ipv4 } else { &ipv6 };
            let detected_err = if family == "ipv4" { &ipv4_error } else { &ipv6_error };
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
                                entry.dns_ips =
                                    records.iter().map(|r| r.content.clone()).collect();
                                entry.in_sync = match &entry.detected_ip {
                                    Some(ip) => entry.dns_ips.len() == 1 && entry.dns_ips[0] == *ip,
                                    None => false,
                                };
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
    }
}

async fn detect_both(
    cfg: &Config,
) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    let mut ipv4 = None;
    let mut ipv6 = None;
    let mut ipv4_error = None;
    let mut ipv6_error = None;

    if cfg.ip4_provider != "none" {
        match detect_ip(&cfg.ip4_provider, "ipv4", cfg.detection_timeout).await {
            Ok(ip) => ipv4 = ip,
            Err(e) => ipv4_error = Some(e),
        }
    }
    if cfg.ip6_provider != "none" {
        match detect_ip(&cfg.ip6_provider, "ipv6", cfg.detection_timeout).await {
            Ok(ip) => ipv6 = ip,
            Err(e) => ipv6_error = Some(e),
        }
    }
    (ipv4, ipv6, ipv4_error, ipv6_error)
}

/// Run one on-demand update cycle, mirroring the cloudflare-ddns updater:
/// create the record if missing, update it if the content differs, skip
/// otherwise. Transient detection failures never touch existing records.
pub async fn update_now(cfg: &Config, cf: &CloudflareClient) -> Vec<String> {
    let mut log = Vec::new();
    let (ipv4, ipv6, ipv4_error, ipv6_error) = detect_both(cfg).await;
    if let Some(e) = &ipv4_error {
        log.push(format!("⚠️ IPv4 detection failed, skipping A records: {e}"));
    }
    if let Some(e) = &ipv6_error {
        log.push(format!("⚠️ IPv6 detection failed, skipping AAAA records: {e}"));
    }

    for domain in &cfg.domains {
        let zone = match cf.zone_for_domain(domain).await {
            Ok(Some(z)) => z,
            Ok(None) => {
                log.push(format!("❌ {domain}: no matching Cloudflare zone"));
                continue;
            }
            Err(e) => {
                log.push(format!("❌ {domain}: zone lookup failed: {e}"));
                continue;
            }
        };

        for (family, rtype) in wanted_types(cfg) {
            let detected = if family == "ipv4" { &ipv4 } else { &ipv6 };
            let ip = match detected {
                Some(ip) => ip.clone(),
                None => continue, // transient failure or disabled — preserve records
            };
            match cf.list_records_by_name(&zone.id, rtype, domain).await {
                Ok(records) if records.is_empty() => {
                    let payload = RecordPayload {
                        record_type: rtype.to_string(),
                        name: domain.clone(),
                        content: Some(ip.clone()),
                        proxied: Some(cfg.proxied),
                        ttl: cfg.ttl,
                        comment: cfg.record_comment.clone(),
                        tags: None,
                        priority: None,
                        data: None,
                    };
                    match cf.create_record(&zone.id, &payload).await {
                        Ok(_) => log.push(format!("✅ {domain} {rtype}: created → {ip}")),
                        Err(e) => log.push(format!("❌ {domain} {rtype}: create failed: {e}")),
                    }
                }
                Ok(records) => {
                    for rec in records {
                        if rec.content == ip {
                            log.push(format!("ℹ️ {domain} {rtype}: already up to date ({ip})"));
                        } else {
                            let patch = RecordPatch {
                                content: Some(ip.clone()),
                                ..Default::default()
                            };
                            match cf.patch_record(&zone.id, &rec.id, &patch).await {
                                Ok(_) => log.push(format!(
                                    "✅ {domain} {rtype}: updated {} → {ip}",
                                    rec.content
                                )),
                                Err(e) => {
                                    log.push(format!("❌ {domain} {rtype}: update failed: {e}"))
                                }
                            }
                        }
                    }
                }
                Err(e) => log.push(format!("❌ {domain} {rtype}: lookup failed: {e}")),
            }
        }
    }

    if log.is_empty() {
        log.push("ℹ️ Nothing to do.".to_string());
    }
    log
}
