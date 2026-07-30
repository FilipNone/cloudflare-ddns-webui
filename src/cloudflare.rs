//! Cloudflare API v4 client, modelled after the one in cloudflare-ddns:
//! a thin reqwest wrapper with Bearer-token auth and envelope decoding.

use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

// --- Envelope ---

#[derive(Debug, Deserialize)]
pub struct CfError {
    pub code: Option<i64>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Envelope<T> {
    pub success: Option<bool>,
    pub errors: Option<Vec<CfError>>,
    pub result: Option<T>,
    pub result_info: Option<ResultInfo>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResultInfo {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub total_pages: Option<u32>,
    pub total_count: Option<u32>,
}

// --- API types ---

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub status: Option<String>,
    pub paused: Option<bool>,
    #[serde(rename = "type")]
    pub zone_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub proxiable: Option<bool>,
    pub proxied: Option<bool>,
    pub ttl: Option<i64>,
    pub comment: Option<String>,
    pub tags: Option<Vec<String>>,
    pub priority: Option<u16>,
    pub created_on: Option<String>,
    pub modified_on: Option<String>,
    pub data: Option<serde_json::Value>,
}

/// Payload for creating a record. `data` carries structured content for
/// types like SRV and CAA.
#[derive(Debug, Serialize, Clone)]
pub struct RecordPayload {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
    pub ttl: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Partial payload for PATCH updates (used by bulk modify).
#[derive(Debug, Serialize, Clone, Default)]
pub struct RecordPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug)]
pub struct ApiFailure {
    pub status: u16,
    pub messages: Vec<String>,
}

impl std::fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.messages.is_empty() {
            write!(f, "Cloudflare API error (HTTP {})", self.status)
        } else {
            write!(f, "{}", self.messages.join("; "))
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ImportResult {
    pub recs_added: Option<u32>,
    pub total_records_parsed: Option<u32>,
}

// --- Client ---

#[derive(Clone)]
pub struct CloudflareClient {
    client: reqwest::Client,
    token: String,
    base: String,
}

impl CloudflareClient {
    pub fn new(token: &str, timeout: Duration, base_url: Option<&str>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        CloudflareClient {
            client,
            token: token.to_string(),
            base: base_url.unwrap_or(API_BASE).trim_end_matches('/').to_string(),
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}/{path}", self.base))
            .header("Authorization", format!("Bearer {}", self.token))
    }

    async fn api<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T, ApiFailure> {
        let mut req = self.request(method.clone(), path);
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(|e| ApiFailure {
            status: 0,
            messages: vec![format!("request to Cloudflare failed: {e}")],
        })?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let env: Envelope<T> = serde_json::from_str(&text).map_err(|_| ApiFailure {
            status,
            messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
        })?;
        if env.success.unwrap_or(false) {
            env.result.ok_or_else(|| ApiFailure {
                status,
                messages: vec!["Cloudflare response missing result".to_string()],
            })
        } else {
            let messages = env
                .errors
                .unwrap_or_default()
                .into_iter()
                .map(|e| match (e.code, e.message) {
                    (Some(c), Some(m)) => format!("[{c}] {m}"),
                    (None, Some(m)) => m,
                    (Some(c), None) => format!("error code {c}"),
                    (None, None) => "unknown error".to_string(),
                })
                .collect();
            Err(ApiFailure { status, messages })
        }
    }

    /// Like `api`, for endpoints whose result may legitimately be absent.
    async fn api_opt<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<Option<T>, ApiFailure> {
        let mut req = self.request(method, path);
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(|e| ApiFailure {
            status: 0,
            messages: vec![format!("request to Cloudflare failed: {e}")],
        })?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let env: Envelope<T> = serde_json::from_str(&text).map_err(|_| ApiFailure {
            status,
            messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
        })?;
        if env.success.unwrap_or(false) {
            Ok(env.result)
        } else {
            let messages = env
                .errors
                .unwrap_or_default()
                .into_iter()
                .map(|e| e.message.unwrap_or_else(|| "unknown error".to_string()))
                .collect();
            Err(ApiFailure { status, messages })
        }
    }

    // --- Zones ---

    pub async fn list_zones(&self) -> Result<Vec<Zone>, ApiFailure> {
        let mut zones = Vec::new();
        let mut page = 1u32;
        loop {
            let path = format!("zones?per_page=50&page={page}&order=name");
            let (mut batch, info): (Vec<Zone>, Option<ResultInfo>) = {
                // Need both result and result_info - decode manually.
                let resp = self
                    .request(reqwest::Method::GET, &path)
                    .send()
                    .await
                    .map_err(|e| ApiFailure {
                        status: 0,
                        messages: vec![format!("request to Cloudflare failed: {e}")],
                    })?;
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let env: Envelope<Vec<Zone>> =
                    serde_json::from_str(&text).map_err(|_| ApiFailure {
                        status,
                        messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
                    })?;
                if !env.success.unwrap_or(false) {
                    return Err(ApiFailure {
                        status,
                        messages: env
                            .errors
                            .unwrap_or_default()
                            .into_iter()
                            .map(|e| e.message.unwrap_or_else(|| "unknown error".to_string()))
                            .collect(),
                    });
                }
                (env.result.unwrap_or_default(), env.result_info)
            };
            let total_pages = info.and_then(|i| i.total_pages).unwrap_or(1);
            let done = batch.is_empty() || page >= total_pages;
            zones.append(&mut batch);
            if done || page >= 50 {
                break;
            }
            page += 1;
        }
        Ok(zones)
    }

    // --- DNS records ---

    pub async fn list_records(&self, zone_id: &str) -> Result<(Vec<DnsRecord>, u32), ApiFailure> {
        let mut records = Vec::new();
        let mut page = 1u32;
        let mut total_count;
        loop {
            let path = format!("zones/{zone_id}/dns_records?per_page=100&page={page}&order=type,name");
            let resp = self
                .request(reqwest::Method::GET, &path)
                .send()
                .await
                .map_err(|e| ApiFailure {
                    status: 0,
                    messages: vec![format!("request to Cloudflare failed: {e}")],
                })?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let env: Envelope<Vec<DnsRecord>> =
                serde_json::from_str(&text).map_err(|_| ApiFailure {
                    status,
                    messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
                })?;
            if !env.success.unwrap_or(false) {
                return Err(ApiFailure {
                    status,
                    messages: env
                        .errors
                        .unwrap_or_default()
                        .into_iter()
                        .map(|e| e.message.unwrap_or_else(|| "unknown error".to_string()))
                        .collect(),
                });
            }
            let mut batch = env.result.unwrap_or_default();
            let (count, total_pages) = match env.result_info {
                Some(i) => (
                    i.total_count.unwrap_or(0),
                    i.total_pages.unwrap_or(1),
                ),
                None => (0, 1),
            };
            total_count = count;
            let done = batch.is_empty() || page >= total_pages;
            records.append(&mut batch);
            if done || page >= 100 {
                break;
            }
            page += 1;
        }
        Ok((records, total_count))
    }

    pub async fn create_record(
        &self,
        zone_id: &str,
        payload: &RecordPayload,
    ) -> Result<DnsRecord, ApiFailure> {
        self.api(
            reqwest::Method::POST,
            &format!("zones/{zone_id}/dns_records"),
            Some(payload),
        )
        .await
    }

    pub async fn patch_record(
        &self,
        zone_id: &str,
        record_id: &str,
        patch: &RecordPatch,
    ) -> Result<DnsRecord, ApiFailure> {
        self.api(
            reqwest::Method::PATCH,
            &format!("zones/{zone_id}/dns_records/{record_id}"),
            Some(patch),
        )
        .await
    }

    pub async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        payload: &RecordPayload,
    ) -> Result<DnsRecord, ApiFailure> {
        self.api(
            reqwest::Method::PUT,
            &format!("zones/{zone_id}/dns_records/{record_id}"),
            Some(payload),
        )
        .await
    }

    pub async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), ApiFailure> {
        self.api_opt::<serde_json::Value>(
            reqwest::Method::DELETE,
            &format!("zones/{zone_id}/dns_records/{record_id}"),
            None::<&()>,
        )
        .await?;
        Ok(())
    }

    // --- Import / export (BIND zone files, Cloudflare native endpoints) ---

    pub async fn export_records(&self, zone_id: &str) -> Result<String, ApiFailure> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("zones/{zone_id}/dns_records/export"),
            )
            .send()
            .await
            .map_err(|e| ApiFailure {
                status: 0,
                messages: vec![format!("request to Cloudflare failed: {e}")],
            })?;
        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            return Err(ApiFailure {
                status,
                messages: vec![format!("export failed (HTTP {status})")],
            });
        }
        resp.text().await.map_err(|e| ApiFailure {
            status: 0,
            messages: vec![format!("failed to read export: {e}")],
        })
    }

    pub async fn import_records(
        &self,
        zone_id: &str,
        filename: &str,
        bind_data: Vec<u8>,
    ) -> Result<ImportResult, ApiFailure> {
        // Hand-rolled multipart/form-data body (keeps the binary lean - no
        // extra multipart dependency).
        let boundary = format!("cfddnswebui{}", std::process::id());
        let mut body = Vec::with_capacity(bind_data.len() + 256);
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&bind_data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let resp = self
            .request(
                reqwest::Method::POST,
                &format!("zones/{zone_id}/dns_records/import"),
            )
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
            .await
            .map_err(|e| ApiFailure {
                status: 0,
                messages: vec![format!("request to Cloudflare failed: {e}")],
            })?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let env: Envelope<ImportResult> = serde_json::from_str(&text).map_err(|_| ApiFailure {
            status,
            messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
        })?;
        if env.success.unwrap_or(false) {
            Ok(env.result.unwrap_or(ImportResult {
                recs_added: None,
                total_records_parsed: None,
            }))
        } else {
            Err(ApiFailure {
                status,
                messages: env
                    .errors
                    .unwrap_or_default()
                    .into_iter()
                    .map(|e| e.message.unwrap_or_else(|| "unknown error".to_string()))
                    .collect(),
            })
        }
    }

    // --- Helpers for DDNS features ---

    /// Find the zone that owns `domain` by walking parent domains, exactly
    /// like cloudflare-ddns does.
    pub async fn zone_for_domain(&self, domain: &str) -> Result<Option<Zone>, ApiFailure> {
        let mut current = domain.to_string();
        loop {
            let zones: Vec<Zone> = self
                .api_opt(
                    reqwest::Method::GET,
                    &format!("zones?name={current}"),
                    None::<&()>,
                )
                .await?
                .unwrap_or_default();
            if let Some(zone) = zones.into_iter().next() {
                return Ok(Some(zone));
            }
            match current.find('.') {
                Some(pos) => {
                    current = current[pos + 1..].to_string();
                    if !current.contains('.') {
                        break;
                    }
                }
                None => break,
            }
        }
        Ok(None)
    }

    pub async fn list_records_by_name(
        &self,
        zone_id: &str,
        record_type: &str,
        name: &str,
    ) -> Result<Vec<DnsRecord>, ApiFailure> {
        let path = format!(
            "zones/{zone_id}/dns_records?per_page=100&type={record_type}&name={}",
            url_encode(name)
        );
        let records: Vec<DnsRecord> = self
            .api_opt(reqwest::Method::GET, &path, None::<&()>)
            .await?
            .unwrap_or_default();
        // Cloudflare normalizes names to lowercase; match case-insensitively.
        Ok(records
            .into_iter()
            .filter(|r| r.name.eq_ignore_ascii_case(name))
            .collect())
    }
}

pub fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
