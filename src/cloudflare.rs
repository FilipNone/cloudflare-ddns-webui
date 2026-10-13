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
    pub tags: Option<Vec<String>>,
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
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("Cloudflare HTTP client configuration is valid");
        CloudflareClient {
            client,
            token: token.to_string(),
            base: base_url
                .unwrap_or(API_BASE)
                .trim_end_matches('/')
                .to_string(),
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
            messages: vec![format!("request to Cloudflare failed: {}", e.without_url())],
        })?;
        let status = resp.status().as_u16();
        let text = read_body(resp).await?;
        let env: Envelope<T> = serde_json::from_str(&text).map_err(|_| ApiFailure {
            status,
            messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
        })?;
        if (200..300).contains(&status) && env.success.unwrap_or(false) {
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
            messages: vec![format!("request to Cloudflare failed: {}", e.without_url())],
        })?;
        let status = resp.status().as_u16();
        let text = read_body(resp).await?;
        let env: Envelope<T> = serde_json::from_str(&text).map_err(|_| ApiFailure {
            status,
            messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
        })?;
        if (200..300).contains(&status) && env.success.unwrap_or(false) {
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
                let text = read_body(resp).await?;
                let env: Envelope<Vec<Zone>> =
                    serde_json::from_str(&text).map_err(|_| ApiFailure {
                        status,
                        messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
                    })?;
                if !(200..300).contains(&status) || !env.success.unwrap_or(false) {
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
                (
                    env.result.ok_or_else(|| ApiFailure {
                        status: 502,
                        messages: vec!["Cloudflare response missing zone result".into()],
                    })?,
                    env.result_info,
                )
            };
            let total_pages = info.and_then(|i| i.total_pages).unwrap_or(1);
            let done = batch.is_empty() || page >= total_pages;
            zones.append(&mut batch);
            if done {
                break;
            }
            if page >= 50 {
                return Err(input_error(
                    "zone listing exceeds the supported pagination limit",
                ));
            }
            page += 1;
        }
        Ok(zones)
    }

    // --- DNS records ---

    pub async fn list_records(&self, zone_id: &str) -> Result<(Vec<DnsRecord>, u32), ApiFailure> {
        validate_identifier(zone_id)?;
        let mut records = Vec::new();
        let mut page = 1u32;
        let mut total_count;
        loop {
            let path =
                format!("zones/{zone_id}/dns_records?per_page=100&page={page}&order=type,name");
            let resp = self
                .request(reqwest::Method::GET, &path)
                .send()
                .await
                .map_err(|e| ApiFailure {
                    status: 0,
                    messages: vec![format!("request to Cloudflare failed: {e}")],
                })?;
            let status = resp.status().as_u16();
            let text = read_body(resp).await?;
            let env: Envelope<Vec<DnsRecord>> =
                serde_json::from_str(&text).map_err(|_| ApiFailure {
                    status,
                    messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
                })?;
            if !(200..300).contains(&status) || !env.success.unwrap_or(false) {
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
            let mut batch = env.result.ok_or_else(|| ApiFailure {
                status: 502,
                messages: vec!["Cloudflare response missing record result".into()],
            })?;
            let (count, total_pages) = match env.result_info {
                Some(i) => (i.total_count.unwrap_or(0), i.total_pages.unwrap_or(1)),
                None => (0, 1),
            };
            total_count = count;
            let done = batch.is_empty() || page >= total_pages;
            records.append(&mut batch);
            if done {
                break;
            }
            if page >= 100 {
                return Err(input_error(
                    "record listing exceeds the supported pagination limit",
                ));
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
        validate_identifier(zone_id)?;
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
        validate_identifier(zone_id)?;
        validate_identifier(record_id)?;
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
        validate_identifier(zone_id)?;
        validate_identifier(record_id)?;
        self.api(
            reqwest::Method::PATCH,
            &format!("zones/{zone_id}/dns_records/{record_id}"),
            Some(payload),
        )
        .await
    }

    pub async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), ApiFailure> {
        validate_identifier(zone_id)?;
        validate_identifier(record_id)?;
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
        validate_identifier(zone_id)?;
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("zones/{zone_id}/dns_records/export"),
            )
            .send()
            .await
            .map_err(|e| ApiFailure {
                status: 0,
                messages: vec![format!("request to Cloudflare failed: {}", e.without_url())],
            })?;
        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            return Err(ApiFailure {
                status,
                messages: vec![format!("export failed (HTTP {status})")],
            });
        }
        read_body(resp).await
    }

    pub async fn import_records(
        &self,
        zone_id: &str,
        filename: &str,
        bind_data: Vec<u8>,
    ) -> Result<ImportResult, ApiFailure> {
        validate_identifier(zone_id)?;
        if filename.is_empty()
            || filename.len() > 128
            || filename.starts_with('.')
            || !filename
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(input_error(
                "invalid zone-file name; use letters, digits, dots, hyphens or underscores",
            ));
        }
        // Hand-rolled multipart/form-data body (keeps the binary lean - no
        // extra multipart dependency).
        let mut random = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
            .map_err(|_| input_error("cannot generate multipart boundary"))?;
        let boundary = format!(
            "cfddnswebui{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
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
        let text = read_body(resp).await?;
        let env: Envelope<ImportResult> = serde_json::from_str(&text).map_err(|_| ApiFailure {
            status,
            messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
        })?;
        if (200..300).contains(&status) && env.success.unwrap_or(false) {
            env.result
                .filter(|result| {
                    result.recs_added.is_some() && result.total_records_parsed.is_some()
                })
                .ok_or_else(|| ApiFailure {
                    status: 502,
                    messages: vec![
                        "Cloudflare response missing import counts; import outcome is unknown"
                            .into(),
                    ],
                })
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
                .api(
                    reqwest::Method::GET,
                    &format!("zones?name={}", url_encode(&current)),
                    None::<&()>,
                )
                .await?;
            if let Some(zone) = zones
                .into_iter()
                .find(|z| z.name.eq_ignore_ascii_case(&current))
            {
                validate_identifier(&zone.id)?;
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
        let (records, _) = self.list_records(zone_id).await?;
        // Cloudflare normalizes names to lowercase; match case-insensitively.
        Ok(records
            .into_iter()
            .filter(|r| r.record_type == record_type && r.name.eq_ignore_ascii_case(name))
            .collect())
    }
}

fn input_error(message: &str) -> ApiFailure {
    ApiFailure {
        status: 400,
        messages: vec![message.to_string()],
    }
}

async fn read_body(mut response: reqwest::Response) -> Result<String, ApiFailure> {
    const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
    let status = response.status().as_u16();
    let failure = |message: &str| ApiFailure {
        status,
        messages: vec![message.to_string()],
    };
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Err(failure("Cloudflare response exceeds the 8 MiB limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| failure("cannot read Cloudflare response"))?
    {
        if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
            return Err(failure("Cloudflare response exceeds the 8 MiB limit"));
        }
        body.reserve_exact(chunk.len());
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| failure("Cloudflare response is not UTF-8"))
}

pub fn validate_identifier(id: &str) -> Result<(), ApiFailure> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(input_error("invalid zone or record identifier"));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_record_result_is_not_an_empty_zone() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0, "request headers were truncated");
                request.extend_from_slice(&buffer[..count]);
                assert!(request.len() <= 8192);
            }
            let body = r#"{"success":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let cf = CloudflareClient::new("synthetic-token", Duration::from_secs(2), Some(&base));
        assert_eq!(
            cf.list_records("synthetic-zone").await.unwrap_err().status,
            502
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn missing_zone_lookup_result_never_falls_back_to_parent() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                assert!(request.len() <= 8192);
            }
            let body = r#"{"success":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let cf = CloudflareClient::new("synthetic-token", Duration::from_secs(2), Some(&base));
        let error = cf.zone_for_domain("sub.example.com").await.unwrap_err();
        assert!(error.to_string().contains("missing result"), "{error}");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn missing_import_counts_are_not_a_successful_import() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        for result in [
            "",
            ",\"result\":null",
            ",\"result\":{}",
            ",\"result\":{\"recs_added\":0}",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let body = format!("{{\"success\":true{result}}}");
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                    assert!(request.len() <= 8192);
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            });
            let cf = CloudflareClient::new("synthetic-token", Duration::from_secs(2), Some(&base));
            assert_eq!(
                cf.import_records(
                    "synthetic-zone",
                    "zone.txt",
                    b"$TTL 300\n@ A 192.0.2.1\n".to_vec()
                )
                .await
                .unwrap_err()
                .status,
                502
            );
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn unsafe_identifiers_are_rejected_before_network() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cf = CloudflareClient::new(
            "synthetic-token",
            Duration::from_millis(100),
            Some("http://127.0.0.1:1"),
        );
        for id in [
            "",
            "..",
            "../zones",
            "record/other",
            "record?x=y",
            "record#fragment",
            "%2e%2e",
            "a\r\nb",
            "a b",
        ] {
            let error = cf.delete_record("synthetic-zone", id).await.unwrap_err();
            assert_eq!(
                error.status, 400,
                "unsafe identifier must fail before contacting upstream: {id:?}"
            );
            let error = cf.list_records(id).await.unwrap_err();
            assert_eq!(error.status, 400);
        }
    }

    #[tokio::test]
    async fn unsafe_multipart_filenames_are_rejected_before_network() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cf = CloudflareClient::new(
            "synthetic-token",
            Duration::from_millis(100),
            Some("http://127.0.0.1:1"),
        );
        for filename in [
            "",
            "../zone.txt",
            "a/b.txt",
            "a\\b.txt",
            "a\".txt",
            "a\r\nX-Forged: yes",
        ] {
            let error = cf
                .import_records(
                    "synthetic-zone",
                    filename,
                    b"example.com. 300 IN A 192.0.2.1".to_vec(),
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.status, 400,
                "unsafe filename reached network: {filename:?}"
            );
        }
    }
}
