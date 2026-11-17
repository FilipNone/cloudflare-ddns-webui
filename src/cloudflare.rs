//! Cloudflare API v4 client, modelled after the one in cloudflare-ddns:
//! a thin reqwest wrapper with Bearer-token auth and envelope decoding.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";
/// Cloudflare returns at most 50 zones per page.
const ZONES_PER_PAGE: u32 = 50;
const RECORDS_PER_PAGE: u32 = 100;
// Page limits, so an upstream that keeps reporting more pages cannot keep
// one request busy indefinitely.
const MAX_ZONE_PAGES: u32 = 50;
const MAX_RECORD_PAGES: u32 = 100;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Cloudflare documents zone and record IDs as at most 32 characters.
const MAX_IDENTIFIER_LEN: usize = 32;
const MAX_IMPORT_FILENAME_LEN: usize = 128;
const MISSING_RESULT: &str = "Cloudflare response missing result";
/// Most records in one batch request. Cloudflare allows 200 on the Free plan
/// and 3,500 on paid plans. The GUI cannot see the plan, so it uses the Free
/// limit.
pub const BATCH_LIMIT: usize = 200;

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
    pub data: Option<RecordData>,
}

/// The `data` object of SRV, CAA, HTTPS and SVCB records. It is sent as a
/// plain object with the fields of the variant.
#[derive(Debug, Serialize, Clone)]
#[serde(untagged)]
pub enum RecordData {
    Srv(SrvData),
    Caa(CaaData),
    Svcb(SvcbData),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SrvData {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CaaData {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

/// Used for both HTTPS and SVCB records.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SvcbData {
    pub priority: u16,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
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

/// A record to delete in a batch request. Cloudflare needs only its ID.
#[derive(Debug, Serialize, Clone)]
pub struct BatchDelete {
    pub id: String,
}

/// A record to change in a batch request. The patch fields sit next to the
/// ID, and Cloudflare keeps every field the patch leaves out.
#[derive(Debug, Serialize, Clone)]
pub struct BatchPatch {
    pub id: String,
    #[serde(flatten)]
    pub patch: RecordPatch,
}

/// Body of `POST /zones/{zone_id}/dns_records/batch`. Cloudflare runs the
/// whole batch in one transaction: if any operation fails, it applies none
/// and replies with the first error.
#[derive(Debug, Serialize, Clone, Default)]
pub struct BatchRequest {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deletes: Vec<BatchDelete>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub patches: Vec<BatchPatch>,
}

impl BatchRequest {
    /// The record IDs in the order Cloudflare applies them: deletes first,
    /// then patches.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.deletes
            .iter()
            .map(|item| item.id.as_str())
            .chain(self.patches.iter().map(|item| item.id.as_str()))
    }
}

/// The record IDs in a batch reply. Cloudflare sends full records; only the
/// IDs are needed to confirm what it applied.
#[derive(Deserialize)]
struct BatchResult {
    deletes: Option<Vec<IdOnly>>,
    patches: Option<Vec<IdOnly>>,
}

#[derive(Deserialize)]
struct IdOnly {
    id: String,
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
    pub fn new(token: &str, timeout: Duration, base_url: Option<&str>) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|e| {
                format!(
                    "cannot create the Cloudflare HTTP client: {}",
                    e.without_url()
                )
            })?;
        Ok(CloudflareClient {
            client,
            token: token.to_string(),
            base: base_url
                .unwrap_or(API_BASE)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}/{path}", self.base))
            .bearer_auth(&self.token)
    }

    /// Send a request and unwrap the Cloudflare envelope. The result can be
    /// absent; each caller decides whether that is an error.
    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<(Option<T>, Option<ResultInfo>), ApiFailure> {
        let response = request.send().await.map_err(transport_error)?;
        let status = response.status().as_u16();
        let text = read_body(response).await?;
        let envelope: Envelope<T> = serde_json::from_str(&text).map_err(|_| ApiFailure {
            status,
            messages: vec![format!("unexpected Cloudflare response (HTTP {status})")],
        })?;
        if !(200..300).contains(&status) || !envelope.success.unwrap_or(false) {
            return Err(api_errors(status, envelope.errors));
        }
        Ok((envelope.result, envelope.result_info))
    }

    /// Like `send`, for endpoints that must return a result.
    async fn api<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T, ApiFailure> {
        let mut request = self.request(method, path);
        if let Some(body) = body {
            request = request.json(body);
        }
        let (result, _) = self.send(request).await?;
        result.ok_or_else(|| bad_upstream(MISSING_RESULT))
    }

    /// Fetch every page of a listing and return the items with Cloudflare's
    /// reported total.
    async fn list_all<T: DeserializeOwned>(
        &self,
        path: &str,
        per_page: u32,
        max_pages: u32,
        what: &str,
    ) -> Result<(Vec<T>, u32), ApiFailure> {
        let separator = if path.contains('?') { '&' } else { '?' };
        let mut items = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!("{path}{separator}per_page={per_page}&page={page}");
            let (batch, info) = self
                .send::<Vec<T>>(self.request(reqwest::Method::GET, &url))
                .await?;
            let mut batch = batch.ok_or_else(|| bad_upstream(MISSING_RESULT))?;
            let (total_pages, total_count) = page_totals(info)?;
            let done = batch.is_empty() || page >= total_pages;
            items.append(&mut batch);
            if done {
                // A short listing would make missing records look deleted.
                if items.len() < total_count as usize {
                    return Err(bad_upstream(
                        "Cloudflare returned fewer items than it reported",
                    ));
                }
                return Ok((items, total_count));
            }
            if page >= max_pages {
                return Err(bad_upstream(&format!(
                    "{what} listing exceeds the supported pagination limit"
                )));
            }
            page += 1;
        }
    }

    // --- Zones ---

    pub async fn list_zones(&self) -> Result<Vec<Zone>, ApiFailure> {
        let (zones, _) = self
            .list_all("zones?order=name", ZONES_PER_PAGE, MAX_ZONE_PAGES, "zone")
            .await?;
        Ok(zones)
    }

    // --- DNS records ---

    pub async fn list_records(&self, zone_id: &str) -> Result<(Vec<DnsRecord>, u32), ApiFailure> {
        validate_identifier(zone_id)?;
        // The frontend sorts records itself, so one documented sort key is enough.
        self.list_all(
            &format!("zones/{zone_id}/dns_records?order=type&direction=asc"),
            RECORDS_PER_PAGE,
            MAX_RECORD_PAGES,
            "record",
        )
        .await
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

    /// Sent as PATCH, so Cloudflare keeps any field that `payload` leaves out.
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
        let request = self.request(
            reqwest::Method::DELETE,
            &format!("zones/{zone_id}/dns_records/{record_id}"),
        );
        self.send::<serde_json::Value>(request).await?;
        Ok(())
    }

    /// Send one batch of deletes and patches. `Ok` means Cloudflare confirmed
    /// every record in it. A Cloudflare error reply means it applied none of
    /// them. When the reply is lost, unreadable or does not list the records
    /// sent, the outcome is unknown and the error says so.
    pub async fn batch(&self, zone_id: &str, batch: &BatchRequest) -> Result<(), ApiFailure> {
        validate_identifier(zone_id)?;
        for id in batch.ids() {
            validate_identifier(id)?;
        }
        let count = batch.deletes.len().saturating_add(batch.patches.len());
        if count == 0 || count > BATCH_LIMIT {
            return Err(input_error(&format!(
                "a batch must contain between 1 and {BATCH_LIMIT} records"
            )));
        }
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("zones/{zone_id}/dns_records/batch"),
            )
            .json(batch)
            .send()
            .await
            .map_err(|error| unknown_outcome(transport_error(error)))?;
        let status = response.status().as_u16();
        let text = read_body(response).await.map_err(unknown_outcome)?;
        let envelope: Envelope<serde_json::Value> = serde_json::from_str(&text).map_err(|_| {
            unknown_outcome(bad_upstream(&format!(
                "unexpected Cloudflare response (HTTP {status})"
            )))
        })?;
        match envelope.success {
            Some(true) if (200..300).contains(&status) => {}
            // Cloudflare rolls back the whole batch when it reports an error.
            Some(false) => return Err(api_errors(status, envelope.errors)),
            _ => {
                return Err(unknown_outcome(bad_upstream(&format!(
                    "unexpected Cloudflare response (HTTP {status})"
                ))))
            }
        }
        if batch_confirmed(batch, envelope.result) {
            Ok(())
        } else {
            Err(unknown_outcome(bad_upstream(
                "Cloudflare reported success without listing the records in the batch",
            )))
        }
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
            .map_err(transport_error)?;
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
            || filename.len() > MAX_IMPORT_FILENAME_LEN
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

        let request = self
            .request(
                reqwest::Method::POST,
                &format!("zones/{zone_id}/dns_records/import"),
            )
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body);
        let (result, _) = self.send::<ImportResult>(request).await?;
        result
            .filter(|result| result.recs_added.is_some() && result.total_records_parsed.is_some())
            .ok_or_else(|| {
                bad_upstream("Cloudflare response missing import counts; import outcome is unknown")
            })
    }

    // --- Helpers for DDNS features ---

    /// Find the zone that owns `domain`: try the name itself, then each
    /// parent in turn, stopping before the top-level domain.
    pub async fn zone_for_domain(&self, domain: &str) -> Result<Option<Zone>, ApiFailure> {
        let mut current = domain;
        loop {
            let zones: Vec<Zone> = self
                .api(
                    reqwest::Method::GET,
                    &format!("zones?name={}", url_encode(current)),
                    None::<&()>,
                )
                .await?;
            let mut matches = zones
                .into_iter()
                .filter(|z| z.name.eq_ignore_ascii_case(current));
            if let Some(zone) = matches.next() {
                // The token can see two zones with one name, for example in
                // two accounts. Picking one could update the wrong zone.
                if matches.next().is_some() {
                    return Err(bad_upstream(&format!(
                        "more than one Cloudflare zone is named {current}"
                    )));
                }
                validate_identifier(&zone.id)?;
                return Ok(Some(zone));
            }
            match current.split_once('.') {
                Some((_, parent)) if parent.contains('.') => current = parent,
                _ => return Ok(None),
            }
        }
    }

    /// Fetch the records with this exact type and name. The DDNS code
    /// refuses duplicates, so one page is enough and a longer listing fails.
    pub async fn list_records_by_name(
        &self,
        zone_id: &str,
        record_type: &str,
        name: &str,
    ) -> Result<Vec<DnsRecord>, ApiFailure> {
        validate_identifier(zone_id)?;
        let path = format!(
            "zones/{zone_id}/dns_records?type={}&name.exact={}&per_page={RECORDS_PER_PAGE}",
            url_encode(record_type),
            url_encode(name)
        );
        let (records, info) = self
            .send::<Vec<DnsRecord>>(self.request(reqwest::Method::GET, &path))
            .await?;
        let records = records.ok_or_else(|| bad_upstream(MISSING_RESULT))?;
        let (_, total_count) = page_totals(info)?;
        if total_count as usize > records.len() {
            return Err(bad_upstream(
                "Cloudflare reported more matching records than it returned",
            ));
        }
        // Cloudflare normalizes names to lowercase; match case-insensitively.
        // The filter also guards against an upstream that ignores the query.
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

fn bad_upstream(message: &str) -> ApiFailure {
    ApiFailure {
        status: 502,
        messages: vec![message.to_string()],
    }
}

fn transport_error(error: reqwest::Error) -> ApiFailure {
    // The URL holds zone and record IDs, which must not reach logs or the browser.
    ApiFailure {
        status: 0,
        messages: vec![format!(
            "request to Cloudflare failed: {}",
            error.without_url()
        )],
    }
}

/// Marks a batch failure where Cloudflare may have applied the batch anyway,
/// for example when the reply was lost after the request was sent.
fn unknown_outcome(failure: ApiFailure) -> ApiFailure {
    ApiFailure {
        // Status 0 stays a transport failure; any reply counts as a bad upstream.
        status: if failure.status == 0 { 0 } else { 502 },
        messages: vec![format!(
            "{failure}; the outcome is unknown, so reload the records before retrying"
        )],
    }
}

/// Whether a success reply lists exactly the records sent, each once. The
/// docs do not promise an order, so the IDs are compared sorted. A missing
/// list counts as empty.
fn batch_confirmed(batch: &BatchRequest, result: Option<serde_json::Value>) -> bool {
    fn same_ids<'a>(reported: Option<Vec<IdOnly>>, sent: impl Iterator<Item = &'a str>) -> bool {
        let reported = reported.unwrap_or_default();
        let mut reported: Vec<&str> = reported.iter().map(|item| item.id.as_str()).collect();
        let mut sent: Vec<&str> = sent.collect();
        reported.sort_unstable();
        sent.sort_unstable();
        reported == sent
    }
    let Some(result) = result.and_then(|value| serde_json::from_value::<BatchResult>(value).ok())
    else {
        return false;
    };
    same_ids(
        result.deletes,
        batch.deletes.iter().map(|item| item.id.as_str()),
    ) && same_ids(
        result.patches,
        batch.patches.iter().map(|item| item.id.as_str()),
    )
}

/// Cloudflare's error list as messages, with the numeric code when present.
fn api_errors(status: u16, errors: Option<Vec<CfError>>) -> ApiFailure {
    let messages = errors
        .unwrap_or_default()
        .into_iter()
        .map(|e| match (e.code, e.message) {
            (Some(c), Some(m)) => format!("[{c}] {m}"),
            (None, Some(m)) => m,
            (Some(c), None) => format!("error code {c}"),
            (None, None) => "unknown error".to_string(),
        })
        .collect();
    ApiFailure { status, messages }
}

/// Page count and item count from a listing. Without them a short page
/// looks like the end of the list, so a missing value is an error.
fn page_totals(info: Option<ResultInfo>) -> Result<(u32, u32), ApiFailure> {
    info.and_then(|info| Some((info.total_pages?, info.total_count?)))
        .ok_or_else(|| bad_upstream("Cloudflare response missing pagination info"))
}

async fn read_body(response: reqwest::Response) -> Result<String, ApiFailure> {
    let status = response.status().as_u16();
    let failure = |message: &str| ApiFailure {
        status,
        messages: vec![message.to_string()],
    };
    let body = read_limited(response, MAX_RESPONSE_BYTES)
        .await
        .map_err(|error| match error {
            BodyError::TooLarge => failure("Cloudflare response exceeds the 8 MiB limit"),
            BodyError::Read(_) => failure("cannot read Cloudflare response"),
        })?;
    String::from_utf8(body).map_err(|_| failure("Cloudflare response is not UTF-8"))
}

pub(crate) enum BodyError {
    TooLarge,
    Read(reqwest::Error),
}

/// Read a response body, giving up as soon as it would pass `max` bytes.
pub(crate) async fn read_limited(
    mut response: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, BodyError> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(BodyError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(BodyError::Read)? {
        if chunk.len() > max.saturating_sub(body.len()) {
            return Err(BodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub fn validate_identifier(id: &str) -> Result<(), ApiFailure> {
    if id.is_empty()
        || id.len() > MAX_IDENTIFIER_LEN
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
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn client(base: &str) -> CloudflareClient {
        let _ = rustls::crypto::ring::default_provider().install_default();
        CloudflareClient::new("synthetic-token", TIMEOUT, Some(base)).unwrap()
    }

    /// Answer one connection per body with HTTP 200 and return the request lines.
    async fn serve(bodies: Vec<String>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let (base, task) = serve_requests(bodies).await;
        let lines = tokio::spawn(async move {
            let requests = task.await.unwrap();
            requests.into_iter().map(|(line, _)| line).collect()
        });
        (base, lines)
    }

    /// Like `serve`, returning each request line with its body.
    async fn serve_requests(
        bodies: Vec<String>,
    ) -> (String, tokio::task::JoinHandle<Vec<(String, String)>>) {
        let responses = bodies
            .into_iter()
            .map(|body| {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            })
            .collect();
        serve_raw(responses).await
    }

    /// Answer one connection per raw HTTP response, written as given.
    async fn serve_raw(
        responses: Vec<String>,
    ) -> (String, tokio::task::JoinHandle<Vec<(String, String)>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                let end = loop {
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        break end + 4;
                    }
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0, "request headers were truncated");
                    request.extend_from_slice(&buffer[..count]);
                    assert!(request.len() <= 8192);
                };
                let head = String::from_utf8(request[..end].to_vec()).unwrap();
                let length: usize = head
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                // Read the whole body, so closing the socket cannot reset the reply.
                while request.len() < end + length {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0, "request body was truncated");
                    request.extend_from_slice(&buffer[..count]);
                }
                let line = head.lines().next().unwrap().to_string();
                let sent = String::from_utf8(request[end..].to_vec()).unwrap();
                requests.push((line, sent));
                // A client that rejects the reply early may close first.
                let _ = stream.write_all(response.as_bytes()).await;
            }
            requests
        });
        (base, task)
    }

    fn page(result: serde_json::Value, total_pages: u32, total_count: u32) -> String {
        json!({
            "success": true,
            "result": result,
            "result_info": {"page": 1, "per_page": 100, "total_pages": total_pages, "total_count": total_count},
        })
        .to_string()
    }

    fn record(id: &str, record_type: &str, name: &str) -> serde_json::Value {
        json!({"id": id, "type": record_type, "name": name, "content": "192.0.2.1"})
    }

    #[tokio::test]
    async fn missing_record_result_is_not_an_empty_zone() {
        let (base, task) = serve(vec![r#"{"success":true}"#.into()]).await;
        assert_eq!(
            client(&base)
                .list_records("synthetic-zone")
                .await
                .unwrap_err()
                .status,
            502
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn missing_zone_lookup_result_never_falls_back_to_parent() {
        let (base, task) = serve(vec![r#"{"success":true}"#.into()]).await;
        let error = client(&base)
            .zone_for_domain("sub.example.com")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("missing result"), "{error}");
        assert_eq!(task.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn duplicate_zone_names_fail_closed() {
        let body = json!({"success": true, "result": [
            {"id": "zone-one", "name": "example.com"},
            {"id": "zone-two", "name": "EXAMPLE.com"},
        ]});
        let (base, task) = serve(vec![body.to_string()]).await;
        let error = client(&base)
            .zone_for_domain("example.com")
            .await
            .unwrap_err();
        assert_eq!(error.status, 502);
        assert!(error.to_string().contains("more than one"), "{error}");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn record_listing_uses_a_documented_order_and_reads_every_page() {
        let (base, task) = serve(vec![
            page(json!([record("one", "A", "example.com")]), 2, 2),
            page(json!([record("two", "AAAA", "example.com")]), 2, 2),
        ])
        .await;
        let (records, total) = client(&base).list_records("synthetic-zone").await.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(total, 2);
        let lines = task.await.unwrap();
        assert!(
            lines[0].starts_with(
                "GET /zones/synthetic-zone/dns_records?order=type&direction=asc&per_page=100&page=1 "
            ),
            "{}",
            lines[0]
        );
        assert!(lines[1].contains("&page=2 "), "{}", lines[1]);
    }

    #[tokio::test]
    async fn listings_without_pagination_info_or_with_missing_items_fail() {
        let (base, task) = serve(vec![r#"{"success":true,"result":[]}"#.into()]).await;
        let error = client(&base).list_zones().await.unwrap_err();
        assert_eq!(error.status, 502);
        assert!(error.to_string().contains("pagination"), "{error}");
        task.await.unwrap();

        let (base, task) =
            serve(vec![page(json!([record("one", "A", "example.com")]), 1, 2)]).await;
        let error = client(&base)
            .list_records("synthetic-zone")
            .await
            .unwrap_err();
        assert_eq!(error.status, 502);
        assert!(error.to_string().contains("fewer"), "{error}");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn records_by_name_use_one_filtered_request() {
        let (base, task) = serve(vec![page(
            json!([
                record("one", "A", "example.com"),
                record("two", "AAAA", "example.com"),
                record("three", "A", "www.example.com"),
            ]),
            1,
            3,
        )])
        .await;
        let records = client(&base)
            .list_records_by_name("synthetic-zone", "A", "Example.com")
            .await
            .unwrap();
        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["one"]);
        let lines = task.await.unwrap();
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with(
                "GET /zones/synthetic-zone/dns_records?type=A&name.exact=Example.com&per_page=100 "
            ),
            "{}",
            lines[0]
        );
    }

    #[tokio::test]
    async fn records_by_name_fail_closed_when_the_listing_is_incomplete() {
        for body in [
            page(json!([record("one", "A", "example.com")]), 2, 101),
            json!({"success": true, "result": [record("one", "A", "example.com")]}).to_string(),
        ] {
            let (base, task) = serve(vec![body]).await;
            let error = client(&base)
                .list_records_by_name("synthetic-zone", "A", "example.com")
                .await
                .unwrap_err();
            assert_eq!(error.status, 502, "{error}");
            assert_eq!(task.await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn cloudflare_error_codes_are_kept_in_messages() {
        let body = r#"{"success":false,"errors":[{"code":81044,"message":"Record not found"}]}"#;
        let (base, task) = serve(vec![body.into(), body.into()]).await;
        let cf = client(&base);
        for error in [
            cf.list_zones().await.unwrap_err(),
            cf.list_records("synthetic-zone").await.unwrap_err(),
        ] {
            assert_eq!(error.to_string(), "[81044] Record not found");
        }
        task.await.unwrap();
    }

    #[tokio::test]
    async fn transport_errors_never_include_the_request_url() {
        let zone = "0123456789abcdef0123456789abcdef";
        let cf = client("http://127.0.0.1:1/client/v4");
        let errors = [
            cf.list_zones().await.unwrap_err(),
            cf.list_records(zone).await.unwrap_err(),
            cf.import_records(zone, "zone.txt", b"$TTL 300\n@ A 192.0.2.1\n".to_vec())
                .await
                .unwrap_err(),
            cf.zone_for_domain("example.com").await.unwrap_err(),
            cf.delete_record(zone, zone).await.unwrap_err(),
            cf.batch(zone, &deletes(&[zone])).await.unwrap_err(),
        ];
        for error in errors {
            let text = error.to_string();
            assert_eq!(error.status, 0, "{text}");
            assert!(text.starts_with("request to Cloudflare failed"), "{text}");
            for leaked in [zone, "127.0.0.1", "client/v4", "zones", "example.com"] {
                assert!(!text.contains(leaked), "{text}");
            }
        }
    }

    #[tokio::test]
    async fn missing_import_counts_are_not_a_successful_import() {
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
            let cf = client(&base);
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
        let cf = client("http://127.0.0.1:1");
        let too_long = "a".repeat(MAX_IDENTIFIER_LEN + 1);
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
            too_long.as_str(),
        ] {
            let error = cf.delete_record("synthetic-zone", id).await.unwrap_err();
            assert_eq!(
                error.status, 400,
                "unsafe identifier must fail before contacting upstream: {id:?}"
            );
            let error = cf.list_records(id).await.unwrap_err();
            assert_eq!(error.status, 400);
        }
        assert!(validate_identifier(&"a".repeat(MAX_IDENTIFIER_LEN)).is_ok());
    }

    #[tokio::test]
    async fn unsafe_multipart_filenames_are_rejected_before_network() {
        let cf = client("http://127.0.0.1:1");
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

    fn deletes(ids: &[&str]) -> BatchRequest {
        BatchRequest {
            deletes: ids
                .iter()
                .map(|id| BatchDelete { id: id.to_string() })
                .collect(),
            ..BatchRequest::default()
        }
    }

    fn patch(id: &str, patch: RecordPatch) -> BatchPatch {
        BatchPatch {
            id: id.to_string(),
            patch,
        }
    }

    #[test]
    fn batch_bodies_carry_ids_and_only_the_changed_fields() {
        assert_eq!(
            serde_json::to_value(deletes(&["one", "two"])).unwrap(),
            json!({"deletes": [{"id": "one"}, {"id": "two"}]})
        );
        let patches = BatchRequest {
            patches: vec![
                patch(
                    "one",
                    RecordPatch {
                        ttl: Some(600),
                        ..RecordPatch::default()
                    },
                ),
                patch(
                    "two",
                    RecordPatch {
                        proxied: Some(true),
                        ttl: Some(1),
                        comment: Some(String::new()),
                        tags: Some(vec!["test:batch".into()]),
                        content: None,
                    },
                ),
            ],
            ..BatchRequest::default()
        };
        assert_eq!(
            serde_json::to_value(&patches).unwrap(),
            json!({"patches": [
                {"id": "one", "ttl": 600},
                {"id": "two", "ttl": 1, "proxied": true, "comment": "", "tags": ["test:batch"]},
            ]})
        );
        assert_eq!(patches.ids().collect::<Vec<_>>(), ["one", "two"]);
    }

    #[tokio::test]
    async fn batch_posts_to_the_zone_batch_endpoint_and_keeps_error_codes() {
        let ok = json!({"success": true, "errors": [], "result": {"deletes": [{"id": "one"}]}});
        let failed = r#"{"success":false,"errors":[{"code":81044,"message":"Record not found"}]}"#;
        let (base, task) = serve_requests(vec![ok.to_string(), failed.into()]).await;
        let cf = client(&base);
        cf.batch("synthetic-zone", &deletes(&["one"]))
            .await
            .unwrap();
        let error = cf
            .batch("synthetic-zone", &deletes(&["two"]))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "[81044] Record not found");
        let requests = task.await.unwrap();
        for ((line, body), id) in requests.iter().zip(["one", "two"]) {
            assert!(
                line.starts_with("POST /zones/synthetic-zone/dns_records/batch "),
                "{line}"
            );
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(body, json!({"deletes": [{"id": id}]}));
        }
    }

    #[tokio::test]
    async fn batch_checks_every_identifier_and_its_size_before_network() {
        let cf = client("http://127.0.0.1:1");
        let full: Vec<String> = (0..=BATCH_LIMIT).map(|i| format!("r{i}")).collect();
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        let mut late_bad_patch = deletes(&["one", "two"]);
        late_bad_patch
            .patches
            .push(patch("record/other", RecordPatch::default()));
        for (zone, batch) in [
            ("../zones", deletes(&["one"])),
            ("synthetic-zone", deletes(&["one", "two", "a b"])),
            ("synthetic-zone", late_bad_patch),
            ("synthetic-zone", BatchRequest::default()),
            ("synthetic-zone", deletes(&full)),
        ] {
            let error = cf.batch(zone, &batch).await.unwrap_err();
            assert_eq!(error.status, 400, "{error}");
        }
        // A full batch passes the checks and fails only at the network.
        let error = cf
            .batch("synthetic-zone", &deletes(&full[..BATCH_LIMIT]))
            .await
            .unwrap_err();
        assert_eq!(error.status, 0, "{error}");
    }

    #[tokio::test]
    async fn batch_success_without_a_matching_result_is_an_unknown_outcome() {
        let mut sent = deletes(&["one", "two"]);
        sent.patches.push(patch(
            "three",
            RecordPatch {
                ttl: Some(600),
                ..RecordPatch::default()
            },
        ));
        let one = json!({"id": "one"});
        let two = json!({"id": "two"});
        let three = json!({"id": "three"});
        let replies = [
            json!({"success": true}),
            json!({"success": true, "result": null}),
            json!({"success": true, "result": {}}),
            json!({"success": true, "result": {"deletes": [one], "patches": [three]}}),
            json!({"success": true, "result": {"deletes": [one, two]}}),
            json!({"success": true, "result": {"deletes": [one, one], "patches": [three]}}),
            json!({"success": true, "result": {"deletes": [one, {"id": "other"}], "patches": [three]}}),
            json!({"success": true, "result": {"deletes": "one", "patches": [three]}}),
        ];
        // Full records, plus empty lists for other operations. The docs do not
        // promise an order, so a reply in a different order still confirms.
        let applied = json!({"success": true, "result": {
            "deletes": [{"id": "one", "type": "A"}, {"id": "two", "type": "A"}],
            "patches": [{"id": "three", "type": "A", "ttl": 600}],
            "puts": [], "posts": [],
        }});
        let reordered = json!({"success": true, "result": {
            "deletes": [{"id": "two", "type": "A"}, {"id": "one", "type": "A"}],
            "patches": [{"id": "three", "type": "A", "ttl": 600}],
        }});
        let bodies = replies
            .iter()
            .chain([&applied, &reordered])
            .map(|r| r.to_string());
        let (base, task) = serve_requests(bodies.collect()).await;
        let cf = client(&base);
        for reply in &replies {
            let error = cf.batch("synthetic-zone", &sent).await.unwrap_err();
            assert_eq!(error.status, 502, "{reply}: {error}");
            assert!(
                error.to_string().contains("outcome is unknown"),
                "{reply}: {error}"
            );
        }
        cf.batch("synthetic-zone", &sent).await.unwrap();
        cf.batch("synthetic-zone", &sent).await.unwrap();
        assert_eq!(task.await.unwrap().len(), replies.len() + 2);
    }

    #[tokio::test]
    async fn lost_or_unreadable_batch_replies_are_an_unknown_outcome() {
        let reply = |status: &str, body: &str| {
            format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let responses = vec![
            // The connection closes after the request was sent.
            String::new(),
            // Too large to read.
            "HTTP/1.1 200 OK\r\nContent-Length: 9999999999\r\nConnection: close\r\n\r\n{}".into(),
            // Cut off before the declared length.
            "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"success\":"
                .into(),
            reply("200 OK", "not json"),
            reply("200 OK", "{}"),
            reply("504 Gateway Timeout", "<html>timeout</html>"),
            reply("502 Bad Gateway", "{}"),
        ];
        let count = responses.len();
        let (base, task) = serve_raw(responses).await;
        let cf = client(&base);
        for _ in 0..count {
            let error = cf
                .batch("synthetic-zone", &deletes(&["one"]))
                .await
                .unwrap_err();
            let text = error.to_string();
            assert!(text.contains("outcome is unknown"), "{text}");
            for leaked in ["synthetic-zone", "127.0.0.1", "dns_records"] {
                assert!(!text.contains(leaked), "{text}");
            }
        }
        assert_eq!(task.await.unwrap().len(), count);
    }
}
