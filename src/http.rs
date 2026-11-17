//! A minimal, dependency-free HTTP/1.1 server built directly on tokio's
//! TcpListener - in the spirit of cloudflare-ddns: no web framework, no
//! runtime bloat, just enough HTTP to serve the GUI and its JSON API.

use crate::pp::{self, PP};
use std::collections::HashMap;
use std::future::Future;
use std::io::Write as _;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::{timeout, timeout_at, Duration, Instant};

const MAX_HEAD_SIZE: usize = 64 * 1024; // 64 KB request head
const MAX_BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MB (zone file imports)
const MAX_HEADER_LINE_SIZE: usize = 8 * 1024;
const MAX_HEADERS: usize = 100;
const MAX_CHUNK_METADATA_SIZE: usize = MAX_HEAD_SIZE;
const MAX_CONNECTIONS: usize = 16;
/// How long a kept-alive connection may wait for the first byte of its next request.
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);
/// Time for a whole request head and body, counted from its first byte.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Limits for the read-and-discard step in `linger_close`.
const LINGER_TIMEOUT: Duration = Duration::from_secs(1);
const LINGER_LIMIT: u64 = 64 * 1024;
/// How long shutdown waits for open connections. Docker sends SIGKILL 10
/// seconds after SIGTERM by default.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub remote: SocketAddr,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        let header = self.header("cookie")?;
        for part in header.split(';') {
            let part = part.trim();
            if let Some((n, v)) = part.split_once('=') {
                if n.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        serde_json::from_slice(&self.body).map_err(|e| format!("invalid JSON body: {e}"))
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Response {
            status,
            content_type: content_type.to_string(),
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn json<T: serde::Serialize>(status: u16, value: &T) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Response::new(status, "application/json; charset=utf-8", body)
    }

    pub fn json_error(status: u16, message: &str) -> Self {
        Response::json(status, &serde_json::json!({ "error": message }))
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// RFC 9112 allows an empty reason phrase, so unlisted codes get one.
    fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            408 => "Request Timeout",
            409 => "Conflict",
            413 => "Content Too Large",
            414 => "URI Too Long",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "",
        }
    }
}

/// The function `serve` calls for each request.
pub type Handler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

/// One buffer per connection, kept across requests so pipelined bytes stay
/// buffered.
type Conn = BufReader<TcpStream>;

/// Why a request could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadError {
    /// Reply with this status and error message, then close.
    Reject(u16, &'static str),
    /// The socket failed, so no reply can be sent.
    Io,
}

const TRUNCATED: ReadError = ReadError::Reject(400, "connection closed mid-request");
const TIMED_OUT: ReadError = ReadError::Reject(408, "request timeout");
const BODY_TOO_LARGE: ReadError = ReadError::Reject(413, "request body too large");
const CHUNK_METADATA_TOO_LARGE: ReadError = ReadError::Reject(413, "chunk metadata too large");
const REQUEST_LINE_TOO_LONG: ReadError = ReadError::Reject(414, "request line too long");
const HEADERS_TOO_LARGE: ReadError = ReadError::Reject(431, "request headers too large");
const UNSUPPORTED_ENCODING: ReadError = ReadError::Reject(501, "unsupported Transfer-Encoding");

fn invalid(message: &'static str) -> ReadError {
    ReadError::Reject(400, message)
}

impl From<std::io::Error> for ReadError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            TRUNCATED
        } else {
            ReadError::Io
        }
    }
}

/// How the request body is delimited.
enum Framing {
    Length(usize),
    Chunked,
}

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    framing: Framing,
    expect_continue: bool,
}

/// How `read_line` stopped.
enum Line {
    Complete,
    TooLong,
    Eof,
}

/// Percent-decode a URL component (path or query value). `+` stands for a
/// space only in query strings, where HTML forms use it.
fn url_decode(input: &str, plus_is_space: bool) -> String {
    let hex = |byte: Option<&u8>| {
        byte.and_then(|&byte| char::from(byte).to_digit(16))
            .and_then(|digit| u8::try_from(digit).ok())
    };
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'%' {
            if let (Some(high), Some(low)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
                out.push(high * 16 + low);
                i += 3;
                continue;
            }
        }
        out.push(if plus_is_space && byte == b'+' {
            b' '
        } else {
            byte
        });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(url_decode(key, true), url_decode(value, true));
    }
    map
}

/// Runs one I/O step against the request deadline.
async fn with_deadline<T>(
    deadline: Instant,
    step: impl Future<Output = std::io::Result<T>>,
) -> Result<T, ReadError> {
    match timeout_at(deadline, step).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(TIMED_OUT),
    }
}

/// Reads one line, including its `\n`, into `line` without reading more than
/// `limit` bytes.
async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    limit: usize,
    deadline: Instant,
) -> Result<Line, ReadError> {
    line.clear();
    let mut limited = (&mut *reader).take(limit as u64);
    with_deadline(deadline, limited.read_until(b'\n', line)).await?;
    Ok(if line.ends_with(b"\n") {
        Line::Complete
    } else if line.len() == limit {
        Line::TooLong
    } else {
        Line::Eof
    })
}

/// Reads the request line and header lines, each with its CRLF, through the
/// blank line that ends the head. Returns Ok(None) when the connection closes
/// before the first byte.
async fn read_head<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, ReadError> {
    let mut head = Vec::new();
    let mut line = Vec::new();
    loop {
        let limit = MAX_HEAD_SIZE
            .saturating_sub(head.len())
            .min(MAX_HEADER_LINE_SIZE + 2);
        match read_line(reader, &mut line, limit, deadline).await? {
            Line::Complete => {}
            Line::TooLong if head.is_empty() => return Err(REQUEST_LINE_TOO_LONG),
            Line::TooLong => return Err(HEADERS_TOO_LARGE),
            Line::Eof if head.is_empty() && line.is_empty() => return Ok(None),
            Line::Eof => return Err(TRUNCATED),
        }
        if !line.ends_with(b"\r\n") {
            return Err(invalid("request head lines must end with CRLF"));
        }
        head.extend_from_slice(&line);
        if line == b"\r\n" {
            return Ok(Some(head));
        }
    }
}

fn parse_head(head: &[u8]) -> Result<Head, ReadError> {
    let is_token = |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte);
    let head = head
        .strip_suffix(b"\r\n\r\n")
        .ok_or(invalid("malformed request line"))?;
    let head = std::str::from_utf8(head).map_err(|_| invalid("invalid request head encoding"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    // HTTP/1.1 and origin-form targets only. RFC 9112 §3.2.2 says servers
    // must also accept absolute-form; the README documents this deviation.
    if method.is_empty()
        || !method.bytes().all(is_token)
        || !target.starts_with('/')
        || !target
            .bytes()
            .all(|byte| (b'!'..=b'~').contains(&byte) && byte != b'#')
        || version != "HTTP/1.1"
        || parts.next().is_some()
    {
        return Err(invalid("malformed request line"));
    }

    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(HEADERS_TOO_LARGE);
        }
        let (name, value) = line.split_once(':').ok_or(invalid("malformed header"))?;
        if name.is_empty()
            || !name.bytes().all(is_token)
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(invalid("malformed header"));
        }
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_string(),
        ));
    }
    let mut hosts = headers.iter().filter(|(name, _)| name == "host");
    let host = hosts.next().ok_or(invalid("missing Host header"))?;
    if hosts.next().is_some()
        || host.1.is_empty()
        || !host
            .1
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b",/?#@\\".contains(&byte))
    {
        return Err(invalid("invalid Host header"));
    }
    let mut lengths = headers.iter().filter(|(name, _)| name == "content-length");
    let content_length = lengths.next();
    let mut encodings = headers
        .iter()
        .filter(|(name, _)| name == "transfer-encoding");
    let transfer_encoding = encodings.next();
    if lengths.next().is_some()
        || encodings.next().is_some()
        || (content_length.is_some() && transfer_encoding.is_some())
    {
        return Err(invalid("ambiguous request framing"));
    }
    let framing = match (content_length, transfer_encoding) {
        (Some((_, value)), _) => {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid("invalid Content-Length"));
            }
            let length = value
                .parse::<usize>()
                .map_err(|_| invalid("invalid Content-Length"))?;
            if length > MAX_BODY_SIZE {
                return Err(BODY_TOO_LARGE);
            }
            Framing::Length(length)
        }
        (None, Some((_, value))) => {
            check_transfer_encoding(value)?;
            Framing::Chunked
        }
        (None, None) => Framing::Length(0),
    };
    let expect_continue = headers
        .iter()
        .any(|(name, value)| name == "expect" && value.eq_ignore_ascii_case("100-continue"));
    Ok(Head {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        framing,
        expect_continue,
    })
}

/// Accepts `chunked` alone. A list that breaks the framing rules gets 400;
/// a coding this server does not implement gets 501 (RFC 9112 §6.1).
fn check_transfer_encoding(value: &str) -> Result<(), ReadError> {
    let mut codings = value
        .split(',')
        .map(|coding| coding.trim_matches([' ', '\t']));
    let last = codings.next_back().unwrap_or_default();
    // RFC 9112 §6.3: chunked must be the final coding and appear only once.
    if last.is_empty()
        || codings
            .clone()
            .any(|coding| coding.is_empty() || coding.eq_ignore_ascii_case("chunked"))
    {
        return Err(invalid("invalid Transfer-Encoding"));
    }
    if !last.eq_ignore_ascii_case("chunked") || codings.next().is_some() {
        return Err(UNSUPPORTED_ENCODING);
    }
    Ok(())
}

/// Appends exactly `length` bytes to `body`. Capacity grows only as bytes
/// arrive, so a client that declares a large body and then sends nothing
/// cannot make the server reserve that memory.
async fn read_body<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    body: &mut Vec<u8>,
    length: usize,
    deadline: Instant,
) -> Result<(), ReadError> {
    let mut remaining = length;
    while remaining > 0 {
        let available = with_deadline(deadline, reader.fill_buf()).await?;
        if available.is_empty() {
            return Err(TRUNCATED);
        }
        let received = available.len().min(remaining);
        let required = body.len().saturating_add(received);
        if required > body.capacity() {
            let target = required
                .checked_next_power_of_two()
                .map_or(required, |size| size.min(MAX_BODY_SIZE))
                .max(required);
            body.reserve_exact(target - body.len());
        }
        body.extend_from_slice(&available[..received]);
        reader.consume(received);
        remaining -= received;
    }
    Ok(())
}

async fn read_crlf<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    deadline: Instant,
    message: &'static str,
) -> Result<(), ReadError> {
    let mut crlf = [0; 2];
    with_deadline(deadline, reader.read_exact(&mut crlf)).await?;
    if crlf == *b"\r\n" {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

/// Parses a chunk-size line, CRLF included. Chunk extensions are ignored.
fn parse_chunk_size(line: &[u8]) -> Result<usize, ReadError> {
    let line = line
        .strip_suffix(b"\r\n")
        .ok_or(invalid("invalid chunk size CRLF"))?;
    if line
        .iter()
        .any(|&byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err(invalid("invalid control byte in chunk size"));
    }
    let digits = line.split(|&byte| byte == b';').next().unwrap_or_default();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid("invalid chunk size"));
    }
    std::str::from_utf8(digits)
        .ok()
        .and_then(|digits| usize::from_str_radix(digits, 16).ok())
        .ok_or(invalid("invalid chunk size"))
}

/// Decodes a chunked body. Trailer fields are not supported.
async fn read_chunked<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    deadline: Instant,
) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::new();
    let mut line = Vec::new();
    // Chunk-size lines and CRLFs do not count toward MAX_BODY_SIZE, so they
    // get their own budget.
    let mut metadata_size = 0;
    loop {
        let limit = MAX_CHUNK_METADATA_SIZE
            .saturating_sub(metadata_size)
            .min(MAX_HEADER_LINE_SIZE);
        match read_line(reader, &mut line, limit, deadline).await? {
            Line::Complete => {}
            Line::TooLong => return Err(CHUNK_METADATA_TOO_LARGE),
            Line::Eof => return Err(TRUNCATED),
        }
        metadata_size += line.len();
        let size = parse_chunk_size(&line)?;
        if size == 0 {
            break;
        }
        if size > MAX_BODY_SIZE.saturating_sub(body.len()) {
            return Err(BODY_TOO_LARGE);
        }
        read_body(reader, &mut body, size, deadline).await?;
        read_crlf(reader, deadline, "invalid chunk data CRLF").await?;
        metadata_size += 2;
        if metadata_size > MAX_CHUNK_METADATA_SIZE {
            return Err(CHUNK_METADATA_TOO_LARGE);
        }
    }
    // The last chunk is followed by an empty trailer section.
    read_crlf(reader, deadline, "invalid chunk terminator CRLF").await?;
    if metadata_size + 2 > MAX_CHUNK_METADATA_SIZE {
        return Err(CHUNK_METADATA_TOO_LARGE);
    }
    Ok(body)
}

/// Reads one request. The request deadline starts here, so the caller waits
/// for the first byte before calling. Returns Ok(None) when the connection
/// closes before the first byte.
async fn read_request(stream: &mut Conn, remote: SocketAddr) -> Result<Option<Request>, ReadError> {
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let Some(head) = read_head(stream, deadline).await? else {
        return Ok(None);
    };
    let head = parse_head(&head)?;
    let has_body = !matches!(head.framing, Framing::Length(0));
    if head.expect_continue && has_body {
        // The client may hold the body back until it sees this (RFC 9110 §10.1.1).
        with_deadline(deadline, stream.get_mut().write_all(CONTINUE)).await?;
    }
    let body = match head.framing {
        Framing::Length(length) => {
            let mut body = Vec::new();
            read_body(stream, &mut body, length, deadline).await?;
            body
        }
        Framing::Chunked => read_chunked(stream, deadline).await?,
    };
    let (path, query) = match head.target.split_once('?') {
        Some((path, query)) => (path, parse_query(query)),
        None => (head.target.as_str(), HashMap::new()),
    };
    Ok(Some(Request {
        method: head.method,
        path: url_decode(path, false),
        query,
        headers: head.headers,
        body,
        remote,
    }))
}

/// Formats seconds since the Unix epoch as an IMF-fixdate (RFC 9110 §5.6.7),
/// such as `Sun, 06 Nov 1994 08:49:37 GMT`.
struct HttpDate(u64);

impl std::fmt::Display for HttpDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let days = self.0 / 86_400;
        let seconds = self.0 % 86_400;
        // Howard Hinnant's civil_from_days. Years are counted from March so
        // the leap day falls at the end; an era is 400 years.
        let shifted = days + 719_468;
        let era = shifted / 146_097;
        let day_of_era = shifted % 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_from_march = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
        let month = (month_from_march + 2) % 12;
        let year = era * 400 + year_of_era + u64::from(month < 2);
        write!(
            f,
            "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
            WEEKDAYS[(days % 7) as usize],
            MONTHS[month as usize],
            seconds / 3_600,
            seconds / 60 % 60,
            seconds % 60
        )
    }
}

/// Serializes a response. A HEAD response keeps the GET headers, including
/// Content-Length, and leaves out the body.
fn write_response(resp: &Response, head_only: bool, close: bool) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let mut out = Vec::with_capacity(resp.body.len().saturating_add(512));
    // Writes into a Vec cannot fail.
    let _ = write!(
        out,
        "HTTP/1.1 {} {}\r\nDate: {}\r\nContent-Type: {}\r\n",
        resp.status,
        Response::status_text(resp.status),
        HttpDate(now),
        resp.content_type
    );
    // A 204 response has no content and no Content-Length (RFC 9110 §8.6).
    let has_body = resp.status != 204;
    if has_body {
        let _ = write!(out, "Content-Length: {}\r\n", resp.body.len());
    }
    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    for (name, value) in &resp.headers {
        if !name.eq_ignore_ascii_case("connection") {
            let _ = write!(out, "{name}: {value}\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    if has_body && !head_only {
        out.extend_from_slice(&resp.body);
    }
    out
}

/// True when a Connection header lists the `close` option.
fn wants_close(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"))
    })
}

async fn send(stream: &mut Conn, bytes: &[u8]) -> bool {
    matches!(
        timeout(WRITE_TIMEOUT, stream.get_mut().write_all(bytes)).await,
        Ok(Ok(()))
    )
}

/// Closes the write side, then reads and drops input for a short while.
/// Closing a socket that still has unread input makes the kernel send a
/// reset, which can destroy a response the client has not read yet
/// (RFC 9112 §9.6).
async fn linger_close(stream: &mut Conn) {
    if stream.get_mut().shutdown().await.is_err() {
        return;
    }
    let mut rest = (&mut *stream).take(LINGER_LIMIT);
    let _ = timeout(
        LINGER_TIMEOUT,
        tokio::io::copy_buf(&mut rest, &mut tokio::io::sink()),
    )
    .await;
}

async fn handle_connection(
    stream: TcpStream,
    remote: SocketAddr,
    handler: Handler,
    mut shutdown: watch::Receiver<bool>,
) {
    let _ = stream.set_nodelay(true);
    let mut stream = BufReader::new(stream);
    loop {
        // Between requests the connection closes without a reply on EOF, on
        // the idle timeout or when the server shuts down.
        let ready = tokio::select! {
            biased;
            _ = shutdown.wait_for(|stopping| *stopping) => false,
            ready = timeout(IDLE_TIMEOUT, stream.fill_buf()) => {
                matches!(ready, Ok(Ok(bytes)) if !bytes.is_empty())
            }
        };
        if !ready {
            return;
        }
        let mut req = match read_request(&mut stream, remote).await {
            Ok(Some(req)) => req,
            Ok(None) | Err(ReadError::Io) => return,
            Err(ReadError::Reject(status, message)) => {
                let response = Response::json_error(status, message);
                if send(&mut stream, &write_response(&response, false, true)).await {
                    linger_close(&mut stream).await;
                }
                return;
            }
        };
        // HEAD must work wherever GET does (RFC 9110 §9.1), so the handler
        // only ever sees GET.
        let head_only = req.method == "HEAD";
        if head_only {
            req.method = String::from("GET");
        }
        let close_requested = wants_close(&req.headers);
        let resp = handler(req).await;
        let close = close_requested || wants_close(&resp.headers) || *shutdown.borrow();
        if !send(&mut stream, &write_response(&resp, head_only, close)).await {
            return;
        }
        if close {
            linger_close(&mut stream).await;
            return;
        }
    }
}

/// Answers a connection over MAX_CONNECTIONS with 503 and drops it. Nothing
/// here waits, so a flood of connections cannot stall the accept loop.
fn refuse(stream: TcpStream) {
    let response =
        Response::json_error(503, "too many open connections").header("Retry-After", "1");
    let _ = stream.try_write(&write_response(&response, false, true));
    // Discard input that has already arrived. Closing a socket with unread
    // input sends a reset, which can destroy the reply.
    let mut discard = [0; 4096];
    for _ in 0..16 {
        if !matches!(stream.try_read(&mut discard), Ok(read) if read > 0) {
            break;
        }
    }
}

/// True when a message last logged at `last` may be logged again at `now`.
fn log_due(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|last| now.saturating_duration_since(last) >= REFUSAL_LOG_INTERVAL)
}

/// Serve on a pre-bound listener until `shutdown` resolves. Then stop
/// accepting, give open connections up to SHUTDOWN_GRACE to finish, and
/// abort the rest.
pub async fn serve(
    listener: TcpListener,
    handler: Handler,
    shutdown: impl Future<Output = ()>,
    log: PP,
) {
    let (stop, stopping) = watch::channel(false);
    let mut connections = tokio::task::JoinSet::new();
    let mut last_refusal_log = None;
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, remote)) => {
                        while connections.try_join_next().is_some() {}
                        if connections.len() < MAX_CONNECTIONS {
                            connections.spawn(handle_connection(
                                stream,
                                remote,
                                handler.clone(),
                                stopping.clone(),
                            ));
                        } else {
                            refuse(stream);
                            let now = Instant::now();
                            if log_due(last_refusal_log, now) {
                                last_refusal_log = Some(now);
                                log.warningf(
                                    pp::EMOJI_WARNING,
                                    format_args!(
                                        "{MAX_CONNECTIONS} connections are open; refusing new ones with 503"
                                    ),
                                );
                            }
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
            () = &mut shutdown => break,
        }
    }
    drop(listener);
    let _ = stop.send(true);
    let _ = timeout(SHUTDOWN_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() -> PP {
        PP::new(false, true)
    }

    fn status(result: Result<Option<Request>, ReadError>) -> Option<u16> {
        match result {
            Err(ReadError::Reject(status, _)) => Some(status),
            _ => None,
        }
    }

    fn reply(status: u16, body: &'static str) -> Handler {
        Arc::new(move |_| Box::pin(async move { Response::new(status, "text/plain", body) }))
    }

    async fn parse_wire(wire: Vec<u8>) -> Result<Option<Request>, ReadError> {
        timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let writer = tokio::spawn(async move {
                let _ = client.write_all(&wire).await;
                let _ = client.shutdown().await;
            });
            let (stream, remote) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let result = read_request(&mut stream, remote).await;
            drop(stream);
            writer.await.unwrap();
            result
        })
        .await
        .expect("loopback parser test timed out")
    }

    /// Connects a client to a `handle_connection` task. Keep the returned
    /// sender alive: dropping it reads as a shutdown.
    async fn connect(
        handler: Handler,
    ) -> (TcpStream, tokio::task::JoinHandle<()>, watch::Sender<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, remote) = listener.accept().await.unwrap();
        let (stop, stopping) = watch::channel(false);
        let server = tokio::spawn(handle_connection(stream, remote, handler, stopping));
        (client, server, stop)
    }

    /// Reads one response with a Content-Length body.
    async fn read_response(client: &mut TcpStream) -> String {
        let mut out = Vec::new();
        let mut byte = [0];
        while !out.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).await.unwrap();
            out.push(byte[0]);
        }
        let head = String::from_utf8(out.clone()).unwrap();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .map_or(0, |value| value.parse().unwrap());
        let mut body = vec![0; length];
        client.read_exact(&mut body).await.unwrap();
        out.extend(body);
        String::from_utf8(out).unwrap()
    }

    async fn start_server(
        handler: Handler,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (trigger, triggered) = tokio::sync::oneshot::channel::<()>();
        let shutdown = async move {
            let _ = triggered.await;
        };
        let server = tokio::spawn(serve(listener, handler, shutdown, quiet()));
        (address, server, trigger)
    }

    #[tokio::test]
    async fn framing_rejects_duplicate_or_conflicting_lengths() {
        for headers in [
            "Content-Length: 1\r\nContent-Length: 1",
            "Content-Length: 1\r\ncOnTeNt-LeNgTh: 2",
            "Content-Length: 1, 1",
            "Content-Length: 1, 2",
            "Content-Length: 0\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\nContent-Length: 0",
        ] {
            let wire =
                format!("POST /test HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n\r\n0\r\n\r\n");
            assert_eq!(
                status(parse_wire(wire.into_bytes()).await),
                Some(400),
                "{headers}"
            );
        }
    }

    #[tokio::test]
    async fn framing_rejects_invalid_content_lengths() {
        for length in [
            "",
            "garbage",
            "+1",
            "-1",
            "1 0",
            "0x1",
            "184467440737095516160",
        ] {
            let wire = format!(
                "POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\n\r\na"
            );
            assert_eq!(
                status(parse_wire(wire.into_bytes()).await),
                Some(400),
                "{length:?}"
            );
        }
    }

    #[tokio::test]
    async fn framing_rejects_unsupported_or_duplicate_transfer_codings() {
        for (encoding, expected) in [
            ("gzip", 501),
            ("identity", 501),
            ("xchunked", 501),
            ("chunkedx", 501),
            ("gzip, chunked", 501),
            ("chunked;name=value", 501),
            ("chunked, gzip", 400),
            ("chunked, chunked", 400),
            (", chunked", 400),
            ("", 400),
            ("chunked\r\nTransfer-Encoding: chunked", 400),
        ] {
            let wire = format!("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: {encoding}\r\n\r\n0\r\n\r\n");
            assert_eq!(
                status(parse_wire(wire.into_bytes()).await),
                Some(expected),
                "{encoding:?}"
            );
        }
    }

    #[tokio::test]
    async fn framing_rejects_malformed_request_lines_and_headers() {
        for head in [
            "GET /test\r\nHost: localhost",
            "GET /test HTTP/1.1 extra\r\nHost: localhost",
            "GET /test HTTP/1.0\r\nHost: localhost",
            "GET\t/test HTTP/1.1\r\nHost: localhost",
            "GET  /test HTTP/1.1\r\nHost: localhost",
            "G@T /test HTTP/1.1\r\nHost: localhost",
            "GET example.com HTTP/1.1\r\nHost: localhost",
            "GET http://localhost/test HTTP/1.1\r\nHost: localhost",
            "GET /test#fragment HTTP/1.1\r\nHost: localhost",
            "GET /test HTTP/1.1",
            "GET /test HTTP/1.1\r\nHost:",
            "GET /test HTTP/1.1\r\nHost: localhost\r\nHost: localhost",
            "GET /test HTTP/1.1\r\nHost : localhost",
            "GET /test HTTP/1.1\r\n Host: localhost",
            "GET /test HTTP/1.1\r\nHost: localhost\r\nmalformed",
            "GET /test HTTP/1.1\r\nHost: localhost\r\n: value",
            "GET /test HTTP/1.1\r\nHost: localhost\r\nBad(Name: value",
            "GET /test HTTP/1.1\r\nHost: localhost\r\nX-Test: value\nInjected: value",
            "GET /test HTTP/1.1\r\nHost: localhost\r\nX-Test: value\rInjected: value",
            "GET /test HTTP/1.1\r\nHost: localhost\r\nX-Test: \0",
            "GET /test HTTP/1.1\r\nHost: localhost\r\nX-Test: \u{7f}",
            "\r\nGET /test HTTP/1.1\r\nHost: localhost",
        ] {
            let result = parse_wire(format!("{head}\r\n\r\n").into_bytes()).await;
            assert_eq!(status(result), Some(400), "{head:?}");
        }
        let result =
            parse_wire(b"GET /test HTTP/1.1\r\nHost: localhost\r\nX-Test: \xff\r\n\r\n".to_vec())
                .await;
        assert_eq!(status(result), Some(400));
    }

    #[tokio::test]
    async fn framing_bounds_request_line_header_fields_and_chunk_metadata() {
        let heads = [
            (
                format!(
                    "GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: {}\r\n\r\n",
                    "a".repeat(8192)
                ),
                431,
            ),
            (
                format!(
                    "GET / HTTP/1.1\r\nHost: localhost\r\n{}\r\n",
                    "X-Test: a\r\n".repeat(101)
                ),
                431,
            ),
            (
                format!(
                    "GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: {}\r\n\r\n",
                    "a".repeat(MAX_HEAD_SIZE)
                ),
                431,
            ),
            (
                format!(
                    "GET /{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    "a".repeat(MAX_HEADER_LINE_SIZE)
                ),
                414,
            ),
        ];
        for (head, expected) in heads {
            assert_eq!(status(parse_wire(head.into_bytes()).await), Some(expected));
        }
        let bodies = [
            format!("0;name={}\r\n\r\n", "a".repeat(8192)),
            format!("{}0\r\n\r\n", "1\r\na\r\n".repeat(MAX_HEAD_SIZE / 5 + 1)),
        ];
        for body in bodies {
            let wire = format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n{body}"
            );
            assert_eq!(
                parse_wire(wire.into_bytes()).await.unwrap_err(),
                CHUNK_METADATA_TOO_LARGE
            );
        }
    }

    #[tokio::test]
    async fn framing_truncation_never_becomes_a_request() {
        for wire in [
            "GET / HTTP/1.1\r\nHost: localhost\r\n",
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nabc",
            "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
            "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r",
            "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            let error = parse_wire(wire.as_bytes().to_vec()).await.expect_err(wire);
            assert_eq!(error, TRUNCATED);
        }
        assert!(parse_wire(Vec::new()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn framing_valid_bodies_leave_pipelined_requests_intact() {
        for framing in [
            "Content-Length: 4\r\n\r\ntest",
            "Transfer-Encoding: ChUnKeD\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            client.write_all(format!("POST /first HTTP/1.1\r\nHost: localhost\r\n{framing}GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();
            let (stream, remote) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let first = read_request(&mut stream, remote).await.unwrap().unwrap();
            assert_eq!(first.body, b"test");
            let second = read_request(&mut stream, remote).await.unwrap().unwrap();
            assert_eq!(second.path, "/second");
            assert!(read_request(&mut stream, remote).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn framing_accepts_ows_and_limit_boundaries() {
        let wire = format!(
            "POST /test?q=synthetic HTTP/1.1\r\nHost: [::1]:8080\r\nContent-Length:\t0004 \t\r\nX-Test: {}\r\n\r\ntest",
            "a".repeat(MAX_HEADER_LINE_SIZE - "X-Test: ".len())
        );
        let request = parse_wire(wire.into_bytes()).await.unwrap().unwrap();
        assert_eq!(request.body, b"test");
        assert_eq!(request.query.get("q").unwrap(), "synthetic");
        let wire = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\n{}\r\n",
            "X-Test: a\r\n".repeat(MAX_HEADERS - 1)
        );
        assert_eq!(
            parse_wire(wire.into_bytes())
                .await
                .unwrap()
                .unwrap()
                .headers
                .len(),
            MAX_HEADERS
        );
        let target = format!(
            "/{}",
            "a".repeat(MAX_HEADER_LINE_SIZE - "GET / HTTP/1.1".len())
        );
        let wire = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(
            parse_wire(wire.into_bytes()).await.unwrap().unwrap().path,
            target
        );
        let wire = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_SIZE + 1
        );
        assert_eq!(
            parse_wire(wire.into_bytes()).await.unwrap_err(),
            BODY_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn path_keeps_plus_and_query_decodes_it_as_space() {
        let wire = b"GET /a+b%20c?q=a+b%2Bc&flag HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec();
        let request = parse_wire(wire).await.unwrap().unwrap();
        assert_eq!(request.path, "/a+b c");
        assert_eq!(request.query.get("q").unwrap(), "a b+c");
        assert_eq!(request.query.get("flag").unwrap(), "");
        assert_eq!(url_decode("%4", false), "%4");
        assert_eq!(url_decode("%zz%41", false), "%zzA");
    }

    #[tokio::test]
    async fn framing_body_allocation_tracks_received_bytes_and_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut body = Vec::new();
        let error = read_body(
            &mut BufReader::new(stream),
            &mut body,
            MAX_BODY_SIZE,
            Instant::now() + Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert_eq!(error, TIMED_OUT);
        assert_eq!(body.capacity(), 0);
        let mut wire = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {MAX_BODY_SIZE}\r\n\r\n"
        )
        .into_bytes();
        wire.resize(wire.len() + MAX_BODY_SIZE, b'a');
        let request = parse_wire(wire).await.unwrap().unwrap();
        assert_eq!(request.body.len(), MAX_BODY_SIZE);
        assert!(request.body.capacity() <= MAX_BODY_SIZE);
    }

    #[tokio::test]
    async fn framing_ambiguous_pipeline_never_reaches_the_handler() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let handler: Handler = Arc::new(move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Response::new(200, "text/plain", "synthetic") })
        });
        let (mut client, server, _stop) = connect(handler).await;
        client.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /second HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn framing_errors_report_status_and_close_before_dispatch() {
        for (wire, expected) in [
            (
                "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: garbage\r\n\r\n".to_string(),
                "400 Bad Request",
            ),
            (
                format!(
                    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
                    MAX_BODY_SIZE + 1
                ),
                "413 Content Too Large",
            ),
            (
                format!(
                    "GET /{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    "a".repeat(MAX_HEADER_LINE_SIZE)
                ),
                "414 URI Too Long",
            ),
            (
                format!(
                    "GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: {}\r\n\r\n",
                    "a".repeat(MAX_HEADER_LINE_SIZE)
                ),
                "431 Request Header Fields Too Large",
            ),
            (
                "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n".to_string(),
                "501 Not Implemented",
            ),
        ] {
            let handler: Handler = Arc::new(|_| panic!("invalid request reached handler"));
            let (mut client, server, _stop) = connect(handler).await;
            // Input the server never reads would make a plain close send a
            // reset and destroy the error response.
            let mut wire = wire.into_bytes();
            wire.resize(wire.len() + 16 * 1024, b'x');
            client.write_all(&wire).await.unwrap();
            let mut output = Vec::new();
            timeout(Duration::from_secs(2), client.read_to_end(&mut output))
                .await
                .unwrap()
                .expect("error response was reset before the client read it");
            drop(client);
            server.await.unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(
                output.starts_with(&format!("HTTP/1.1 {expected}\r\n")),
                "{output}"
            );
            assert!(output.contains("Connection: close\r\n"), "{output}");
        }
    }

    #[tokio::test]
    async fn framing_connection_close_token_is_honored_on_the_wire() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let handler: Handler = Arc::new(move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Response::new(200, "text/plain", "synthetic") })
        });
        let (mut client, server, _stop) = connect(handler).await;
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, CLOSE\r\n\r\nGET /second HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        let mut output = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut output))
            .await
            .unwrap()
            .expect("response was reset before the client read it");
        server.await.unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(output.contains("Connection: close\r\n"), "{output}");
        assert!(output.ends_with("\r\n\r\nsynthetic"), "{output}");
    }

    #[tokio::test]
    async fn framing_trickle_cannot_reset_the_request_deadline() {
        let mut cases = Vec::new();
        for (prefix, next) in [
            ("G", "E"),
            ("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n", "\r\na"),
            ("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1", ";name=value"),
            ("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n", "1\r\nb\r\n"),
        ] {
            cases.push(tokio::spawn(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
                client.write_all(prefix.as_bytes()).await.unwrap();
                let writer = tokio::spawn(async move {
                    tokio::time::sleep(REQUEST_TIMEOUT / 2).await;
                    client.write_all(next.as_bytes()).await.unwrap();
                    tokio::time::sleep(REQUEST_TIMEOUT).await;
                });
                let (stream, remote) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let result = timeout(REQUEST_TIMEOUT + Duration::from_millis(500), read_request(&mut stream, remote)).await;
                writer.abort();
                let error = result.expect("trickle extended the total request deadline").unwrap_err();
                assert_eq!(error, TIMED_OUT, "{prefix:?}");
            }));
        }
        for case in cases {
            case.await.unwrap();
        }
    }

    #[tokio::test]
    async fn idle_keep_alive_connection_closes_after_the_idle_timeout() {
        let (mut client, server, _stop) = connect(reply(200, "synthetic")).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(!response.contains("Connection:"), "{response}");
        let idle = Instant::now();
        let mut rest = Vec::new();
        timeout(
            IDLE_TIMEOUT + Duration::from_secs(2),
            client.read_to_end(&mut rest),
        )
        .await
        .expect("idle connection stayed open")
        .unwrap();
        assert!(rest.is_empty(), "idle close sent a response");
        let elapsed = idle.elapsed();
        assert!(
            elapsed >= IDLE_TIMEOUT - Duration::from_millis(100),
            "{elapsed:?}"
        );
        assert!(
            elapsed < IDLE_TIMEOUT + Duration::from_secs(1),
            "{elapsed:?}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn request_deadline_starts_at_the_first_byte() {
        let (mut client, server, _stop) = connect(reply(200, "synthetic")).await;
        // The first byte comes just inside the idle timeout, and the rest
        // comes after REQUEST_TIMEOUT has passed since the connection opened
        // but before it has passed since that first byte.
        tokio::time::sleep(IDLE_TIMEOUT - Duration::from_secs(1)).await;
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        tokio::time::sleep(REQUEST_TIMEOUT - Duration::from_secs(2)).await;
        client
            .write_all(b"Host: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut output = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with("HTTP/1.1 200 OK\r\n"), "{output}");
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn head_requests_are_served_as_get_without_a_body() {
        let methods = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = methods.clone();
        let handler: Handler = Arc::new(move |req: Request| {
            let status = if req.method == "GET" { 200 } else { 404 };
            seen.lock().unwrap().push(req.method);
            Box::pin(async move { Response::new(status, "text/plain", "synthetic") })
        });
        let (mut client, server, _stop) = connect(handler).await;
        client
            .write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut output = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();
        let output = String::from_utf8(output).unwrap();
        let (head, get) = output.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{output}");
        assert!(head.contains("\r\nContent-Length: 9"), "{output}");
        assert!(
            get.starts_with("HTTP/1.1 200 OK\r\n"),
            "HEAD sent a body: {output}"
        );
        assert!(get.ends_with("\r\n\r\nsynthetic"), "{output}");
        assert_eq!(*methods.lock().unwrap(), ["GET", "GET"]);
    }

    #[tokio::test]
    async fn expect_continue_is_answered_before_the_body_is_read() {
        let handler: Handler = Arc::new(|req: Request| {
            Box::pin(async move { Response::new(200, "text/plain", req.body) })
        });
        let (mut client, server, _stop) = connect(handler).await;
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n")
            .await
            .unwrap();
        let mut interim = vec![0; CONTINUE.len()];
        timeout(Duration::from_secs(2), client.read_exact(&mut interim))
            .await
            .expect("server waited for the body before sending 100 Continue")
            .unwrap();
        assert_eq!(interim, CONTINUE);
        client.write_all(b"test").await.unwrap();
        let response = read_response(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.ends_with("\r\n\r\ntest"), "{response}");
        // No interim response without a body or when the body is refused.
        for (wire, expected) in [
            (
                "GET / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n\r\n".to_string(),
                "HTTP/1.1 200 OK\r\n",
            ),
            (
                format!("POST / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n", MAX_BODY_SIZE + 1),
                "HTTP/1.1 413 Content Too Large\r\n",
            ),
        ] {
            client.write_all(wire.as_bytes()).await.unwrap();
            let response = read_response(&mut client).await;
            assert!(response.starts_with(expected), "{response}");
        }
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn excess_connections_get_503_and_slots_are_reused() {
        timeout(Duration::from_secs(3), async {
            let (address, server, _trigger) = start_server(reply(204, "")).await;
            let mut clients = Vec::new();
            for _ in 0..MAX_CONNECTIONS {
                let mut client = TcpStream::connect(address).await.unwrap();
                client
                    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .await
                    .unwrap();
                let mut byte = [0];
                client.read_exact(&mut byte).await.unwrap();
                clients.push(client);
            }
            let mut excess = TcpStream::connect(address).await.unwrap();
            let mut output = Vec::new();
            excess.read_to_end(&mut output).await.unwrap();
            let output = String::from_utf8(output).unwrap();
            let body = r#"{"error":"too many open connections"}"#;
            assert!(
                output.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
                "{output}"
            );
            assert!(output.contains("\r\nRetry-After: 1\r\n"), "{output}");
            assert!(output.contains("\r\nConnection: close\r\n"), "{output}");
            assert!(
                output.contains(&format!("\r\nContent-Length: {}\r\n", body.len())),
                "{output}"
            );
            assert!(output.ends_with(&format!("\r\n\r\n{body}")), "{output}");
            drop(clients.pop());
            loop {
                let mut client = TcpStream::connect(address).await.unwrap();
                client
                    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                let mut output = Vec::new();
                client.read_to_end(&mut output).await.unwrap();
                if output.starts_with(b"HTTP/1.1 204 No Content\r\n") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            server.abort();
        })
        .await
        .unwrap();
    }

    #[test]
    fn refused_connections_are_logged_once_a_minute() {
        let start = Instant::now();
        assert!(log_due(None, start));
        assert!(!log_due(Some(start), start + Duration::from_secs(59)));
        assert!(log_due(Some(start), start + REFUSAL_LOG_INTERVAL));
    }

    #[tokio::test]
    async fn shutdown_lets_in_flight_requests_finish() {
        let started = Arc::new(tokio::sync::Notify::new());
        let notify = started.clone();
        let handler: Handler = Arc::new(move |_| {
            let notify = notify.clone();
            Box::pin(async move {
                notify.notify_one();
                tokio::time::sleep(Duration::from_millis(300)).await;
                Response::new(200, "text/plain", "finished")
            })
        });
        let (address, server, trigger) = start_server(handler).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        started.notified().await;
        trigger.send(()).unwrap();
        let mut output = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with("HTTP/1.1 200 OK\r\n"), "{output}");
        assert!(output.contains("\r\nConnection: close\r\n"), "{output}");
        assert!(output.ends_with("\r\n\r\nfinished"), "{output}");
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn shutdown_closes_idle_keep_alive_connections_at_once() {
        let (address, server, trigger) = start_server(reply(200, "synthetic")).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        read_response(&mut client).await;
        let stopping = Instant::now();
        trigger.send(()).unwrap();
        timeout(Duration::from_secs(1), server)
            .await
            .expect("an idle connection held up shutdown")
            .unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        assert!(stopping.elapsed() < IDLE_TIMEOUT);
    }

    #[tokio::test]
    async fn shutdown_gives_up_after_the_grace_period() {
        let handler: Handler = Arc::new(|_| Box::pin(std::future::pending()));
        let (address, server, trigger) = start_server(handler).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stopping = Instant::now();
        trigger.send(()).unwrap();
        timeout(SHUTDOWN_GRACE + Duration::from_secs(1), server)
            .await
            .expect("shutdown waited past the grace period")
            .unwrap();
        assert!(stopping.elapsed() >= SHUTDOWN_GRACE - Duration::from_millis(100));
        let mut rest = Vec::new();
        let _ = client.read_to_end(&mut rest).await;
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn framing_response_write_has_a_deadline() {
        let handler: Handler = Arc::new(|_| {
            Box::pin(async { Response::new(200, "text/plain", vec![b'a'; 16 * 1024 * 1024]) })
        });
        let (mut client, mut server, _stop) = connect(handler).await;
        let started = Instant::now();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let result = timeout(WRITE_TIMEOUT + Duration::from_secs(2), &mut server).await;
        server.abort();
        result
            .expect("blocked response write did not time out")
            .unwrap();
        assert!(started.elapsed() >= WRITE_TIMEOUT);
    }

    #[test]
    fn status_lines_use_registered_reason_phrases() {
        for (status, line) in [
            (409, "HTTP/1.1 409 Conflict\r\n"),
            (413, "HTTP/1.1 413 Content Too Large\r\n"),
            (414, "HTTP/1.1 414 URI Too Long\r\n"),
            (428, "HTTP/1.1 428 Precondition Required\r\n"),
            (501, "HTTP/1.1 501 Not Implemented\r\n"),
            (503, "HTTP/1.1 503 Service Unavailable\r\n"),
            (299, "HTTP/1.1 299 \r\n"),
        ] {
            let bytes = write_response(&Response::new(status, "text/plain", ""), false, false);
            assert!(bytes.starts_with(line.as_bytes()), "{status}");
        }
    }

    #[test]
    fn http_date_is_imf_fixdate() {
        for (seconds, date) in [
            (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
            (784_111_777, "Sun, 06 Nov 1994 08:49:37 GMT"),
            (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
            (1_709_251_199, "Thu, 29 Feb 2024 23:59:59 GMT"),
            (1_709_251_200, "Fri, 01 Mar 2024 00:00:00 GMT"),
            (4_107_542_400, "Mon, 01 Mar 2100 00:00:00 GMT"),
            (253_402_300_799, "Fri, 31 Dec 9999 23:59:59 GMT"),
        ] {
            assert_eq!(HttpDate(seconds).to_string(), date);
        }
    }

    #[test]
    fn response_headers_follow_rfc_9110() {
        let ok = Response::new(200, "text/plain", "synthetic").header("Connection", "close");
        let text = String::from_utf8(write_response(&ok, false, false)).unwrap();
        let date = text
            .lines()
            .find_map(|line| line.strip_prefix("Date: "))
            .unwrap();
        assert!(date.ends_with(" GMT") && date.len() == 29, "{date}");
        assert!(text.contains("\r\nContent-Length: 9\r\n"), "{text}");
        assert!(
            !text.contains("Connection"),
            "handler Connection header leaked: {text}"
        );
        assert!(text.ends_with("\r\n\r\nsynthetic"), "{text}");
        let closing = String::from_utf8(write_response(&ok, false, true)).unwrap();
        assert_eq!(closing.matches("Connection").count(), 1, "{closing}");
        assert!(closing.contains("\r\nConnection: close\r\n"), "{closing}");
        let empty = Response::new(204, "text/plain", "ignored");
        let text = String::from_utf8(write_response(&empty, false, false)).unwrap();
        assert!(text.starts_with("HTTP/1.1 204 No Content\r\n"), "{text}");
        assert!(!text.contains("Content-Length"), "{text}");
        assert!(text.ends_with("\r\n\r\n"), "{text}");
    }

    async fn parse_chunked(body: &str) -> Result<Option<Request>, ReadError> {
        parse_wire(
            format!("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n{body}")
                .into_bytes(),
        )
        .await
    }

    #[tokio::test]
    async fn chunked_maximum_size_after_nonempty_body_is_rejected() {
        let wire_body = format!("1\r\na\r\n{:x}\r\n", usize::MAX);
        assert_eq!(parse_chunked(&wire_body).await.unwrap_err(), BODY_TOO_LARGE);
    }

    #[tokio::test]
    async fn chunked_malformed_hex_size_is_rejected() {
        for size in ["not-hex", "", "+1", "-1", "0x1", "1 0", " 1", "1 "] {
            let wire_body = format!("{size}\r\n\r\n");
            assert_eq!(
                status(parse_chunked(&wire_body).await),
                Some(400),
                "size: {size:?}"
            );
        }
        let result = parse_chunked(&format!("{:x}0\r\n\r\n", usize::MAX)).await;
        assert_eq!(status(result), Some(400));
    }

    #[tokio::test]
    async fn chunked_oversized_body_is_rejected_before_reading_payload() {
        for wire_body in [
            format!("{:x}\r\n", MAX_BODY_SIZE + 1),
            format!("1\r\na\r\n{:x}\r\n", MAX_BODY_SIZE),
        ] {
            assert_eq!(parse_chunked(&wire_body).await.unwrap_err(), BODY_TOO_LARGE);
        }
    }

    #[tokio::test]
    async fn chunked_valid_body_is_decoded() {
        let request = parse_chunked("5;name=value\r\nHello\r\nA\r\n, world!!!\r\n0\r\n\r\n")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/test");
        assert_eq!(request.body, b"Hello, world!!!");
    }

    #[tokio::test]
    async fn chunked_invalid_crlf_is_rejected() {
        for wire_body in [
            "1\na\r\n0\r\n\r\n",
            "\r1\r\na\r\n0\r\n\r\n",
            "1\r\naXX0\r\n\r\n",
            "0\r\nXX",
        ] {
            assert_eq!(
                status(parse_chunked(wire_body).await),
                Some(400),
                "body: {wire_body:?}"
            );
        }
    }

    #[tokio::test]
    async fn chunked_extensions_reject_embedded_controls() {
        for extension in ["name=value\rX", "\r", "name=\0", "name=\u{7f}"] {
            for size in ["0", "1"] {
                let payload = if size == "0" {
                    "\r\n"
                } else {
                    "a\r\n0\r\n\r\n"
                };
                let body = format!("{size};{extension}\r\n{payload}");
                assert_eq!(status(parse_chunked(&body).await), Some(400), "{body:?}");
            }
        }
    }

    #[tokio::test]
    async fn chunked_truncated_terminator_is_rejected() {
        for wire_body in ["0\r\n", "0\r\n\r"] {
            assert_eq!(parse_chunked(wire_body).await.unwrap_err(), TRUNCATED);
        }
    }
}
