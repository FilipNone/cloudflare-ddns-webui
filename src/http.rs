//! A minimal, dependency-free HTTP/1.1 server built directly on tokio's
//! TcpListener - in the spirit of cloudflare-ddns: no web framework, no
//! runtime bloat, just enough HTTP to serve the GUI and its JSON API.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, timeout_at, Duration, Instant};

const MAX_HEAD_SIZE: usize = 64 * 1024; // 64 KB request head
const MAX_BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MB (zone file imports)
const MAX_HEADER_LINE_SIZE: usize = 8 * 1024;
const MAX_HEADERS: usize = 100;
const MAX_CHUNK_METADATA_SIZE: usize = MAX_HEAD_SIZE;
const MAX_CONNECTIONS: usize = 16;
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);

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

    fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            413 => "Payload Too Large",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            _ => "OK",
        }
    }
}

type Handler = Arc<
    dyn Fn(Request) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
        + Send
        + Sync,
>;

/// Percent-decode a URL component (path or query value).
fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                }
            };
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
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
        match pair.split_once('=') {
            Some((k, v)) => {
                map.insert(url_decode(k), url_decode(v));
            }
            None => {
                map.insert(url_decode(pair), String::new());
            }
        }
    }
    map
}

/// Read exactly `buf.len()` bytes with a deadline.
async fn read_exact_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    timeout_at(deadline, stream.read_exact(buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))?
        .map(|_| ())
}

async fn read_body_deadline(
    stream: &mut TcpStream,
    body: &mut Vec<u8>,
    length: usize,
    deadline: Instant,
) -> std::io::Result<()> {
    let mut remaining = length;
    let mut buffer = [0; 8192];
    while remaining > 0 {
        let limit = remaining.min(buffer.len());
        let received = timeout_at(deadline, stream.read(&mut buffer[..limit]))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))??;
        if received == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated request body",
            ));
        }
        let required = body.len() + received;
        if required > body.capacity() {
            body.reserve_exact(required.next_power_of_two().min(MAX_BODY_SIZE) - body.len());
        }
        body.extend_from_slice(&buffer[..received]);
        remaining -= received;
    }
    Ok(())
}

/// Read a single request from the stream. Returns Ok(None) on clean EOF.
async fn read_request(
    stream: &mut TcpStream,
    remote: SocketAddr,
) -> std::io::Result<Option<Request>> {
    let deadline = Instant::now() + KEEPALIVE_TIMEOUT;
    // --- Read the head (request line + headers) ---
    let mut head = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        match timeout_at(deadline, stream.read(&mut byte)).await {
            Ok(Ok(0)) => {
                if head.is_empty() {
                    return Ok(None); // clean close between requests
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-request",
                ));
            }
            Ok(Ok(_)) => {
                head.push(byte[0]);
                if head.len() > MAX_HEAD_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "request head too large",
                    ));
                }
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                if head.is_empty() {
                    return Ok(None); // idle keep-alive timeout
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "header read timeout",
                ));
            }
        }
    }

    let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
    let is_token = |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte);
    let head_text = std::str::from_utf8(&head[..head.len() - 4])
        .map_err(|_| invalid("invalid request head encoding"))?;
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let raw_target = parts.next().unwrap_or_default().to_string();
    let version = parts.next().unwrap_or_default();
    if request_line.len() > MAX_HEADER_LINE_SIZE
        || method.is_empty()
        || !method.bytes().all(is_token)
        || !raw_target.starts_with('/')
        || !raw_target
            .bytes()
            .all(|byte| (b'!'..=b'~').contains(&byte) && byte != b'#')
        || version != "HTTP/1.1"
        || parts.next().is_some()
    {
        return Err(invalid("malformed request line"));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.len() > MAX_HEADER_LINE_SIZE || headers.len() >= MAX_HEADERS {
            return Err(invalid("request headers too large"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed header"))?;
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
    let host = hosts.next().ok_or_else(|| invalid("missing Host header"))?;
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
    let content_length = content_length
        .map(|(_, value)| {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid("invalid Content-Length"));
            }
            value
                .parse::<usize>()
                .map_err(|_| invalid("invalid Content-Length"))
        })
        .transpose()?;
    if transfer_encoding.is_some_and(|(_, value)| !value.eq_ignore_ascii_case("chunked")) {
        return Err(invalid("unsupported Transfer-Encoding"));
    }

    // --- Read the body ---
    let mut body = Vec::new();
    if transfer_encoding.is_some() {
        // Minimal chunked decoding.
        let mut metadata_size = 0;
        loop {
            let mut size_line = String::new();
            loop {
                let mut b = [0u8; 1];
                match timeout_at(deadline, stream.read(&mut b)).await {
                    Ok(Ok(0)) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "eof in chunk size",
                        ))
                    }
                    Ok(Ok(_)) => {
                        metadata_size += 1;
                        if metadata_size > MAX_CHUNK_METADATA_SIZE
                            || size_line.len() >= MAX_HEADER_LINE_SIZE
                        {
                            return Err(invalid("chunk metadata too large"));
                        }
                        if b[0] == b'\n' {
                            break;
                        }
                        size_line.push(b[0] as char);
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "chunk read timeout",
                        ))
                    }
                }
            }
            let size_line = size_line.strip_suffix('\r').ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size CRLF")
            })?;
            if size_line
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid control byte in chunk size",
                ));
            }
            let size_str = size_line.split(';').next().unwrap_or_default();
            if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid chunk size",
                ));
            }
            let size = usize::from_str_radix(size_str, 16).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size")
            })?;
            if size == 0 {
                // Consume trailing CRLF; trailer fields are not supported.
                let mut trail = [0u8; 2];
                read_exact_deadline(stream, &mut trail, deadline).await?;
                if trail != *b"\r\n" {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid chunk terminator CRLF",
                    ));
                }
                if metadata_size + 2 > MAX_CHUNK_METADATA_SIZE {
                    return Err(invalid("chunk metadata too large"));
                }
                break;
            }
            if size > MAX_BODY_SIZE - body.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request body too large",
                ));
            }
            read_body_deadline(stream, &mut body, size, deadline).await?;
            let mut crlf = [0u8; 2];
            read_exact_deadline(stream, &mut crlf, deadline).await?;
            metadata_size += 2;
            if metadata_size > MAX_CHUNK_METADATA_SIZE {
                return Err(invalid("chunk metadata too large"));
            }
            if crlf != *b"\r\n" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid chunk data CRLF",
                ));
            }
        }
    } else if let Some(len) = content_length {
        if len > MAX_BODY_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request body too large",
            ));
        }
        if len > 0 {
            read_body_deadline(stream, &mut body, len, deadline).await?;
        }
    }

    // --- Split path and query ---
    let (raw_path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p, parse_query(q)),
        None => (raw_target.as_str(), HashMap::new()),
    };

    Ok(Some(Request {
        method,
        path: url_decode(raw_path),
        query,
        headers,
        body,
        remote,
    }))
}

fn write_response(resp: &Response, head_only: bool, close: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(resp.body.len() + 256);
    out.extend_from_slice(
        format!(
            "HTTP/1.1 {} {}\r\n",
            resp.status,
            Response::status_text(resp.status)
        )
        .as_bytes(),
    );
    out.extend_from_slice(format!("Content-Type: {}\r\n", resp.content_type).as_bytes());
    out.extend_from_slice(format!("Content-Length: {}\r\n", resp.body.len()).as_bytes());
    out.extend_from_slice(if close {
        b"Connection: close\r\n"
    } else {
        b"Connection: keep-alive\r\n"
    });
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("connection") {
            continue;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if !head_only {
        out.extend_from_slice(&resp.body);
    }
    out
}

async fn handle_connection(mut stream: TcpStream, remote: SocketAddr, handler: Handler) {
    let _ = stream.set_nodelay(true);
    loop {
        match read_request(&mut stream, remote).await {
            Ok(Some(req)) => {
                let head_only = req.method == "HEAD";
                let close_requested = req.headers.iter().any(|(name, value)| {
                    name == "connection"
                        && value
                            .split(',')
                            .any(|token| token.trim().eq_ignore_ascii_case("close"))
                });
                let resp = handler(req).await;
                let close_requested = close_requested
                    || resp.headers.iter().any(|(name, value)| {
                        name.eq_ignore_ascii_case("connection")
                            && value
                                .split(',')
                                .any(|token| token.trim().eq_ignore_ascii_case("close"))
                    });
                let bytes = write_response(&resp, head_only, close_requested);
                if !matches!(
                    timeout(KEEPALIVE_TIMEOUT, stream.write_all(&bytes)).await,
                    Ok(Ok(()))
                ) {
                    return;
                }
                if close_requested {
                    return;
                }
            }
            Ok(None) => return,
            Err(error) => {
                let message = error.to_string();
                let status = match error.kind() {
                    std::io::ErrorKind::InvalidData => match message.as_str() {
                        "request body too large" | "chunk metadata too large" => 413,
                        "request head too large" | "request headers too large" => 431,
                        _ => 400,
                    },
                    std::io::ErrorKind::UnexpectedEof => 400,
                    std::io::ErrorKind::TimedOut => 408,
                    _ => return,
                };
                let response = Response::json_error(status, &message);
                let bytes = write_response(&response, false, true);
                let _ = timeout(KEEPALIVE_TIMEOUT, stream.write_all(&bytes)).await;
                return;
            }
        }
    }
}

/// Serve on a pre-bound listener until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    handler: Handler,
    mut shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) -> std::io::Result<()> {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, remote)) => {
                        while connections.try_join_next().is_some() {}
                        if connections.len() >= MAX_CONNECTIONS {
                            drop(stream);
                            continue;
                        }
                        let h = handler.clone();
                        connections.spawn(async move {
                            handle_connection(stream, remote, h).await;
                        });
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
            _ = &mut shutdown => {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    async fn parse_wire(wire: Vec<u8>) -> std::io::Result<Option<Request>> {
        timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let mut client = TcpStream::connect(listener.local_addr()?).await?;
            let writer = tokio::spawn(async move {
                let _ = client.write_all(&wire).await;
                let _ = client.shutdown().await;
            });
            let (mut stream, remote) = listener.accept().await?;
            let result = read_request(&mut stream, remote).await;
            drop(stream);
            writer.await.unwrap();
            result
        })
        .await
        .expect("loopback parser test timed out")
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
            let error = parse_wire(wire.into_bytes()).await.expect_err(headers);
            assert_eq!(error.kind(), ErrorKind::InvalidData, "{headers}");
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
            let error = parse_wire(wire.into_bytes()).await.expect_err(length);
            assert_eq!(error.kind(), ErrorKind::InvalidData, "{length:?}");
        }
    }

    #[tokio::test]
    async fn framing_rejects_unsupported_or_duplicate_transfer_codings() {
        for encoding in [
            "gzip",
            "identity",
            "xchunked",
            "chunkedx",
            "gzip, chunked",
            "chunked, gzip",
            "chunked, chunked",
            "chunked;name=value",
            "",
            "chunked\r\nTransfer-Encoding: chunked",
        ] {
            let wire = format!("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: {encoding}\r\n\r\n0\r\n\r\n");
            let error = parse_wire(wire.into_bytes()).await.expect_err(encoding);
            assert_eq!(error.kind(), ErrorKind::InvalidData, "{encoding:?}");
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
        ] {
            let error = parse_wire(format!("{head}\r\n\r\n").into_bytes())
                .await
                .expect_err(head);
            assert_eq!(error.kind(), ErrorKind::InvalidData, "{head:?}");
        }
        let error =
            parse_wire(b"GET /test HTTP/1.1\r\nHost: localhost\r\nX-Test: \xff\r\n\r\n".to_vec())
                .await
                .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn framing_bounds_header_fields_and_chunk_metadata() {
        let heads = [
            format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: {}\r\n\r\n",
                "a".repeat(8192)
            ),
            format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\n{}\r\n",
                "X-Test: a\r\n".repeat(101)
            ),
            format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: {}\r\n\r\n",
                "a".repeat(MAX_HEAD_SIZE)
            ),
        ];
        for head in heads {
            let error = parse_wire(head.into_bytes()).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
        let bodies = [
            format!("0;name={}\r\n\r\n", "a".repeat(8192)),
            format!("{}0\r\n\r\n", "1\r\na\r\n".repeat(MAX_HEAD_SIZE / 5 + 1)),
        ];
        for body in bodies {
            let wire = format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n{body}"
            );
            let error = parse_wire(wire.into_bytes()).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
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
            assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
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
            let (mut stream, remote) = listener.accept().await.unwrap();
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
        let wire = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_SIZE + 1
        );
        assert_eq!(
            parse_wire(wire.into_bytes()).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn framing_body_allocation_tracks_received_bytes_and_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut body = Vec::new();
        let error = read_body_deadline(
            &mut stream,
            &mut body,
            MAX_BODY_SIZE,
            Instant::now() + Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, remote) = listener.accept().await.unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let handler: Handler = Arc::new(move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Response::new(200, "text/plain", "synthetic") })
        });
        let server = tokio::spawn(handle_connection(stream, remote, handler));
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
        for (wire, status) in [
            (
                "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: garbage\r\n\r\n".to_string(),
                400,
            ),
            (
                format!(
                    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
                    MAX_BODY_SIZE + 1
                ),
                413,
            ),
            (
                format!(
                    "GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: {}\r\n\r\n",
                    "a".repeat(MAX_HEADER_LINE_SIZE)
                ),
                431,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, remote) = listener.accept().await.unwrap();
            let handler: Handler = Arc::new(|_| panic!("invalid request reached handler"));
            let server = tokio::spawn(handle_connection(stream, remote, handler));
            client.write_all(wire.as_bytes()).await.unwrap();
            let mut output = Vec::new();
            if let Err(error) = timeout(Duration::from_secs(2), client.read_to_end(&mut output))
                .await
                .unwrap()
            {
                assert_eq!(error.kind(), ErrorKind::ConnectionReset);
            }
            server.await.unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(
                output.starts_with(&format!("HTTP/1.1 {status} ")),
                "{output}"
            );
            assert!(output.contains("Connection: close\r\n"), "{output}");
        }
    }

    #[tokio::test]
    async fn framing_connection_close_token_is_honored_on_the_wire() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, remote) = listener.accept().await.unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let handler: Handler = Arc::new(move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Response::new(200, "text/plain", "synthetic") })
        });
        let server = tokio::spawn(handle_connection(stream, remote, handler));
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, CLOSE\r\n\r\nGET /second HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        let mut output = Vec::new();
        if let Err(error) = timeout(Duration::from_secs(2), client.read_to_end(&mut output))
            .await
            .unwrap()
        {
            assert_eq!(error.kind(), ErrorKind::ConnectionReset);
        }
        server.await.unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(output.contains("Connection: close\r\n"), "{output}");
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
                    tokio::time::sleep(KEEPALIVE_TIMEOUT / 2).await;
                    client.write_all(next.as_bytes()).await.unwrap();
                    tokio::time::sleep(KEEPALIVE_TIMEOUT).await;
                });
                let (mut stream, remote) = listener.accept().await.unwrap();
                let result = timeout(KEEPALIVE_TIMEOUT + Duration::from_millis(500), read_request(&mut stream, remote)).await;
                writer.abort();
                let error = result.expect("trickle extended the total request deadline").unwrap_err();
                assert_eq!(error.kind(), ErrorKind::TimedOut, "{prefix:?}");
            }));
        }
        for case in cases {
            case.await.unwrap();
        }
    }

    #[tokio::test]
    async fn framing_connection_admission_is_bounded() {
        timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let handler: Handler =
                Arc::new(|_| Box::pin(async { Response::new(204, "text/plain", "") }));
            let server = tokio::spawn(serve(listener, handler, Box::pin(std::future::pending())));
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
            let mut byte = [0];
            let rejected = timeout(Duration::from_millis(200), excess.read(&mut byte)).await;
            server.abort();
            assert_eq!(
                rejected.expect("excess connection was not closed").unwrap(),
                0
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn framing_response_write_has_a_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, remote) = listener.accept().await.unwrap();
        let handler: Handler = Arc::new(|_| {
            Box::pin(async { Response::new(200, "text/plain", vec![b'a'; 16 * 1024 * 1024]) })
        });
        let mut server = tokio::spawn(handle_connection(stream, remote, handler));
        let started = Instant::now();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let result = timeout(KEEPALIVE_TIMEOUT + Duration::from_secs(2), &mut server).await;
        server.abort();
        result
            .expect("blocked response write did not time out")
            .unwrap();
        assert!(started.elapsed() >= KEEPALIVE_TIMEOUT);
    }

    async fn parse_chunked(body: &str) -> std::io::Result<Option<Request>> {
        timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let mut client = TcpStream::connect(listener.local_addr()?).await?;
            client
                .write_all(
                    format!(
                        "POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n{body}"
                    )
                    .as_bytes(),
                )
                .await?;
            client.shutdown().await?;
            let (mut stream, remote) = listener.accept().await?;
            read_request(&mut stream, remote).await
        })
        .await
        .expect("loopback parser test timed out")
    }

    #[tokio::test]
    async fn chunked_maximum_size_after_nonempty_body_is_rejected() {
        let wire_body = format!("1\r\na\r\n{:x}\r\n", usize::MAX);
        let error = parse_chunked(&wire_body).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "request body too large");
    }

    #[tokio::test]
    async fn chunked_malformed_hex_size_is_rejected() {
        for size in ["not-hex", "", "+1", "-1", "0x1", "1 0", " 1", "1 "] {
            let wire_body = format!("{size}\r\n\r\n");
            let error = parse_chunked(&wire_body)
                .await
                .expect_err("malformed chunk size must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData, "size: {size:?}");
        }
        let error = parse_chunked(&format!("{:x}0\r\n\r\n", usize::MAX))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn chunked_oversized_body_is_rejected_before_reading_payload() {
        for wire_body in [
            format!("{:x}\r\n", MAX_BODY_SIZE + 1),
            format!("1\r\na\r\n{:x}\r\n", MAX_BODY_SIZE),
        ] {
            let error = parse_chunked(&wire_body).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "request body too large");
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
            let error = parse_chunked(wire_body)
                .await
                .expect_err("invalid chunk CRLF must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData, "body: {wire_body:?}");
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
                let error = parse_chunked(&body)
                    .await
                    .expect_err("chunk extensions must not contain forbidden controls");
                assert_eq!(error.kind(), ErrorKind::InvalidData);
            }
        }
    }

    #[tokio::test]
    async fn chunked_truncated_terminator_is_rejected() {
        for wire_body in ["0\r\n", "0\r\n\r"] {
            let error = parse_chunked(wire_body).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        }
    }
}
