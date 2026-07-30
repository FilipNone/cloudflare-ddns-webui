//! A minimal, dependency-free HTTP/1.1 server built directly on tokio's
//! TcpListener - in the spirit of cloudflare-ddns: no web framework, no
//! runtime bloat, just enough HTTP to serve the GUI and its JSON API.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const MAX_HEAD_SIZE: usize = 64 * 1024; // 64 KB request head
const MAX_BODY_SIZE: usize = 16 * 1024 * 1024; // 16 MB (zone file imports)
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
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            _ => "OK",
        }
    }
}

type Handler = Arc<dyn Fn(Request) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> + Send + Sync>;

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
    deadline: Duration,
) -> std::io::Result<()> {
    timeout(deadline, stream.read_exact(buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))?
        .map(|_| ())
}

/// Read a single request from the stream. Returns Ok(None) on clean EOF.
async fn read_request(stream: &mut TcpStream, remote: SocketAddr) -> std::io::Result<Option<Request>> {
    // --- Read the head (request line + headers) ---
    let mut head = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        match timeout(KEEPALIVE_TIMEOUT, stream.read(&mut byte)).await {
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

    let head_text = String::from_utf8_lossy(&head);
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_uppercase();
    let raw_target = parts.next().unwrap_or_default().to_string();
    let _version = parts.next().unwrap_or_default();
    if method.is_empty() || raw_target.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_lowercase(), value.trim().to_string()));
        }
    }

    // --- Read the body ---
    let find_header = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };

    let mut body = Vec::new();
    if let Some(te) = find_header("transfer-encoding") {
        if te.to_lowercase().contains("chunked") {
            // Minimal chunked decoding.
            loop {
                let mut size_line = String::new();
                loop {
                    let mut b = [0u8; 1];
                    match timeout(KEEPALIVE_TIMEOUT, stream.read(&mut b)).await {
                        Ok(Ok(0)) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "eof in chunk size",
                            ))
                        }
                        Ok(Ok(_)) => {
                            if b[0] == b'\n' {
                                break;
                            }
                            if b[0] != b'\r' {
                                size_line.push(b[0] as char);
                            }
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
                let size_str = size_line.split(';').next().unwrap_or("0").trim();
                let size = usize::from_str_radix(size_str, 16).unwrap_or(0);
                if size == 0 {
                    // Consume trailing CRLF (and any trailers up to empty line).
                    let mut trail = [0u8; 2];
                    let _ = read_exact_deadline(stream, &mut trail, KEEPALIVE_TIMEOUT).await;
                    break;
                }
                if body.len() + size > MAX_BODY_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "request body too large",
                    ));
                }
                let start = body.len();
                body.resize(start + size, 0);
                read_exact_deadline(stream, &mut body[start..], KEEPALIVE_TIMEOUT).await?;
                let mut crlf = [0u8; 2];
                read_exact_deadline(stream, &mut crlf, KEEPALIVE_TIMEOUT).await?;
            }
        }
    } else if let Some(cl) = find_header("content-length") {
        let len: usize = cl.parse().unwrap_or(0);
        if len > MAX_BODY_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request body too large",
            ));
        }
        body.resize(len, 0);
        if len > 0 {
            read_exact_deadline(stream, &mut body, KEEPALIVE_TIMEOUT).await?;
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

fn write_response(resp: &Response, head_only: bool) -> Vec<u8> {
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
    out.extend_from_slice(b"Connection: keep-alive\r\n");
    for (name, value) in &resp.headers {
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
                let close_requested = req
                    .header("connection")
                    .map(|v| v.eq_ignore_ascii_case("close"))
                    .unwrap_or(false);
                let resp = handler(req).await;
                let bytes = write_response(&resp, head_only);
                if stream.write_all(&bytes).await.is_err() {
                    return;
                }
                if close_requested {
                    return;
                }
            }
            Ok(None) => return,
            Err(_) => return,
        }
    }
}

/// Serve on a pre-bound listener until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    handler: Handler,
    mut shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, remote)) => {
                        let h = handler.clone();
                        tokio::spawn(async move {
                            handle_connection(stream, remote, h).await;
                        });
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            _ = &mut shutdown => {
                return Ok(());
            }
        }
    }
}
