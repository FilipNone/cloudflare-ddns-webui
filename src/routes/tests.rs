use super::*;

fn fixture_config() -> Config {
    Config {
        api_token: "synthetic".into(),
        listen: "127.0.0.1:8888".parse().unwrap(),
        data_dir: String::new(),
        session_ttl: std::time::Duration::from_secs(300),
        update_timeout: std::time::Duration::from_secs(5),
        detection_timeout: std::time::Duration::from_secs(2),
        secure_cookies: false,
        public_origin: None,
        domains: vec![],
        ip4_domains: vec![],
        ip6_domains: vec![],
        ddns_contract: "standalone-v1".into(),
        managed_record_comment: None,
        ip4_provider: "none".into(),
        ip6_provider: "none".into(),
        ttl: 1,
        proxied: false,
        record_comment: None,
        emoji: false,
        quiet: true,
        api_base: None,
    }
}

fn fixture_request(host: &str, origin: Option<&str>) -> Request {
    let mut headers = vec![("host".into(), host.into())];
    if let Some(origin) = origin {
        headers.push(("origin".into(), origin.into()));
    }
    Request {
        method: "POST".into(),
        path: "/api/auth/setup".into(),
        query: Default::default(),
        headers,
        body: vec![],
        remote: "127.0.0.1:12345".parse().unwrap(),
    }
}

const PASSWORD: &str = "synthetic-password";
const ZONE: &str = "0123456789abcdef0123456789abcdef";

/// One request that reached the fake Cloudflare upstream.
struct Upstream {
    method: String,
    path: String,
    body: Value,
}

/// Picks the fake upstream's reply. `None` closes the connection unanswered.
type Responder = Box<dyn FnMut(&Upstream) -> Option<(u16, Value)> + Send>;

/// Reads one request with a Content-Length body, or `None` if the
/// connection ends first.
async fn read_upstream(socket: &mut tokio::net::TcpStream) -> Option<Upstream> {
    use tokio::io::AsyncReadExt;
    let mut data = Vec::new();
    let mut buffer = [0; 8192];
    let end = loop {
        if let Some(end) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break end + 4;
        }
        let count = socket.read(&mut buffer).await.ok()?;
        if count == 0 {
            return None;
        }
        data.extend_from_slice(&buffer[..count]);
    };
    let head = String::from_utf8(data[..end].to_vec()).ok()?;
    let mut line = head.lines().next()?.split(' ');
    let (method, path) = (line.next()?.to_owned(), line.next()?.to_owned());
    let length = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while data.len() < end + length {
        let count = socket.read(&mut buffer).await.ok()?;
        if count == 0 {
            return None;
        }
        data.extend_from_slice(&buffer[..count]);
    }
    let body = serde_json::from_slice(&data[end..]).unwrap_or(Value::Null);
    Some(Upstream { method, path, body })
}

/// App state over a temporary data directory. Cloudflare calls go to a
/// loopback listener that counts connections, logs each request and
/// answers with the current responder. The default responder closes each
/// connection unanswered.
struct Fixture {
    dir: std::path::PathBuf,
    state: Arc<AppState>,
    upstream_hits: Arc<std::sync::atomic::AtomicUsize>,
    upstream_log: Arc<std::sync::Mutex<Vec<Upstream>>>,
    responder: Arc<std::sync::Mutex<Responder>>,
    upstream: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_config(|_| {}).await
    }

    async fn with_config(change: impl FnOnce(&mut Config)) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ddns-routes-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_base = format!("http://{}/client/v4", listener.local_addr().unwrap());
        let upstream_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let upstream_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: Arc<std::sync::Mutex<Responder>> =
            Arc::new(std::sync::Mutex::new(Box::new(|_| None)));
        let (hits, log, reply) = (
            upstream_hits.clone(),
            upstream_log.clone(),
            responder.clone(),
        );
        let upstream = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            while let Ok((mut socket, _)) = listener.accept().await {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let Some(request) = read_upstream(&mut socket).await else {
                    continue;
                };
                let answer = (reply.lock().unwrap())(&request);
                log.lock().unwrap().push(request);
                if let Some((status, body)) = answer {
                    let body = body.to_string();
                    let response = format!(
                        "HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            }
        });
        let mut cfg = fixture_config();
        cfg.data_dir = dir.to_str().unwrap().to_owned();
        change(&mut cfg);
        let state = Arc::new(AppState {
            cf: CloudflareClient::new("synthetic", cfg.update_timeout, Some(&api_base)).unwrap(),
            detector: ddns::Detector::new(cfg.detection_timeout).unwrap(),
            auth: Auth::new(
                cfg.session_ttl,
                dir.join("state.json").to_str().unwrap(),
                PP::new(false, true),
            )
            .unwrap(),
            ui: UiStore::new(&cfg.data_dir, PP::new(false, true)).unwrap(),
            pp: PP::new(false, true),
            ddns_running: std::sync::atomic::AtomicBool::new(false),
            cfg,
        });
        Self {
            dir,
            state,
            upstream_hits,
            upstream_log,
            responder,
            upstream,
        }
    }

    /// Sets how the fake upstream answers from now on.
    fn respond(&self, responder: impl FnMut(&Upstream) -> Option<(u16, Value)> + Send + 'static) {
        *self.responder.lock().unwrap() = Box::new(responder);
    }

    /// The requests the upstream received since the last call.
    fn take_upstream_requests(&self) -> Vec<Upstream> {
        std::mem::take(&mut *self.upstream_log.lock().unwrap())
    }

    /// Creates the admin account and returns a Cookie header for it.
    fn login(&self) -> String {
        let token = self.state.auth.setup_password_session(PASSWORD).unwrap();
        format!("{}={token}", SESSION_COOKIE)
    }

    fn upstream_hits(&self) -> usize {
        self.upstream_hits.load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn get(&self, path: &str) -> Response {
        self.send("GET", path, None, b"").await
    }

    async fn send(&self, method: &str, path: &str, cookie: Option<&str>, body: &[u8]) -> Response {
        let mut req = fixture_request("localhost:8888", None);
        req.method = method.into();
        req.path = path.into();
        req.headers
            .push(("x-requested-with".into(), "fetch".into()));
        if let Some(cookie) = cookie {
            req.headers.push(("cookie".into(), cookie.into()));
        }
        req.body = body.to_vec();
        handle(self.state.clone(), req).await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.upstream.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
    resp.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn body_json(resp: &Response) -> serde_json::Value {
    serde_json::from_slice(&resp.body).unwrap()
}

#[tokio::test]
async fn logout_clears_the_cookie_without_a_valid_session() {
    let fixture = Fixture::new().await;
    fixture.login();
    for cookie in [None, Some("cfddns_session=expired-or-forged")] {
        let resp = fixture.send("POST", "/api/auth/logout", cookie, b"").await;
        assert_eq!(resp.status, 200);
        let cleared = header(&resp, "Set-Cookie").unwrap();
        assert!(cleared.starts_with("cfddns_session=;"), "{cleared}");
        assert!(cleared.contains("Max-Age=0") && cleared.contains("HttpOnly"));
        assert!(cleared.contains("SameSite=Strict") && cleared.contains("Path=/"));
    }
    let mut req = fixture_request("localhost:8888", None);
    req.path = "/api/auth/logout".into();
    assert_eq!(handle(fixture.state.clone(), req).await.status, 403);
}

#[tokio::test]
async fn secure_cookies_use_the_host_prefix_for_issue_read_and_clear() {
    let fixture = Fixture::with_config(|cfg| cfg.secure_cookies = true).await;
    let token = fixture.state.auth.setup_password_session(PASSWORD).unwrap();
    let plain = format!("cfddns_session={token}");
    let prefixed = format!("__Host-cfddns_session={token}");
    assert_eq!(
        fixture
            .send("GET", "/api/auth/me", Some(&plain), b"")
            .await
            .status,
        401
    );
    assert_eq!(
        fixture
            .send("GET", "/api/auth/me", Some(&prefixed), b"")
            .await
            .status,
        200
    );
    let login = fixture
        .send(
            "POST",
            "/api/auth/login",
            None,
            br#"{"password":"synthetic-password"}"#,
        )
        .await;
    let issued = header(&login, "Set-Cookie").unwrap();
    assert!(issued.starts_with("__Host-cfddns_session=") && issued.contains("; Secure"));
    assert!(!issued.contains("Domain"));
    let logout = fixture
        .send("POST", "/api/auth/logout", Some(&prefixed), b"")
        .await;
    let cleared = header(&logout, "Set-Cookie").unwrap();
    assert!(cleared.starts_with("__Host-cfddns_session=;"), "{cleared}");
    assert!(cleared.contains("Max-Age=0") && cleared.contains("; Secure"));
    assert_eq!(
        fixture
            .send("GET", "/api/auth/me", Some(&prefixed), b"")
            .await
            .status,
        401
    );
}

#[tokio::test]
async fn bulk_is_a_post_route_and_never_a_record_id() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    let path = format!("/api/zones/{ZONE}/records/bulk");
    for method in ["DELETE", "PUT", "GET"] {
        let resp = fixture
            .send(
                method,
                &path,
                Some(&cookie),
                br#"{"type":"A","name":"example.com","content":"192.0.2.1"}"#,
            )
            .await;
        assert_eq!(resp.status, 404, "{method}");
    }
    assert_eq!(fixture.upstream_hits(), 0);
}

#[tokio::test]
async fn bulk_update_rejects_an_empty_patch_before_any_request() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    let path = format!("/api/zones/{ZONE}/records/bulk");
    let body = json!({"action": "update", "ids": [ZONE], "patch": {}}).to_string();
    let resp = fixture
        .send("POST", &path, Some(&cookie), body.as_bytes())
        .await;
    assert_eq!(resp.status, 400);
    assert_eq!(fixture.upstream_hits(), 0);
}

/// A success envelope that echoes the batch body as its result.
fn batch_applied(request: &Upstream) -> Option<(u16, Value)> {
    Some((
        200,
        json!({"success": true, "errors": [], "messages": [], "result": request.body}),
    ))
}

fn record_ids(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("{i:032x}")).collect()
}

/// Checks that every request is a batch whose body has only `key`, and
/// returns the record IDs of each batch.
fn batched_ids(requests: &[Upstream], key: &str) -> Vec<Vec<String>> {
    let batch_path = format!("/client/v4/zones/{ZONE}/dns_records/batch");
    requests
        .iter()
        .map(|request| {
            assert_eq!(
                (request.method.as_str(), request.path.as_str()),
                ("POST", batch_path.as_str())
            );
            let body = request.body.as_object().unwrap();
            assert_eq!(body.keys().collect::<Vec<_>>(), [key]);
            body[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["id"].as_str().unwrap().to_owned())
                .collect()
        })
        .collect()
}

async fn bulk_request(fixture: &Fixture, cookie: &str, body: Value) -> Value {
    let path = format!("/api/zones/{ZONE}/records/bulk");
    let resp = fixture
        .send("POST", &path, Some(cookie), body.to_string().as_bytes())
        .await;
    assert_eq!(resp.status, 200);
    body_json(&resp)
}

#[tokio::test]
async fn bulk_delete_sends_batches_of_at_most_200_records() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    fixture.respond(batch_applied);
    for (count, sizes) in [
        (1, vec![1]),
        (200, vec![200]),
        (201, vec![200, 1]),
        (500, vec![200, 200, 100]),
    ] {
        let ids = record_ids(count);
        let result = bulk_request(&fixture, &cookie, json!({"action": "delete", "ids": ids})).await;
        let requests = fixture.take_upstream_requests();
        for item in requests
            .iter()
            .flat_map(|r| r.body["deletes"].as_array().unwrap())
        {
            assert_eq!(item.as_object().unwrap().len(), 1, "{item}");
        }
        let batches = batched_ids(&requests, "deletes");
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), sizes);
        assert_eq!(batches.concat(), ids);
        let results: Vec<Value> = ids.iter().map(|id| json!({"id": id, "ok": true})).collect();
        assert_eq!(
            result,
            json!({"results": results, "succeeded": count, "failed": 0})
        );
    }
}

#[tokio::test]
async fn failed_batch_fails_every_record_in_it_and_later_batches_still_run() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    let mut sent = 0;
    fixture.respond(move |request| {
        sent += 1;
        if sent > 1 {
            return batch_applied(request);
        }
        let errors = json!([{"code": 81044, "message": "Record not found"}]);
        Some((
            404,
            json!({"success": false, "errors": errors, "result": null}),
        ))
    });
    let ids = record_ids(201);
    let result = bulk_request(&fixture, &cookie, json!({"action": "delete", "ids": ids})).await;
    assert_eq!(
        batched_ids(&fixture.take_upstream_requests(), "deletes").len(),
        2
    );
    let mut results: Vec<Value> = ids[..200]
        .iter()
        .map(|id| json!({"id": id, "ok": false, "error": "[81044] Record not found"}))
        .collect();
    results.push(json!({"id": ids[200], "ok": true}));
    assert_eq!(
        result,
        json!({"results": results, "succeeded": 1, "failed": 200})
    );
}

#[tokio::test]
async fn unconfirmed_batch_is_reported_failed_with_an_unknown_outcome() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    fixture.respond(|_| Some((200, json!({"success": true, "errors": [], "result": null}))));
    let ids = record_ids(2);
    let result = bulk_request(&fixture, &cookie, json!({"action": "delete", "ids": ids})).await;
    assert_eq!(
        (&result["succeeded"], &result["failed"]),
        (&json!(0), &json!(2))
    );
    for item in result["results"].as_array().unwrap() {
        assert_eq!(item["ok"], false, "{item}");
        let error = item["error"].as_str().unwrap();
        assert!(error.contains("outcome is unknown"), "{error}");
    }
}

#[tokio::test]
async fn revoking_the_session_during_a_batch_stops_the_later_ones() {
    let fixture = Fixture::new().await;
    let token = fixture.state.auth.setup_password_session(PASSWORD).unwrap();
    let cookie = format!("{SESSION_COOKIE}={token}");
    let state = fixture.state.clone();
    fixture.respond(move |request| {
        state.auth.destroy_session(&token);
        batch_applied(request)
    });
    let ids = record_ids(401);
    let result = bulk_request(&fixture, &cookie, json!({"action": "delete", "ids": ids})).await;
    assert_eq!(
        batched_ids(&fixture.take_upstream_requests(), "deletes"),
        [ids[..200].to_vec()]
    );
    let mut results: Vec<Value> = ids[..200]
        .iter()
        .map(|id| json!({"id": id, "ok": true}))
        .collect();
    results.extend(ids[200..].iter().map(|id| unsent(id)));
    assert_eq!(
        result,
        json!({"results": results, "succeeded": 200, "failed": 201})
    );
    assert_eq!(
        results[200]["error"],
        "session expired or revoked; write not sent"
    );
}

#[tokio::test]
async fn bulk_update_batches_one_patch_per_record_with_only_the_changed_fields() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    let ids = record_ids(201);
    // The first record is proxied, so a TTL change must leave it at Auto.
    let records: Vec<Value> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            json!({"id": id, "type": "A", "name": format!("r{i}.example.com"),
                   "content": "192.0.2.1", "proxied": i == 0, "ttl": if i == 0 { 1 } else { 300 }})
        })
        .collect();
    let listing = json!({"success": true, "errors": [], "result": records,
        "result_info": {"page": 1, "per_page": 100, "total_pages": 1, "total_count": 201}});
    fixture.respond(move |request| {
        if request.method == "GET" {
            return Some((200, listing.clone()));
        }
        batch_applied(request)
    });
    let synthetic = json!({"ttl": 600, "comment": "synthetic"});
    let tags = json!({"tags": ["test:bulk"]});
    let proxied = json!({"ttl": 1, "proxied": true});
    let dns_only = json!({"ttl": 600, "proxied": false});
    for (patch, first, rest) in [
        (
            &synthetic,
            &json!({"ttl": 1, "comment": "synthetic"}),
            &synthetic,
        ),
        (&tags, &tags, &tags),
        (&json!({"proxied": true, "ttl": 3600}), &proxied, &proxied),
        (&dns_only, &dns_only, &dns_only),
    ] {
        let body = json!({"action": "update", "ids": ids, "patch": patch});
        let result = bulk_request(&fixture, &cookie, body).await;
        assert_eq!(
            (&result["succeeded"], &result["failed"]),
            (&json!(201), &json!(0)),
            "{patch}"
        );
        let requests = fixture.take_upstream_requests();
        assert_eq!(requests[0].method, "GET");
        let batches = batched_ids(&requests[1..], "patches");
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [200, 1]);
        let items = requests[1..]
            .iter()
            .flat_map(|r| r.body["patches"].as_array().unwrap());
        for (i, item) in items.enumerate() {
            let mut expected = if i == 0 { first.clone() } else { rest.clone() };
            expected["id"] = json!(ids[i]);
            assert_eq!(item, &expected, "{patch}");
        }
    }
}

#[tokio::test]
async fn bulk_checks_every_id_before_the_first_batch() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    fixture.respond(batch_applied);
    let path = format!("/api/zones/{ZONE}/records/bulk");
    let mut late_bad_id = record_ids(300);
    late_bad_id[250] = "bad.identifier".into();
    for ids in [late_bad_id, record_ids(501)] {
        for action in ["delete", "update"] {
            let body = json!({"action": action, "ids": ids, "patch": {"ttl": 600}});
            let resp = fixture
                .send("POST", &path, Some(&cookie), body.to_string().as_bytes())
                .await;
            assert_eq!(resp.status, 400, "{action}");
        }
    }
    assert_eq!(fixture.upstream_hits(), 0);
}

#[tokio::test]
async fn appearance_save_failures_are_server_errors_without_details() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    std::fs::create_dir(fixture.dir.join("ui-settings.json")).unwrap();
    let accent = fixture
        .send(
            "POST",
            "/api/ui/accent",
            Some(&cookie),
            br##"{"accent":"#123456"}"##,
        )
        .await;
    let mut req = fixture_request("localhost:8888", None);
    req.path = "/api/ui/icon".into();
    req.query.insert("mime".into(), "image/png".into());
    req.headers
        .push(("x-requested-with".into(), "fetch".into()));
    req.headers.push(("cookie".into(), cookie.clone()));
    req.body = fixture_png();
    let icon = handle(fixture.state.clone(), req).await;
    let reset = fixture
        .send("DELETE", "/api/ui/icon", Some(&cookie), b"")
        .await;
    for resp in [accent, icon, reset] {
        assert_eq!(resp.status, 500);
        let message = body_json(&resp)["error"].as_str().unwrap().to_owned();
        assert!(
            !message.contains(fixture.dir.to_str().unwrap()),
            "{message}"
        );
        assert!(!message.contains("os error"), "{message}");
    }
}

#[tokio::test]
async fn request_bodies_reject_unknown_fields() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    for (method, path, body) in [
        (
            "POST",
            "/api/ui/accent",
            json!({"accent": "#123456", "extra": 1}),
        ),
        (
            "POST",
            "/api/auth/login",
            json!({"password": PASSWORD, "remember": true}),
        ),
        (
            "POST",
            "/api/auth/password",
            json!({"current_password": PASSWORD, "new_password": "synthetic-new",
                   "confirm": "synthetic-new", "code": null, "admin": true}),
        ),
        (
            "POST",
            &format!("/api/zones/{ZONE}/records"),
            json!({"type": "A", "name": "example.com", "content": "192.0.2.1", "zone": ZONE}),
        ),
        (
            "POST",
            &format!("/api/zones/{ZONE}/records/bulk"),
            json!({"action": "update", "ids": [ZONE], "patch": {"content": "192.0.2.1"}}),
        ),
    ] {
        let resp = fixture
            .send(method, path, Some(&cookie), body.to_string().as_bytes())
            .await;
        assert_eq!(resp.status, 400, "{path}");
    }
    assert_eq!(fixture.state.ui.accent(), None);
    assert_eq!(fixture.upstream_hits(), 0);
}

#[tokio::test]
async fn structured_data_is_rejected_for_other_record_types() {
    let fixture = Fixture::new().await;
    let cookie = fixture.login();
    let body = json!({"type": "A", "name": "example.com", "content": "192.0.2.1",
                      "data": {"priority": 1, "weight": 1, "port": 443, "target": "example.com"}});
    let path = format!("/api/zones/{ZONE}/records");
    let resp = fixture
        .send("POST", &path, Some(&cookie), body.to_string().as_bytes())
        .await;
    assert_eq!(resp.status, 400);
    assert_eq!(fixture.upstream_hits(), 0);
}

#[tokio::test]
async fn public_config_does_not_reveal_two_factor_state() {
    let fixture = Fixture::new().await;
    let config = body_json(&fixture.get("/api/config").await);
    assert!(config.get("totp_enabled").is_none(), "{config}");
    assert_eq!(config["configured"], false);
}

#[tokio::test]
async fn every_response_carries_isolation_headers() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .ui
        .set_icon("image/png", fixture_png())
        .unwrap();
    for path in [
        "/",
        "/static/app.js",
        "/static/favicon.svg",
        "/api/config",
        "/missing",
    ] {
        let resp = fixture.get(path).await;
        assert_eq!(
            header(&resp, "Cross-Origin-Opener-Policy"),
            Some("same-origin"),
            "{path}"
        );
        assert_eq!(
            header(&resp, "Cross-Origin-Resource-Policy"),
            Some("same-origin"),
            "{path}"
        );
        let permissions = header(&resp, "Permissions-Policy").unwrap_or_default();
        for feature in ["camera=()", "microphone=()", "geolocation=()"] {
            assert!(permissions.contains(feature), "{path}: {permissions}");
        }
        assert_eq!(header(&resp, "Strict-Transport-Security"), None, "{path}");
    }
    let favicon = fixture.get("/static/favicon.svg").await;
    assert_eq!(
        (favicon.status, favicon.content_type.as_str()),
        (200, "image/png")
    );
    assert_eq!(favicon.body, fixture_png());
    let policies: Vec<&str> = favicon
        .headers
        .iter()
        .filter(|(name, _)| name == "Content-Security-Policy")
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(
        policies,
        [CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'"]
    );
}

#[tokio::test]
async fn every_script_in_index_html_is_served_as_javascript() {
    let fixture = Fixture::new().await;
    let html = String::from_utf8(fixture.get("/").await.body).unwrap();
    let mut listed = Vec::new();
    for tag in html.split("<script").skip(1) {
        let (attributes, rest) = tag.split_once('>').unwrap();
        // Any text before </script> would be an inline script.
        assert!(rest.starts_with("</script>"), "inline script: {tag}");
        let src = attributes
            .split_once(" src=\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(src, _)| src)
            .unwrap_or_else(|| panic!("script without src: {attributes}"));
        let path = src
            .strip_suffix(&format!("?v={VERSION}"))
            .unwrap_or_else(|| panic!("{src} lacks the version query"));
        let resp = fixture.get(path).await;
        assert_eq!(
            (resp.status, resp.content_type.as_str()),
            (200, JAVASCRIPT),
            "{path}"
        );
        assert!(!resp.body.is_empty(), "{path}");
        assert_eq!(header(&resp, "Cache-Control"), Some("no-cache"), "{path}");
        listed.push(path);
    }
    assert_eq!(listed.last(), Some(&"/static/app.js"));
    let mut served: Vec<&str> = SCRIPTS.iter().map(|(path, _)| *path).collect();
    listed.sort_unstable();
    served.sort_unstable();
    assert_eq!(
        listed, served,
        "index.html and SCRIPTS list different files"
    );
    for path in [
        "/static/js/missing.js",
        "/static/js/",
        "/static/core.js",
        "/js/core.js",
    ] {
        assert_eq!(fixture.get(path).await.status, 404, "{path}");
    }
}

#[tokio::test]
async fn hsts_is_sent_only_for_an_https_public_origin() {
    let fixture = Fixture::with_config(|cfg| {
        cfg.public_origin = Some("https://admin.example.com".parse().unwrap());
        cfg.secure_cookies = true;
    })
    .await;
    let mut req = fixture_request("admin.example.com", None);
    req.method = "GET".into();
    req.path = "/".into();
    let resp = handle(fixture.state.clone(), req).await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        header(&resp, "Strict-Transport-Security"),
        Some("max-age=31536000")
    );
}

fn fixture_png() -> Vec<u8> {
    vec![
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 4,
        0, 0, 0, 181, 28, 12, 2, 0, 0, 0, 11, 73, 68, 65, 84, 120, 218, 99, 100, 248, 15, 0, 1, 5,
        1, 1, 39, 24, 227, 102, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ]
}

#[tokio::test]
async fn appearance_static_accent_is_csp_safe_and_refreshes_after_reset() {
    let fixture = Fixture::new().await;
    fixture.state.ui.set_accent(Some("#123456".into())).unwrap();
    let css = fixture.get("/static/style.css").await;
    assert_eq!(css.status, 200);
    assert!(String::from_utf8(css.body)
        .unwrap()
        .ends_with(":root{--accent:#123456;}"));
    let html = fixture.get("/").await;
    assert!(!String::from_utf8(html.body).unwrap().contains("<style>"));
    let csp = html
        .headers
        .iter()
        .find(|(name, _)| name == "Content-Security-Policy")
        .unwrap();
    assert!(csp.1.contains("style-src 'self'"));
    assert!(!csp.1.contains("unsafe-inline"));
    assert!(fixture
        .state
        .ui
        .set_accent(Some("red;}</style>".into()))
        .is_err());
    fixture.state.ui.set_accent(None).unwrap();
    let reset = fixture.get("/static/style.css").await;
    assert_eq!(reset.body, STYLE_CSS.as_bytes());
}

#[tokio::test]
async fn appearance_default_logo_is_independent_of_uploaded_favicon() {
    let fixture = Fixture::new().await;
    let png = fixture_png();
    fixture.state.ui.set_icon("image/png", png.clone()).unwrap();
    let logo = fixture.get("/static/default-logo.svg").await;
    assert_eq!(logo.status, 200);
    assert_eq!(logo.content_type, "image/svg+xml");
    assert_eq!(logo.body, FAVICON_SVG.as_bytes());
    let favicon = fixture.get("/static/favicon.svg").await;
    assert_eq!(favicon.content_type, "image/png");
    assert_eq!(favicon.body, png);
    fixture.state.ui.reset_icon().unwrap();
    assert_eq!(
        fixture.get("/static/favicon.svg").await.body,
        FAVICON_SVG.as_bytes()
    );
}

#[test]
fn trusted_host_and_same_origin_prevent_bootstrap_rebinding() {
    let cfg = fixture_config();
    for (host, origin, allowed) in [
        ("localhost:8888", Some("http://localhost:8888"), true),
        ("127.0.0.1:8888", None, true),
        (
            "attacker.example:8888",
            Some("http://attacker.example:8888"),
            false,
        ),
        ("localhost:8888", Some("http://attacker.example"), false),
        ("[::1]:8888", Some("http://[::1]:8888"), true),
        ("LOCALHOST:8888", Some("http://localhost:8888"), true),
        ("localhost:8888", Some("null"), false),
        ("[::1]:80", None, false),
        ("127.0.0.1:80", None, false),
        ("127.0.0.1:8888/extra", None, false),
        ("attacker@127.0.0.1:8888", None, false),
    ] {
        assert_eq!(
            request_origin_allowed(&cfg, &fixture_request(host, origin)),
            allowed,
            "{host}"
        );
    }
}

#[test]
fn trusted_proxy_origin_has_exact_host_port_and_scheme() {
    let mut cfg = fixture_config();
    cfg.public_origin = Some("https://admin.example.com".parse().unwrap());
    cfg.secure_cookies = true;
    for (host, origin, allowed) in [
        ("admin.example.com", Some("https://admin.example.com"), true),
        (
            "admin.example.com:443",
            Some("https://admin.example.com"),
            true,
        ),
        ("admin.example.com:80", None, false),
        ("admin.example.com", Some("http://admin.example.com"), false),
        ("attacker.example", None, false),
        ("127.0.0.1:8888", None, false),
        ("ADMIN.example.com", Some("https://admin.example.com"), true),
        ("admin.example.com", Some("null"), false),
    ] {
        assert_eq!(
            request_origin_allowed(&cfg, &fixture_request(host, origin)),
            allowed,
            "{host}"
        );
    }
}

#[test]
fn address_record_payloads_require_matching_family() {
    for (record_type, content) in [
        ("A", "not-an-ip"),
        ("A", "2001:db8::1"),
        ("AAAA", "192.0.2.1"),
    ] {
        let body: RecordBody = serde_json::from_value(
            json!({"type":record_type,"name":"example.com","content":content}),
        )
        .unwrap();
        assert!(
            record_payload(body).is_err(),
            "invalid address accepted for {record_type}"
        );
    }
}

#[test]
fn structured_record_data_reaches_cloudflare_unchanged() {
    for body in [
        json!({"type": "SRV", "name": "_sip._tcp.example.com", "ttl": 300, "proxied": false,
               "content": "5 5060 sip.example.com",
               "data": {"priority": 10, "weight": 5, "port": 5060, "target": "sip.example.com"}}),
        json!({"type": "CAA", "name": "example.com", "ttl": 1, "proxied": false,
               "content": "0 issue \"ca.example.net\"",
               "data": {"flags": 0, "tag": "issue", "value": "ca.example.net"}}),
        json!({"type": "HTTPS", "name": "example.com", "ttl": 3600, "proxied": false,
               "content": "1 . alpn=\"h2\"", "comment": "synthetic",
               "data": {"priority": 1, "target": ".", "value": "alpn=\"h2\""}}),
        json!({"type": "SVCB", "name": "_dns.example.com", "ttl": 60, "proxied": false,
               "content": "1 dns.example.com", "tags": ["test:svcb"],
               "data": {"priority": 1, "target": "dns.example.com"}}),
    ] {
        let payload = record_payload(serde_json::from_value(body.clone()).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(payload).unwrap(), body);
    }
}

#[test]
fn record_data_must_match_the_record_type() {
    let srv = json!({"priority": 1, "weight": 1, "port": 443, "target": "example.com"});
    let caa = json!({"flags": 0, "tag": "issue", "value": "ca.example.net"});
    for (record_type, data) in [
        ("A", Some(srv.clone())),
        ("CNAME", Some(srv.clone())),
        ("TXT", Some(json!({}))),
        ("SRV", None),
        ("SRV", Some(caa.clone())),
        (
            "SRV",
            Some(json!({"priority": 1, "weight": 1, "port": 443, "target": ""})),
        ),
        (
            "SRV",
            Some(json!({"priority": 1, "weight": 1, "port": 443, "target": "x", "extra": 1})),
        ),
        ("CAA", Some(srv.clone())),
        (
            "CAA",
            Some(json!({"flags": 0, "tag": "", "value": "ca.example.net"})),
        ),
        (
            "HTTPS",
            Some(json!({"priority": 1, "target": ".", "port": 443})),
        ),
        ("SVCB", Some(json!({"priority": 1, "target": ""}))),
    ] {
        let mut body = json!({"type": record_type, "name": "example.com", "content": "192.0.2.1"});
        if let Some(data) = data {
            body["data"] = data;
        }
        let body: RecordBody = serde_json::from_value(body).unwrap();
        assert!(record_payload(body).is_err(), "accepted {record_type} data");
    }
}

#[test]
fn structured_record_numbers_have_protocol_bounds() {
    for (record_type, data) in [
        (
            "SRV",
            json!({"priority":65536,"weight":1,"port":443,"target":"example.com"}),
        ),
        (
            "CAA",
            json!({"flags":256,"tag":"issue","value":"example.com"}),
        ),
        ("HTTPS", json!({"priority":65536,"target":"example.com"})),
    ] {
        let body: RecordBody =
            serde_json::from_value(json!({"type":record_type,"name":"example.com","data":data}))
                .unwrap();
        assert!(record_payload(body).is_err());
    }
}
