#!/usr/bin/env python3
"""Credential-free integration checks against an already-built binary or image."""

import argparse
import base64
import copy
import hashlib
import hmac
import http.client
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer
from urllib.parse import quote, parse_qs, urlparse


ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "Synthetic-smoke-password-42"
TOKEN = "synthetic-cloudflare-token-not-a-secret"
BIND_FIXTURE = """$ORIGIN example.com.
$TTL 300
import-a IN A 192.0.2.71
    AAAA 2001:db8::71
import-b IN 600 A 192.0.2.72
import-c 900 IN A 192.0.2.73
import-d A 192.0.2.74
import-alias IN CNAME import-a
import-text IN TXT "synthetic; quoted text"
"""


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def load_mock():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "smoke_mock", ROOT / "scripts" / "mock-cloudflare-api.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(
        len(module.ZONES) == 1 and module.ZONES[0]["name"] == "example.com",
        "mock fixture must contain only the synthetic example.com zone",
    )
    require(
        set(module.RECORDS) == {module.ZONES[0]["id"]},
        "mock fixture has unexpected record zones",
    )
    networks = [ipaddress.ip_network(n) for n in (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"
    )]
    for records in module.RECORDS.values():
        for record in records:
            require(
                record["name"] == "example.com"
                or record["name"].endswith(".example.com"),
                "mock record owner is outside the synthetic zone",
            )
            if record["type"] in ("A", "AAAA"):
                address = ipaddress.ip_address(record["content"])
                require(any(address in n for n in networks),
                        "mock address is outside documentation ranges")
            elif record["type"] == "CNAME":
                require(record["content"].rstrip(".") == "example.com",
                        "mock CNAME must target the synthetic zone")
            else:
                require(False, "unexpected mock seed record type; review synthetic fixture")
    for line in module.EXPORT_BIND.splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        fields = line.split(";", 1)[0].split()
        require(fields[0].rstrip(".") == "example.com"
                or fields[0].rstrip(".").endswith(".example.com"),
                "mock export owner is outside the synthetic zone")
        if "A" in fields or "AAAA" in fields:
            address = ipaddress.ip_address(fields[4])
            require(any(address in n for n in networks),
                    "mock export address is outside documentation ranges")
        elif "SOA" in fields:
            require(fields[4].endswith(".example.com.")
                    and fields[5].endswith(".example.com."),
                    "mock export SOA is not synthetic")
        else:
            require(False, "unexpected mock export record type")
    parsed = module.parse_bind(BIND_FIXTURE, "example.com")
    require([(r["name"], r["type"], r["ttl"], r["content"]) for r in parsed] == [
        ("import-a.example.com", "A", 300, "192.0.2.71"),
        ("import-a.example.com", "AAAA", 300, "2001:db8::71"),
        ("import-b.example.com", "A", 600, "192.0.2.72"),
        ("import-c.example.com", "A", 900, "192.0.2.73"),
        ("import-d.example.com", "A", 300, "192.0.2.74"),
        ("import-alias.example.com", "CNAME", 300, "import-a.example.com"),
        ("import-text.example.com", "TXT", 300, "synthetic; quoted text"),
    ], "mock BIND parser does not match the independently specified fixture")
    for invalid in ("$INCLUDE /synthetic", "$TTL 300\nx A not-an-ip",
                    "$TTL 300\nx AAAA 192.0.2.1", "$TTL 300\nx BOGUS content",
                    "$TTL 18446744073709551615h\nx A 192.0.2.1"):
        try:
            module.parse_bind(invalid, "example.com")
        except ValueError:
            continue
        raise AssertionError("mock silently accepts an invalid synthetic import")
    require(totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59) == "287082",
            "stdlib TOTP does not match the independent RFC 6238 vector")
    inherited = module.parse_bind("last.example.com. 600 IN A 192.0.2.1\nnext.example.com. IN A 192.0.2.2\n",
                                  "example.com")
    require([r["ttl"] for r in inherited] == [600, 600], "mock fails standard last explicit TTL inheritance")
    return module


class Mock:
    def __init__(self, module):
        self.module = module
        self.writes = 0
        self.calls = 0
        self.provider_calls = {}
        self.fail_ids = set()
        self.fail_names = set()
        self.malformed_zone_list = None
        self.malformed_record_list = None
        self.record_list_calls = 0
        self.malformed_import = None
        self.malformed_zone_lookup = None
        self.malformed_zone_result = None
        self.zone_queries = []
        self.hold_next_list = False
        self.list_entered = threading.Event()
        self.list_release = threading.Event()
        self.hold_mutation_id = None
        self.mutation_entered = threading.Event()
        self.mutation_release = threading.Event()
        self.lock = threading.Lock()
        owner = self

        class Handler(module.Handler):
            def route(self, method):
                providers = {
                    "/provider/invalid": (200, "not-an-address"),
                    "/provider/wrong-family": (200, "2001:db8::42"),
                    "/provider/http-error": (503, "203.0.113.99"),
                    "/provider/non-2xx": (302, "203.0.113.99"),
                    "/provider/valid-v6": (200, "2001:db8::42"),
                    "/provider/wrong-family-v6": (200, "192.0.2.42"),
                    "/provider/private": (200, "10.0.0.1"),
                    "/provider/loopback": (200, "127.0.0.1"),
                    "/provider/cloudflare": (200, "104.16.0.1"),
                    "/provider/oversized": (200, " " * 20000 + "203.0.113.99"),
                    "/provider/redirect-target": (200, "203.0.113.99"),
                }
                if self.path == "/provider/redirect":
                    with owner.lock:
                        owner.calls += 1
                        owner.provider_calls[self.path] = owner.provider_calls.get(self.path, 0) + 1
                    self.send_response(302)
                    self.send_header("Location", "/provider/redirect-target")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path in providers:
                    with owner.lock:
                        owner.calls += 1
                        owner.provider_calls[self.path] = owner.provider_calls.get(self.path, 0) + 1
                    status, text = providers[self.path]
                    return self._text(text, status)
                if self.headers.get("Authorization") != "Bearer " + TOKEN:
                    return self._json({"success": False, "errors": []}, 401)
                api_path = urlparse(self.path).path
                if method == "GET" and api_path.endswith("/zones"):
                    name = parse_qs(urlparse(self.path).query).get("name", [None])[0]
                    with owner.lock:
                        owner.zone_queries.append(name)
                    if name is not None and name == owner.malformed_zone_lookup:
                        reply = {"success": True, "errors": [], "messages": []}
                        if owner.malformed_zone_result == "null":
                            reply["result"] = None
                        return self._json(reply)
                if method == "GET" and (api_path.endswith("/dns_records") or api_path.endswith("/zones")):
                    if api_path.endswith("/dns_records"):
                        with owner.lock:
                            owner.record_list_calls += 1
                        malformed = owner.malformed_record_list
                    else:
                        malformed = owner.malformed_zone_list
                    if malformed:
                        reply = {"success": True, "errors": [], "messages": []}
                        if malformed == "null":
                            reply["result"] = None
                        return self._json(reply)
                    if api_path.endswith("/dns_records"):
                        with owner.lock:
                            hold = owner.hold_next_list
                            owner.hold_next_list = False
                        if hold:
                            zone = api_path.split("/")[-2]
                            rows = copy.deepcopy(owner.module.RECORDS[zone])
                            owner.list_entered.set()
                            owner.list_release.wait(timeout=5)
                            return self._json(module.envelope(rows))
                if method in ("POST", "PUT", "PATCH", "DELETE"):
                    with owner.lock:
                        owner.writes += 1
                if method == "POST" and api_path.endswith("/dns_records/import") and owner.malformed_import:
                    self._body()
                    reply = {"success": True, "errors": [], "messages": []}
                    if owner.malformed_import == "null":
                        reply["result"] = None
                    elif owner.malformed_import == "empty":
                        reply["result"] = {}
                    elif owner.malformed_import == "missing-added":
                        reply["result"] = {"total_records_parsed": 1}
                    elif owner.malformed_import == "missing-parsed":
                        reply["result"] = {"recs_added": 0}
                    return self._json(reply)
                if method in ("DELETE", "PATCH", "PUT") and api_path.rsplit("/", 1)[-1] == owner.hold_mutation_id:
                    owner.hold_mutation_id = None
                    owner.mutation_entered.set()
                    owner.mutation_release.wait(timeout=5)
                if method in ("PUT", "PATCH", "DELETE") and self.path.rsplit("/", 1)[-1] in owner.fail_ids:
                    return self._json({"success": False, "errors": [
                        {"code": 1000, "message": "synthetic upstream write failure"}]}, 503)
                if method == "POST" and self.path.endswith("/dns_records") and owner.fail_names:
                    payload = json.loads(self._body())
                    if payload.get("name") in owner.fail_names:
                        return self._json({"success": False, "errors": [
                            {"code": 1000, "message": "synthetic upstream create failure"}]}, 503)
                    self._body = lambda: json.dumps(payload).encode("ascii")
                return super().route(method)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server6 = None
        self.thread6 = None
        self.port6 = None
        if socket.has_ipv6:
            class IPv6Server(ThreadingHTTPServer):
                address_family = socket.AF_INET6

            try:
                self.server6 = IPv6Server(("::1", 0), Handler)
            except OSError:
                pass
            else:
                self.server6.daemon_threads = True
                self.port6 = self.server6.server_port
                self.thread6 = threading.Thread(target=self.server6.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        if self.thread6:
            self.thread6.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.server6:
            self.server6.shutdown()
            self.server6.server_close()
            self.thread6.join(timeout=5)

    def snapshot(self):
        with self.lock:
            return self.writes, copy.deepcopy(self.module.RECORDS)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wire_request(port, method, path, payload=None, cookie=None, mutation=True,
                 expected=200, content_type=None, extra_headers=None):
    headers = {}
    if mutation:
        headers["X-Requested-With"] = "fetch"
    if cookie:
        headers["Cookie"] = cookie
    if content_type:
        headers["Content-Type"] = content_type
    headers.update(extra_headers or {})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        content = response.read()
        require(TOKEN.encode() not in content, f"{path}: response exposed the server API token")
        require(response.status in (expected if isinstance(expected, tuple) else (expected,)),
                 f"{method} {path}: expected HTTP {expected}, got {response.status}")
        security = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer"}
        for key, value in security.items():
            require(response.getheader(key) == value, f"{path}: missing {key} protection")
        csp = response.getheader("Content-Security-Policy", "")
        require("frame-ancestors 'none'" in csp or (path == "/static/favicon.svg" and "sandbox" in csp),
                f"{path}: missing restrictive CSP")
        if path.startswith("/api/"):
            require(response.getheader("Cache-Control") == "no-store",
                    f"{path}: API response must not be cached")
        return content, dict(response.getheaders())
    finally:
        conn.close()


def request(port, method, path, body=None, cookie=None, mutation=True, expected=200):
    content, headers = wire_request(
        port, method, path, json.dumps(body).encode("ascii") if body is not None else None,
        cookie, mutation, expected, "application/json" if body is not None else None)
    return json.loads(content) if content else None, headers.get("Set-Cookie")


def session_cookie(header, secure):
    require(header is not None, "authentication did not issue a cookie")
    parsed = SimpleCookie()
    parsed.load(header)
    require(set(parsed) == {"cfddns_session"}, "unexpected session cookie")
    cookie = parsed["cfddns_session"]
    require(cookie["httponly"] and cookie["samesite"] == "Strict"
            and cookie["path"] == "/" and int(cookie["max-age"]) > 0,
            "session cookie lacks required security attributes")
    require(bool(cookie["secure"]) == secure, "Secure cookie configuration ignored")
    return "cfddns_session=" + cookie.value


class App:
    def __init__(self, temp, mock, image=None, serve=False, port=None):
        self.temp = Path(temp)
        self.mock = mock
        self.image = image
        self.serve = serve
        self.port = port if port is not None else free_port()
        self.process = None
        self.container = None
        self.volume = None
        self.docker = shutil.which("docker") if image else None
        self.binary = ROOT / "target" / "release" / "cloudflare-ddns-webui"
        self.host_env = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C",
                         "HOME": str(self.temp)}
        self.state_dir = self.temp / "state"
        self.state_dir.mkdir()
        self.secure = True

    def docker_run(self, *args, check=True, input_data=None, timeout=30):
        result = subprocess.run(
            [self.docker, *args], env=self.host_env, cwd=self.temp,
            input=input_data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        require(not check or result.returncode == 0,
                "Docker command failed: " + args[0])
        return result

    def environment(self, provider):
        return {
            "CLOUDFLARE_API_TOKEN": TOKEN,
            "CLOUDFLARE_API_TOKEN_FILE": "",
            "CLOUDFLARE_API_BASE": f"http://127.0.0.1:{self.mock.port}/client/v4",
            "LISTEN": f"127.0.0.1:{self.port}",
            "DATA_DIR": "/data" if self.image else str(self.state_dir),
            "DOMAINS": "example.com", "IP4_PROVIDER": provider,
            "IP6_PROVIDER": "none", "PROXIED": "false", "TTL": "300",
            "RECORD_COMMENT": "Synthetic smoke fixture", "SESSION_TTL": "300",
            "SECURE_COOKIES": "true" if self.secure else "false",
            "DETECTION_TIMEOUT": "2", "UPDATE_TIMEOUT": "5",
            "EMOJI": "false", "QUIET": "true",
        }

    def start(self, provider="literal:203.0.113.42", overrides=None):
        env = self.environment(provider)
        env.update(overrides or {})
        self.public_origin = env.get("PUBLIC_ORIGIN")
        if self.image:
            require(self.docker is not None, "docker executable is required")
            require(sys.platform.startswith("linux"),
                    "container smoke requires Linux host networking")
            if not self.volume:
                user = self.docker_run("image", "inspect", "--format",
                                       "{{.Config.User}}", self.image).stdout.strip()
                require(user == b"65534:65534", "image User must be 65534:65534")
                self.volume = "cfddns-smoke-" + uuid.uuid4().hex
                self.docker_run("volume", "create", self.volume)
            name = "cfddns-smoke-" + uuid.uuid4().hex
            args = ["create", "--name", name, "--network", "host", "--mount",
                    f"type=volume,source={self.volume},target=/data"]
            for key, value in env.items():
                args.extend(["--env", f"{key}={value}"])
            self.container = name
            self.docker_run(*args, self.image)
            if not getattr(self, "packaging_checked", False):
                archive = self.docker_run("cp", f"{name}:/data/.", "-").stdout
                with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                    members = tar.getmembers()
                    require(members and all(m.isdir() for m in members),
                            "runtime /data must contain no compiler output or files")
                    require(all(m.uid == 65534 and m.gid == 65534 for m in members),
                            "runtime /data must belong to the non-root user")
                    require(all(m.mode & 0o300 == 0o300 for m in members),
                            "runtime /data must be writable by its owner")
                self.packaging_checked = True
                if not self.serve:
                    print("PASS container user and empty writable /data packaging")
            self.docker_run("start", name)
        else:
            require(self.binary.is_file(), "build the release binary before running smoke")
            self.process = subprocess.Popen(
                [str(self.binary)], cwd=self.temp, env={**self.host_env, **env},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

    def alive(self):
        if self.image:
            return self.docker_run("inspect", "--format", "{{.State.Running}}",
                                   self.container).stdout.strip() == b"true"
        return self.process.poll() is None

    def ready(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            require(self.alive(), "application exited before readiness")
            try:
                headers = {"Host": urlparse(self.public_origin).netloc} if self.public_origin else None
                wire_request(self.port, "GET", "/api/config", extra_headers=headers)
                return
            except (OSError, http.client.HTTPException):
                time.sleep(0.05)
        raise AssertionError("application readiness timed out")

    def stop(self):
        if self.container:
            self.docker_run("rm", "--force", self.container, check=False)
            self.container = None
        if self.process:
            if self.process.poll() is None:
                self.process.send_signal(signal.SIGINT)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            self.process = None

    def close(self):
        try:
            self.stop()
        finally:
            if self.volume:
                self.docker_run("volume", "rm", "--force", self.volume, check=False)
                self.volume = None

    def expect_startup_failure(self, reason):
        try:
            if self.image:
                code = int(self.docker_run("wait", self.container, timeout=10).stdout.strip())
            else:
                code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(reason + " must fail startup") from exc
        require(code != 0, reason + " must produce a nonzero exit")
        with socket.socket() as sock:
            sock.settimeout(2)
            require(sock.connect_ex(("127.0.0.1", self.port)) != 0,
                    reason + " must not leave an HTTP listener")

    def corrupt_state(self):
        content = b"{synthetic-corrupt-state"
        if self.image:
            self.start()
            self.docker_run("stop", "--time", "2", self.container)
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as tar:
                member = tarfile.TarInfo("state.json")
                member.size = len(content)
                member.uid = member.gid = 65534
                member.mode = 0o600
                tar.addfile(member, io.BytesIO(content))
            self.docker_run("cp", "--archive", "-", f"{self.container}:/data",
                            input_data=archive.getvalue())
            self.docker_run("start", self.container)
        else:
            (self.state_dir / "state.json").write_bytes(content)
            self.start()
        self.expect_startup_failure("corrupt auth state")


def login(app):
    _, header = request(app.port, "POST", "/api/auth/login", {"password": PASSWORD})
    return session_cookie(header, app.secure)


def chunk_regression(app):
    with socket.create_connection(("127.0.0.1", app.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(
            b"POST /api/auth/setup HTTP/1.1\r\nHost: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n1\r\na\r\nffffffffffffffff\r\n"
        )
        sock.shutdown(socket.SHUT_WR)
        try:
            reply = sock.recv(4096)
        except ConnectionResetError:
            reply = b""
    require(not reply or not reply.startswith(b"HTTP/1.1 2"),
            "overflowing chunk must not be accepted")
    require(app.alive(), "max chunk after one byte crashed the application")
    try:
        request(app.port, "GET", "/api/config")
    except (OSError, http.client.HTTPException) as exc:
        raise AssertionError("application stopped serving after the max chunk") from exc


def setup_session(app, overrides=None):
    app.start(overrides=overrides)
    app.ready()
    _, header = request(app.port, "POST", "/api/auth/setup",
                        {"password": PASSWORD, "confirm": PASSWORD})
    return session_cookie(header, app.secure)


def totp(secret, timestamp=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time() if timestamp is None else timestamp) // 30),
                      hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}"


def enroll(app, cookie):
    enrollment, _ = request(app.port, "POST", "/api/auth/2fa/begin",
                            {"password": PASSWORD}, cookie=cookie)
    secret = enrollment["secret"]
    uri = urlparse(enrollment["uri"])
    require(uri.scheme == "otpauth" and parse_qs(uri.query)["secret"] == [secret],
            "enrollment URI does not carry the advertised secret")
    require("<svg" in enrollment["qr_svg"], "enrollment QR SVG is missing")
    result, header = request(app.port, "POST", "/api/auth/2fa/confirm",
                             {"code": totp(secret)}, cookie=cookie)
    require(len(result["backup_codes"]) == 8 and len(set(result["backup_codes"])) == 8,
            "enrollment must issue eight distinct recovery codes")
    return secret, result["backup_codes"], session_cookie(header, app.secure)


def challenge(app, password=PASSWORD):
    result, header = request(app.port, "POST", "/api/auth/login", {"password": password})
    require(result["requires_2fa"] is True and result["challenge"] and header is None,
            "password alone must not authenticate an enrolled account")
    return result["challenge"]


def factor_login(app, code, password=PASSWORD):
    result, header = request(app.port, "POST", "/api/auth/login/2fa",
                             {"challenge": challenge(app, password), "code": code})
    return result, session_cookie(header, app.secure)


def auth_smoke(app, mock):
    cookie = setup_session(app)
    request(app.port, "POST", "/api/auth/2fa/begin", {}, cookie=cookie, expected=400)
    request(app.port, "POST", "/api/auth/2fa/begin", {"password": "wrong-synthetic"},
            cookie=cookie, expected=401)
    enrollment, _ = request(app.port, "POST", "/api/auth/2fa/begin",
                            {"password": PASSWORD}, cookie=cookie)
    request(app.port, "POST", "/api/auth/2fa/cancel", {}, cookie=cookie)
    request(app.port, "POST", "/api/auth/2fa/confirm", {"code": totp(enrollment["secret"])},
            cookie=cookie, expected=400)
    enrollment, _ = request(app.port, "POST", "/api/auth/2fa/begin",
                            {"password": PASSWORD}, cookie=cookie)
    request(app.port, "POST", "/api/auth/2fa/confirm", {"code": "invalid"},
            cookie=cookie, expected=400)
    confirmed, header = request(app.port, "POST", "/api/auth/2fa/confirm",
                                {"code": totp(enrollment["secret"])}, cookie=cookie)
    secret, codes = enrollment["secret"], confirmed["backup_codes"]
    require(len(codes) == 8 and len(set(codes)) == 8, "invalid recovery-code enrollment result")
    old_cookie, cookie = cookie, session_cookie(header, app.secure)
    request(app.port, "GET", "/api/auth/me", cookie=old_cookie, expected=401)
    me, _ = request(app.port, "GET", "/api/auth/me", cookie=cookie)
    require(me["totp_enabled"] and me["backup_codes_remaining"] == 8,
            "confirmed enrollment is not enabled")
    require(not {"secret", "backup_codes", "totp_secret"}.intersection(me),
            "identity status leaks enrollment material")
    request(app.port, "POST", "/api/auth/2fa/begin", {"password": PASSWORD},
            cookie=cookie, expected=400)
    pending = challenge(app)
    request(app.port, "POST", "/api/auth/login/2fa",
            {"challenge": pending, "code": "invalid"}, expected=401)
    _, header = request(app.port, "POST", "/api/auth/login/2fa",
                        {"challenge": pending, "code": totp(secret)})
    cookie = session_cookie(header, app.secure)
    request(app.port, "POST", "/api/auth/login/2fa",
            {"challenge": pending, "code": totp(secret)}, expected=401)
    result, cookie = factor_login(app, codes[0].lower().replace("-", " "))
    require(result["backup_code_used"] and result["backup_codes_remaining"] == 7,
            "normalized recovery login did not consume exactly one code")
    app.stop()
    app.start()
    app.ready()
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    pending = challenge(app)
    request(app.port, "POST", "/api/auth/login/2fa",
            {"challenge": pending, "code": codes[0]}, expected=401)
    _, cookie = factor_login(app, totp(secret))
    password = "Replacement-synthetic-password-84"
    change = {"current_password": PASSWORD, "new_password": password, "confirm": password}
    request(app.port, "POST", "/api/auth/password", change, cookie=cookie, expected=401)
    request(app.port, "POST", "/api/auth/password",
            {**change, "current_password": "wrong-synthetic", "code": totp(secret)},
            cookie=cookie, expected=401)
    pending = challenge(app)
    _, header = request(app.port, "POST", "/api/auth/password",
                        {**change, "code": totp(secret)}, cookie=cookie)
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    cookie = session_cookie(header, app.secure)
    request(app.port, "POST", "/api/auth/login/2fa",
            {"challenge": pending, "code": totp(secret)}, expected=401)
    app.stop()
    app.start()
    app.ready()
    request(app.port, "POST", "/api/auth/login", {"password": PASSWORD}, expected=401)
    _, cookie = factor_login(app, totp(secret), password)
    pending = challenge(app, password)
    replacement = password + "-recovery"
    _, header = request(app.port, "POST", "/api/auth/password",
                        {"current_password": password, "code": codes[2],
                         "new_password": replacement, "confirm": replacement}, cookie=cookie)
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    cookie = session_cookie(header, app.secure)
    request(app.port, "POST", "/api/auth/login/2fa",
            {"challenge": pending, "code": totp(secret)}, expected=401)
    me, _ = request(app.port, "GET", "/api/auth/me", cookie=cookie)
    require(me["backup_codes_remaining"] == 6, "password mutation did not consume exactly one recovery code")
    password = replacement
    app.stop()
    app.start()
    app.ready()
    pending = challenge(app, password)
    request(app.port, "POST", "/api/auth/login/2fa",
            {"challenge": pending, "code": codes[2]}, expected=401)
    _, cookie = factor_login(app, totp(secret), password)
    request(app.port, "POST", "/api/auth/2fa/disable", {"code": "invalid"},
            cookie=cookie, expected=401)
    pending = challenge(app, password)
    _, header = request(app.port, "POST", "/api/auth/2fa/disable", {"code": codes[1]}, cookie=cookie)
    cookie = session_cookie(header, app.secure)
    request(app.port, "POST", "/api/auth/login/2fa",
            {"challenge": pending, "code": codes[2]}, expected=401)
    request(app.port, "POST", "/api/auth/2fa/disable", {"code": codes[2]},
            cookie=cookie, expected=400)
    me, _ = request(app.port, "GET", "/api/auth/me", cookie=cookie)
    require(not me["totp_enabled"] and me["backup_codes_remaining"] == 0,
            "disabled account retained factors")
    app.stop()
    app.start()
    app.ready()
    result, header = request(app.port, "POST", "/api/auth/login", {"password": password})
    require(result["requires_2fa"] is False, "disabled factor persisted after restart")
    session_cookie(header, app.secure)
    require(mock.writes == 0, "authentication flows unexpectedly wrote Cloudflare")
    print("PASS TOTP enrollment retry/cancel, sessions, password/factor persistence and single-use recovery")


def factor_lockout_smoke(app, mock):
    old_cookie = setup_session(app)
    secret, codes, cookie = enroll(app, old_cookie)
    pending = [challenge(app) for _ in range(6)]
    for token in pending[:5]:
        request(app.port, "POST", "/api/auth/login/2fa",
                {"challenge": token, "code": "invalid"}, expected=401)
    request(app.port, "POST", "/api/auth/login/2fa",
            {"challenge": pending[-1], "code": codes[0]}, expected=429)
    request(app.port, "POST", "/api/auth/login", {"password": PASSWORD}, expected=429)
    request(app.port, "POST", "/api/auth/2fa/disable", {"code": totp(secret)},
            cookie=cookie, expected=429)
    request(app.port, "POST", "/api/auth/password",
            {"current_password": PASSWORD, "code": codes[0],
             "new_password": PASSWORD + "-new", "confirm": PASSWORD + "-new"},
            cookie=cookie, expected=429)
    me, _ = request(app.port, "GET", "/api/auth/me", cookie=cookie)
    require(me["totp_enabled"] and me["backup_codes_remaining"] == 8,
            "locked out operations changed factors")
    require(mock.writes == 0, "factor lockout unexpectedly wrote Cloudflare")
    print("PASS account factor lockout spans challenges and sensitive operations")


def auth_storage_smoke(app, mock):
    if app.image:
        print("SKIP auth disk-failure injection requires host synthetic state access")
        return
    cookie = setup_session(app)
    secret, codes, cookie = enroll(app, cookie)
    path = app.state_dir / "state.json"
    saved = app.state_dir / "synthetic-saved-state.json"
    pending = challenge(app)
    path.rename(saved)
    path.mkdir()
    try:
        for route, body, auth_cookie in (
            ("/api/auth/login/2fa", {"challenge": pending, "code": codes[0]}, None),
            ("/api/auth/password", {"current_password": PASSWORD, "code": codes[1],
                                    "new_password": PASSWORD + "-new", "confirm": PASSWORD + "-new"}, cookie),
            ("/api/auth/2fa/disable", {"code": codes[2]}, cookie),
        ):
            result, header = request(app.port, "POST", route, body, cookie=auth_cookie, expected=500)
            require(header is None, route + ": failed persistence issued an authentication cookie")
            require(not {"secret", "backup_codes", "totp_secret", "backup_code_hashes"}.intersection(result)
                    and all(value not in json.dumps(result) for value in (PASSWORD, secret, *codes)),
                    route + ": failed persistence disclosed authentication material")
        me, _ = request(app.port, "GET", "/api/auth/me", cookie=cookie)
        require(me["totp_enabled"] and me["backup_codes_remaining"] == 8,
                "failed saves changed in-memory identity or consumed recovery codes")
    finally:
        path.rmdir()
        saved.rename(path)
    app.stop()
    app.start()
    app.ready()
    result, cookie = factor_login(app, codes[0])
    require(result["backup_codes_remaining"] == 7, "failed-save recovery code lost on restart")
    _, cookie = factor_login(app, totp(secret))
    print("PASS recovery/password/disable disk failures preserve identity and codes across restart")


def enrollment_storage_smoke(app, mock):
    if app.image:
        print("SKIP setup/enrollment disk-failure injection requires host synthetic state access")
        return
    app.start()
    app.ready()
    path = app.state_dir / "state.json"
    path.mkdir()
    try:
        result, header = request(app.port, "POST", "/api/auth/setup",
                                 {"password": PASSWORD, "confirm": PASSWORD}, expected=(400, 500))
        require(header is None and PASSWORD not in json.dumps(result),
                "failed setup save issued a cookie or disclosed the synthetic password")
        config, _ = request(app.port, "GET", "/api/config")
        require(not config["configured"], "failed setup persisted an in-memory administrator")
    finally:
        path.rmdir()
    _, header = request(app.port, "POST", "/api/auth/setup",
                        {"password": PASSWORD, "confirm": PASSWORD})
    cookie = session_cookie(header, app.secure)
    enrollment, _ = request(app.port, "POST", "/api/auth/2fa/begin",
                            {"password": PASSWORD}, cookie=cookie)
    saved = app.state_dir / "synthetic-saved-state.json"
    path.rename(saved)
    path.mkdir()
    try:
        result, header = request(app.port, "POST", "/api/auth/2fa/confirm",
                                 {"code": totp(enrollment["secret"])}, cookie=cookie, expected=500)
        require(header is None, "failed enrollment save issued an authentication cookie")
        require(not {"secret", "backup_codes", "totp_secret", "backup_code_hashes"}.intersection(result)
                and enrollment["secret"] not in json.dumps(result),
                "failed enrollment save disclosed factor material")
        me, _ = request(app.port, "GET", "/api/auth/me", cookie=cookie)
        require(not me["totp_enabled"] and me["backup_codes_remaining"] == 0,
                "failed enrollment save enabled 2FA or issued recovery codes")
    finally:
        path.rmdir()
        saved.rename(path)
    result, header = request(app.port, "POST", "/api/auth/2fa/confirm",
                             {"code": totp(enrollment["secret"])}, cookie=cookie)
    cookie = session_cookie(header, app.secure)
    require(len(result["backup_codes"]) == 8, "failed save lost pending enrollment")
    if os.name == "posix":
        require(path.stat().st_mode & 0o077 == 0, "credential snapshot permits group/other access")
    app.stop()
    app.start()
    app.ready()
    _, cookie = factor_login(app, totp(enrollment["secret"]))
    require(mock.writes == 0, "setup/enrollment unexpectedly wrote Cloudflare")
    print("PASS failed setup/enrollment saves rollback, retry, restrictive permissions and restart")


def metadata_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    path = f"/api/zones/{zone}/records"
    payload = {"type": "A", "name": "metadata.example.com", "content": "192.0.2.81",
               "ttl": 300, "proxied": False, "comment": "seed-comment", "tags": ["test:seed"]}
    row, _ = request(app.port, "POST", path, payload, cookie=cookie, expected=201)
    rid = row["id"]
    basic = {k: v for k, v in payload.items() if k not in ("comment", "tags")}
    for fields, comment, tags in (({}, "seed-comment", ["test:seed"]),
                                  ({"comment": "new-comment", "tags": ["test:new"]},
                                   "new-comment", ["test:new"]),
                                  ({"comment": "", "tags": []}, "", [])):
        row, _ = request(app.port, "PUT", path + "/" + rid, {**basic, **fields}, cookie=cookie)
        require((row["comment"] or "") == comment and row["tags"] == tags,
                "record PUT lost keep/set/clear metadata semantics")
    request(app.port, "PUT", path + "/" + rid, payload, cookie=cookie)
    for fields, comment, tags in (({"ttl": 600}, "seed-comment", ["test:seed"]),
                                  ({"comment": "bulk-comment", "tags": ["test:bulk"]},
                                   "bulk-comment", ["test:bulk"]),
                                  ({"comment": "", "tags": []}, "", [])):
        result, _ = request(app.port, "POST", path + "/bulk",
                             {"action": "update", "ids": [rid], "patch": fields}, cookie=cookie)
        require(result["succeeded"] == 1 and result["failed"] == 0,
                "bulk metadata update falsely reported failure")
        row = next(r for r in mock.snapshot()[1][zone] if r["id"] == rid)
        require((row["comment"] or "") == comment and row["tags"] == tags,
                "bulk update lost keep/set/clear metadata semantics")
    result, _ = request(app.port, "POST", path + "/bulk",
                         {"action": "update", "ids": [rid], "patch": {"proxied": True, "ttl": 3600}},
                         cookie=cookie)
    row = next(r for r in mock.snapshot()[1][zone] if r["id"] == rid)
    require(result["succeeded"] == 1 and row["proxied"] and row["ttl"] == 1,
            "bulk enabling proxy failed to force automatic TTL")
    request(app.port, "POST", path + "/bulk",
            {"action": "update", "ids": [rid], "patch": {"ttl": 600}}, cookie=cookie)
    row = next(r for r in mock.snapshot()[1][zone] if r["id"] == rid)
    require(row["ttl"] == 1, "TTL-only bulk patch changed a proxied record away from auto")
    request(app.port, "POST", path + "/bulk",
            {"action": "update", "ids": [rid], "patch": {"proxied": False, "ttl": 600}}, cookie=cookie)
    row = next(r for r in mock.snapshot()[1][zone] if r["id"] == rid)
    require(row["ttl"] == 600 and not row["proxied"], "DNS-only bulk patch lost explicit TTL")
    other, _ = request(app.port, "POST", path, {**basic, "name": "partial.example.com"},
                        cookie=cookie, expected=201)
    mock.fail_ids.add(other["id"])
    for action, patch in (("update", {"comment": "partial-success"}), ("delete", None)):
        failed_before = next(r for r in mock.snapshot()[1][zone] if r["id"] == other["id"])
        result, _ = request(app.port, "POST", path + "/bulk",
                             {"action": action, "ids": [rid, other["id"]], "patch": patch}, cookie=cookie)
        require(result["succeeded"] == 1 and result["failed"] == 1
                and len(result["results"]) == 2, "partial bulk failure totals are inaccurate")
        results = {r["id"]: r for r in result["results"]}
        require(results[rid]["ok"] and not results[other["id"]]["ok"]
                and results[other["id"]]["error"], "bulk hid per-record upstream failure")
        records = mock.snapshot()[1][zone]
        require(next(r for r in records if r["id"] == other["id"]) == failed_before,
                "partial upstream failure changed the failed record")
        if action == "update":
            require(next(r for r in records if r["id"] == rid)["comment"] == "partial-success",
                    "partial result claimed success without applying the successful patch")
        else:
            require(all(r["id"] != rid for r in records),
                    "partial delete claimed success without deleting the successful record")
    print("PASS PUT/bulk metadata keep/set/clear, proxy TTL and per-record partial failures")


def identifier_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    rid = mock.module.RECORDS[zone][0]["id"]
    path = f"/api/zones/{zone}/records"
    before = mock.snapshot()
    for invalid in ("../" + rid, "../../../zones/" + zone, rid + "?x=1", rid + "#suffix",
                    "", "bad\\identifier", rid + "/extra", "bad.identifier"):
        for action in ("delete", "update"):
            request(app.port, "POST", path + "/bulk",
                    {"action": action, "ids": [rid, invalid], "patch": {"ttl": 600}},
                    cookie=cookie, expected=400)
            require(mock.snapshot() == before, "bulk invalid identifier caused a write before validation")
    for ids in ([], [rid, rid], [rid] * 501):
        request(app.port, "POST", path + "/bulk", {"action": "delete", "ids": ids},
                cookie=cookie, expected=400)
        require(mock.snapshot() == before, "bulk invalid list caused upstream writes")
    for invalid in ("bad.identifier", zone + "%3Fquery", zone + "%23fragment", ".."):
        request(app.port, "DELETE", f"/api/zones/{invalid}/records/{rid}", cookie=cookie, expected=400)
        require(mock.snapshot() == before, "unsafe zone path reached upstream mutation")
    for invalid in ("bad.identifier", rid + "%3Fquery", rid + "%23fragment"):
        request(app.port, "DELETE", path + "/" + invalid, cookie=cookie, expected=400)
        require(mock.snapshot() == before, "unsafe record path reached upstream mutation")
    bind = b"safe.example.com. 300 IN A 192.0.2.99\n"
    for filename in ("../zone.txt", "a/b.txt", "a\\b.txt", 'a".txt',
                     "a\r\nX-Synthetic: injected", "", ".."):
        wire_request(app.port, "POST", f"/api/zones/{zone}/import?filename={quote(filename, safe='')}",
                     bind, cookie, expected=400, content_type="text/plain")
        require(mock.snapshot() == before, "invalid multipart filename issued upstream write")
    print("PASS unsafe identifiers, duplicates and multipart filenames rejected with zero upstream writes")


def bind_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    path = f"/api/zones/{zone}/import?filename=synthetic-zone.txt"
    exported, headers = wire_request(app.port, "GET", f"/api/zones/{zone}/export", cookie=cookie)
    require(exported.decode() == mock.module.EXPORT_BIND
            and "attachment" in headers.get("Content-Disposition", ""), "BIND export is wrong")
    before = mock.snapshot()
    content, _ = wire_request(app.port, "POST", path, exported, cookie, content_type="text/plain")
    require(json.loads(content) == {"recs_added": 0, "total_records_parsed": 3}
            and mock.snapshot()[1] == before[1], "export/reimport changed existing synthetic DNS records")
    content, _ = wire_request(app.port, "POST", path, BIND_FIXTURE.encode(), cookie, content_type="text/plain")
    result = json.loads(content)
    require(result["recs_added"] == 7 and result["total_records_parsed"] == 7,
            "valid default-TTL/class/owner BIND fixture import counts are wrong")
    imported = [r for r in mock.snapshot()[1][zone] if r["name"].startswith("import-")]
    require(len(imported) == 7, "mock import did not actually create the expected records")
    require(next(r for r in imported if r["name"] == "import-b.example.com")["ttl"] == 600
            and next(r for r in imported if r["type"] == "TXT")["content"] == "synthetic; quoted text",
            "import lost explicit class-first TTL or quoted semicolon content")
    before = mock.snapshot()
    content, _ = wire_request(app.port, "POST", path, BIND_FIXTURE.encode(), cookie, content_type="text/plain")
    require(json.loads(content)["recs_added"] == 0, "reimport duplicated existing records")
    require(mock.snapshot()[1] == before[1], "duplicate reimport mutated existing records")
    for invalid in (b"", b"\xff", b"$INCLUDE /synthetic\n", b"$GENERATE 1-5 x A 192.0.2.1\n",
                    b"$TTL nope\nx IN A 192.0.2.1\n", b"$TTL 300\nx IN A not-an-ip\n",
                    b"$TTL 300\nx IN AAAA 192.0.2.1\n", b"$TTL 300\nx BOGUS content\n",
                    b"$TTL 300\nx IN A 192.0.2.1\nx IN A 192.0.2.1\n"):
        before = mock.snapshot()
        wire_request(app.port, "POST", path, invalid, cookie, expected=400, content_type="text/plain")
        require(mock.snapshot() == before, "invalid/duplicate BIND file reached upstream import")
    print("PASS BIND default TTL, class order, inherited/relative owners, export/reimport and invalid preflight")


def bind_edge_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    path = f"/api/zones/{zone}/import?filename=synthetic-zone.txt"
    bind = b"last.example.com. 600 IN A 192.0.2.31\nnext.example.com. IN A 192.0.2.32\n"
    content, _ = wire_request(app.port, "POST", path, bind, cookie, content_type="text/plain")
    require(json.loads(content)["recs_added"] == 2, "last explicit TTL inheritance import count is wrong")
    imported = [r for r in mock.snapshot()[1][zone] if r["name"] in ("last.example.com", "next.example.com")]
    require(len(imported) == 2 and all(r["ttl"] == 600 for r in imported),
            "last explicit TTL inheritance did not reach correctly parsed records")
    for invalid in (
        b"$TTL 300\nfoo..example.com. A 192.0.2.1\n",
        b"$TTL 300\n@ CAA 0 !!! \"example.com\"\n",
        b"$TTL 300\n@ HTTPS 1 . port=banana\n",
        b"$TTL 300\nx AAAA 2001:db8::1\nx AAAA 2001:0db8:0:0:0:0:0:1\n",
        b"$TTL 300\nx CNAME WWW.EXAMPLE.COM.\nx CNAME www.example.com.\n",
        b"$ORIGIN example.com.\n$TTL 300\nx A 192.0.2.1\nx.example.com. 600 IN A 192.0.2.1\n",
        ("$ORIGIN " + ".".join(["a" * 63, "b" * 63, "c" * 63, "com"]) + ".\n"
         "$ORIGIN " + "d" * 63 + "\n$TTL 300\n@ A 192.0.2.1\n").encode(),
        ("$ORIGIN " + ".".join(["a" * 63, "b" * 63, "c" * 63, "com"]) + ".\n"
         "$TTL 300\n@ CNAME " + "d" * 63 + "\n").encode(),
    ):
        before = mock.snapshot()
        wire_request(app.port, "POST", path, invalid, cookie, expected=400, content_type="text/plain")
        require(mock.snapshot() == before, "malformed/canonically duplicate BIND file reached upstream")
        require(app.alive(), "invalid expanded BIND owner crashed the release process")
        request(app.port, "GET", "/api/auth/me", cookie=cookie)
    print("PASS BIND last explicit TTL inheritance, malformed names/data and canonical duplicate refusal")


def customization_smoke(app, mock):
    cookie = setup_session(app)
    png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
    wire_request(app.port, "POST", "/api/ui/icon?mime=image/png", png, expected=401,
                 content_type="image/png")
    wire_request(app.port, "POST", "/api/ui/icon?mime=image/png", png, cookie,
                 mutation=False, expected=403, content_type="image/png")
    request(app.port, "POST", "/api/ui/accent", {"accent": "red;}</style><script>synthetic</script>"},
            cookie=cookie, expected=400)
    request(app.port, "POST", "/api/ui/accent", {"accent": "123ABC"}, cookie=cookie)
    wire_request(app.port, "POST", "/api/ui/icon?mime=image/png", png, cookie, content_type="image/png")
    for mime, body in (("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'><rect/></svg>"),
                       ("image/svg+xml", b"<svg><s:script xmlns:s='http://www.w3.org/2000/svg'>synthetic</s:script></svg>"),
                       ("image/png", b"<svg onload = 'synthetic'/>"),
                       ("image/jpeg", png), ("image/png", png[:33]),
                       ("image/png", b""), ("image/png", b"x" * (512 * 1024 + 1)),
                       ("text/html", b"<html>synthetic</html>")):
        wire_request(app.port, "POST", "/api/ui/icon?mime=" + quote(mime, safe=""), body,
                     cookie, expected=400, content_type=mime)
        content, headers = wire_request(app.port, "GET", "/static/favicon.svg")
        require(content == png and headers["Content-Type"] == "image/png",
                "rejected upload changed the saved safe raster")
        csp = headers.get("Content-Security-Policy", "")
        require("sandbox" in csp and "default-src 'none'" in csp,
                "uploaded raster lacks the required sandbox and deny-all favicon CSP")
    app.stop()
    app.start()
    app.ready()
    cookie = login(app)
    config, _ = request(app.port, "GET", "/api/config")
    require(config["has_icon"] and config["accent"] == "#123ABC", "customization lost after restart")
    content, headers = wire_request(app.port, "GET", "/static/favicon.svg")
    require(content == png and headers["Content-Type"] == "image/png", "persisted raster differs")
    csp = headers.get("Content-Security-Policy", "")
    require("sandbox" in csp and "default-src 'none'" in csp,
            "persisted raster lacks the required sandbox and deny-all favicon CSP")
    for path in ("/", "/static/style.css", "/static/app.js"):
        wire_request(app.port, "GET", path)
    request(app.port, "DELETE", "/api/ui/icon", cookie=cookie)
    config, _ = request(app.port, "GET", "/api/config")
    require(not config["has_icon"], "icon reset was not reported")
    require(mock.writes == 0, "customization unexpectedly wrote Cloudflare")
    print("PASS raster upload persistence, SVG/spoof rejection, accent validation and security headers")


def config_smoke(app, mock):
    cases = [("TTL", value) for value in ("0", "2", "-1", "86401", "invalid")]
    cases += [(name, "invalid") for name in ("PROXIED", "SECURE_COOKIES", "EMOJI", "QUIET",
                                             "GUI_SHARED_UPDATER_PAUSED")]
    cases += [(name, value) for name in ("SESSION_TTL", "UPDATE_TIMEOUT", "DETECTION_TIMEOUT")
              for value in ("0", "invalid", "18446744073709551615h")]
    cases += [("IP4_PROVIDER", "unknown-provider"), ("GUI_DDNS_CONTRACT", "unknown-v1"),
              ("IP4_PROVIDER", "literal:2001:db8::1"), ("IP4_PROVIDER", "literal:192.0.2.1,192.0.2.2"),
              ("PUBLIC_ORIGIN", "http://attacker.example"),
              ("PUBLIC_ORIGIN", "https://trusted.example/path"),
              ("CLOUDFLARE_API_BASE", "http://192.0.2.1/client/v4"),
              ("GUI_DDNS_CONTRACT", "shared-v1"), ("MANAGED_RECORDS_COMMENT_REGEX", ".*")]
    cases += [(name, "") for name in ("UPDATE_CRON", "UPDATE_ON_START", "DELETE_ON_STOP",
                                      "DELETE_ON_FAILURE", "WAF_LISTS", "SHOUTRRR", "HEALTHCHECKS",
                                      "CONFIG_PATH", "CF_API_TOKEN", "IP4_POLICY", "PUID",
                                      "DOMAINS_GROUP", "IP4_PROVIDER_GROUP")]
    failures = []
    for name, value in cases:
        app.start(overrides={name: value})
        try:
            if app.image:
                try:
                    code = int(app.docker_run("wait", app.container, timeout=2).stdout.strip())
                except subprocess.TimeoutExpired:
                    failures.append(name + "=" + value)
                    continue
            else:
                try:
                    code = app.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    failures.append(name + "=" + value)
                    continue
            require(code != 0, "invalid synthetic configuration exited successfully")
            with socket.socket() as sock:
                sock.settimeout(1)
                require(sock.connect_ex(("127.0.0.1", app.port)) != 0,
                        "invalid configuration left HTTP listener")
        finally:
            app.stop()
    require(not failures, "invalid environment settings silently accepted: " + ", ".join(failures))
    require(mock.writes == 0, "invalid configuration issued upstream writes")
    print("PASS strict TTL/boolean/duration/provider/contract environment rejection")


def origin_smoke(app, mock):
    app.start()
    app.ready()
    before = mock.snapshot()
    setup = json.dumps({"password": PASSWORD, "confirm": PASSWORD}).encode()
    for headers in ({"Host": "attacker.example"},
                    {"Origin": "https://attacker.example"},
                    {"Host": "attacker.example", "Origin": "https://attacker.example"}):
        wire_request(app.port, "GET", "/api/config", extra_headers=headers, expected=403)
        wire_request(app.port, "POST", "/api/auth/setup", setup, expected=403,
                     content_type="application/json", extra_headers=headers)
    config, _ = request(app.port, "GET", "/api/config")
    require(not config["configured"] and mock.snapshot() == before,
            "untrusted host/origin configured identity or upstream")
    _, header = request(app.port, "POST", "/api/auth/setup",
                        {"password": PASSWORD, "confirm": PASSWORD})
    cookie = session_cookie(header, app.secure)
    wire_request(app.port, "POST", "/api/ddns/update", b"{}", cookie, expected=403,
                 content_type="application/json", extra_headers={"Origin": "https://attacker.example"})
    require(mock.snapshot() == before, "cross-origin session mutation reached upstream")
    app.stop()
    app.start(overrides={"PUBLIC_ORIGIN": "https://admin.example.com"})
    app.ready()
    wire_request(app.port, "GET", "/api/config", extra_headers={"Host": "admin.example.com",
                 "Origin": "https://admin.example.com"})
    wire_request(app.port, "GET", "/api/config", expected=403,
                 extra_headers={"Host": "attacker.example"})
    print("PASS untrusted Host/Origin rejection and exact configured reverse-proxy origin")


def ddns_contract_smoke(app, mock):
    zone = mock.module.ZONES[0]["id"]
    cookie = setup_session(app, {"DOMAINS": "", "IP4_DOMAINS": "example.com",
                                "IP6_DOMAINS": "www.example.com",
                                "IP6_PROVIDER": "literal:2001:db8::42"})
    status, _ = request(app.port, "GET", "/api/ddns/status", cookie=cookie)
    require(status["contract_version"] == "standalone-v1" and status["daemon_status"] == "not_observed"
            and status["manual_updates_enabled"], "DDNS status claims unsupported daemon observation")
    before = mock.snapshot()
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(result["success"] and result["outcomes"], "family-specific DDNS failed")
    records = mock.snapshot()[1][zone]
    require(next(r for r in records if r["name"] == "example.com" and r["type"] == "A")["content"]
            == "203.0.113.42", "IP4_DOMAINS not applied")
    require(next(r for r in records if r["name"] == "www.example.com" and r["type"] == "AAAA")["content"]
            == "2001:db8::42", "IP6_DOMAINS not applied")
    require([r for r in records if r["name"] == "example.com" and r["type"] == "AAAA"]
            == [r for r in before[1][zone] if r["name"] == "example.com" and r["type"] == "AAAA"],
            "family-specific configuration touched excluded AAAA")
    before = mock.snapshot()
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(result["success"] and all(o["status"] in ("unchanged", "skipped") for o in result["outcomes"])
            and mock.snapshot() == before, "unchanged DDNS performed unnecessary writes")
    app.stop()
    app.start(overrides={"DOMAINS": "example.com,www.example.com"})
    app.ready()
    cookie = login(app)
    apex = next(r for r in mock.module.RECORDS[zone] if r["type"] == "A" and r["name"] == "example.com")
    apex["content"] = "192.0.2.19"
    mock.fail_ids.add(apex["id"])
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(not result["success"] and any(o["status"] == "failed" and o["error"] for o in result["outcomes"])
            and any(o["status"] in ("created", "updated", "unchanged") for o in result["outcomes"]),
            "partial DDNS upstream failure reported as full success")
    require(apex["content"] == "192.0.2.19", "failed DDNS overwrote existing content")
    mock.fail_ids.clear()
    app.stop()
    shared = {"GUI_DDNS_CONTRACT": "shared-v1", "RECORD_COMMENT": "owned-synthetic",
              "MANAGED_RECORDS_COMMENT_REGEX": "^owned-synthetic$"}
    for overrides in (shared, {**shared, "GUI_SHARED_UPDATER_PAUSED": "false"}):
        before = mock.snapshot()
        app.start(overrides=overrides)
        app.expect_startup_failure("shared contract without explicit paused-updater confirmation")
        require(mock.snapshot() == before, "unconfirmed shared contract issued upstream writes")
        app.stop()
    app.start(overrides={**shared, "GUI_SHARED_UPDATER_PAUSED": "true"})
    app.ready()
    cookie = login(app)
    before = mock.snapshot()
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(not result["success"] and mock.snapshot() == before,
            "shared contract mutated an unowned existing DNS record")
    apex["comment"] = "owned-synthetic"
    duplicate = copy.deepcopy(apex)
    duplicate["id"] = "abcdef0123456789abcdef0123456789"
    mock.module.RECORDS[zone].append(duplicate)
    before = mock.snapshot()
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(not result["success"] and mock.snapshot() == before,
            "shared contract reconciled duplicates without explicit supported policy")
    mock.module.RECORDS[zone].remove(duplicate)
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(result["success"] and apex["content"] == "203.0.113.42",
            "shared exact-comment owner was not updated")
    print("PASS structured DDNS families, unchanged writes, partial failures, ownership and duplicate refusal")


def provider_smoke(app, mock):
    cookie = setup_session(app)
    for kind in ("private", "loopback", "cloudflare", "oversized", "redirect"):
        app.stop()
        app.start("url:http://127.0.0.1:" + str(mock.port) + "/provider/" + kind)
        app.ready()
        cookie = login(app)
        before = mock.snapshot()
        result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
        require(not result["success"] and any(o["status"] == "failed" for o in result["outcomes"]),
                f"{kind} fetched provider value was not rejected")
        require(mock.snapshot() == before, f"{kind} provider failure changed DNS")
    require(mock.provider_calls.get("/provider/redirect", 0) > 0
            and not mock.provider_calls.get("/provider/redirect-target", 0),
            "provider redirect was followed")
    if mock.port6 is None:
        print("SKIP IPv6 provider transport: host has no usable ::1 listener")
        return
    app.stop()
    app.start(overrides={"IP4_PROVIDER": "none",
                         "IP6_PROVIDER": f"url:http://[::1]:{mock.port6}/provider/wrong-family-v6"})
    app.ready()
    cookie = login(app)
    before = mock.snapshot()
    status, _ = request(app.port, "GET", "/api/ddns/status", cookie=cookie)
    require(status["ipv6"] is None and status["ipv6_error"], "IPv6 family mismatch not reported")
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(not result["success"] and mock.snapshot() == before, "IPv6 family mismatch issued writes")
    app.stop()
    app.start(overrides={"IP4_PROVIDER": "none",
                         "IP6_PROVIDER": f"url:http://[::1]:{mock.port6}/provider/valid-v6"})
    app.ready()
    cookie = login(app)
    before = mock.snapshot()
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(result["success"], "valid loopback synthetic IPv6 detection failed")
    zone = mock.module.ZONES[0]["id"]
    records = mock.snapshot()[1][zone]
    require(next(r for r in records if r["name"] == "example.com" and r["type"] == "AAAA")["content"]
            == "2001:db8::42", "IPv6 provider failed to update AAAA")
    require([r for r in records if r["type"] == "A"] == [r for r in before[1][zone] if r["type"] == "A"],
            "IPv4 disabled did not preserve A records")
    print("PASS bounded providers, redirect/private/Cloudflare refusal and IPv6 family/preservation")


def malformed_upstream_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    for kind in ("missing", "null"):
        mock.malformed_zone_list = kind
        before = mock.snapshot()
        request(app.port, "GET", "/api/zones", cookie=cookie, expected=502)
        result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
        require(not result["success"] and any(o["status"] == "failed" for o in result["outcomes"]),
                "malformed upstream zone list was treated as a valid empty zone")
        require(mock.snapshot() == before, "malformed upstream zone list caused DNS creation")
        mock.malformed_zone_list = None
        mock.malformed_record_list = kind
        request(app.port, "GET", f"/api/zones/{zone}/records", cookie=cookie, expected=502)
        mock.zone_queries.clear()
        calls = mock.record_list_calls
        result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
        require(not result["success"] and any(o["status"] == "failed" for o in result["outcomes"]),
                "malformed upstream record list was treated as valid empty DNS")
        require(mock.zone_queries == ["example.com"] and mock.record_list_calls == calls + 1,
                "record-list failure fixture was not exercised after valid zone discovery")
        require(mock.snapshot() == before, "malformed upstream record list caused DNS creation")
        mock.malformed_record_list = None
    app.stop()
    app.start(overrides={"DOMAINS": "sub.example.com"})
    app.ready()
    cookie = login(app)
    for kind in ("missing", "null"):
        mock.malformed_zone_lookup = "sub.example.com"
        mock.malformed_zone_result = kind
        mock.zone_queries.clear()
        before = mock.snapshot()
        result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
        require(not result["success"] and any(o["status"] == "failed" for o in result["outcomes"]),
                "malformed exact zone lookup was treated as a legitimate empty zone")
        require(mock.zone_queries == ["sub.example.com"] and mock.snapshot() == before,
                "malformed exact zone lookup fell back to the parent or wrote DNS")
    mock.malformed_zone_lookup = None
    mock.zone_queries.clear()
    before = mock.snapshot()
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(result["success"] and mock.zone_queries == ["sub.example.com", "example.com"],
            "valid empty exact zone lookup did not allow the supported parent lookup")
    after = mock.snapshot()
    require(after[0] == before[0] + 1 and any(r["name"] == "sub.example.com" and r["type"] == "A"
            and r["content"] == "203.0.113.42" for r in after[1][zone]),
            "valid parent-zone fallback did not create the requested synthetic subdomain")
    print("PASS malformed lists/exact-zone lookups fail closed; legitimate empty zone permits parent fallback")


def malformed_import_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    bind = b"malformed-import.example.com. 300 IN A 192.0.2.87\n"
    for kind in ("missing", "null", "empty", "missing-added", "missing-parsed"):
        mock.malformed_import = kind
        before = mock.snapshot()
        wire_request(app.port, "POST", f"/api/zones/{zone}/import?filename=synthetic-zone.txt",
                     bind, cookie, expected=502, content_type="text/plain")
        after = mock.snapshot()
        require(after[0] == before[0] + 1 and after[1] == before[1],
                "malformed import response fixture was not exercised as one upstream request")
    print("PASS missing/null/empty/partial upstream import results surface 502 without retry or false success")


def concurrent_ddns_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    mock.module.RECORDS[zone] = [r for r in mock.module.RECORDS[zone] if r["type"] != "A"]
    before = mock.snapshot()
    mock.hold_next_list = True
    results, failures = {}, []
    second_done = threading.Event()

    def update(second=False):
        try:
            result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie,
                                expected=409 if second else 200)
            results["second" if second else "first"] = result
        except (AssertionError, OSError, http.client.HTTPException) as exc:
            failures.append(str(exc))
        finally:
            if second:
                second_done.set()

    first = threading.Thread(target=update, daemon=True)
    second = threading.Thread(target=update, args=(True,), daemon=True)
    first.start()
    try:
        require(mock.list_entered.wait(timeout=5), "first DDNS request never reached the held DNS snapshot")
        second.start()
        require(second_done.wait(timeout=2), "second DDNS request did not return while the first GET was held")
        require(not failures and "second" in results,
                "second DDNS request must return 409 before releasing the first GET: " + ", ".join(failures))
        require(first.is_alive() and mock.snapshot() == before,
                "held first DDNS cycle unexpectedly settled or wrote before release")
    finally:
        mock.list_release.set()
        first.join(timeout=10)
        if second.ident is not None:
            second.join(timeout=10)
    require(not first.is_alive() and not second.is_alive() and not failures,
            "concurrent DDNS failed or did not settle: " + ", ".join(failures))
    require(len(results) == 2 and results["first"].get("success") is True,
            "concurrent DDNS returned no successful update")
    after = mock.snapshot()
    apex = [r for r in after[1][zone] if r["type"] == "A" and r["name"] == "example.com"]
    require(after[0] == before[0] + 1 and len(apex) == 1 and apex[0]["content"] == "203.0.113.42",
            "two concurrent GUI DDNS cycles created duplicate records")
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(result["success"] and mock.snapshot() == after,
            "DDNS singleflight guard failed to reset after the first cycle completed")
    print("PASS held DDNS cycle rejects concurrent request with 409, creates one record and resets guard")


def bulk_revocation_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    ids = [r["id"] for r in mock.module.RECORDS[zone]][:2]
    mock.hold_mutation_id = ids[0]
    before = mock.snapshot()
    results, failures = [], []

    def bulk():
        try:
            result, _ = request(app.port, "POST", f"/api/zones/{zone}/records/bulk",
                                {"action": "delete", "ids": ids}, cookie=cookie)
            results.append(result)
        except (AssertionError, OSError, http.client.HTTPException) as exc:
            failures.append(str(exc))

    thread = threading.Thread(target=bulk, daemon=True)
    thread.start()
    try:
        require(mock.mutation_entered.wait(timeout=5), "first bulk delete did not reach the upstream hold")
        password = PASSWORD + "-revoked"
        _, header = request(app.port, "POST", "/api/auth/password",
                            {"current_password": PASSWORD, "new_password": password, "confirm": password},
                            cookie=cookie)
        new_cookie = session_cookie(header, app.secure)
        request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
        request(app.port, "GET", "/api/auth/me", cookie=new_cookie)
    finally:
        mock.mutation_release.set()
        thread.join(timeout=10)
    require(not thread.is_alive() and not failures and len(results) == 1,
            "bulk after revocation did not settle: " + ", ".join(failures))
    result = results[0]
    require(result["succeeded"] == 1 and result["failed"] == 1,
            "bulk continued reporting full success after session revocation")
    per_record = {r["id"]: r for r in result["results"]}
    require(per_record[ids[0]]["ok"] and not per_record[ids[1]]["ok"]
            and per_record[ids[1]]["error"], "bulk failed to report unsent revoked item")
    after = mock.snapshot()
    require(after[0] == before[0] + 1 and all(r["id"] != ids[0] for r in after[1][zone])
            and any(r["id"] == ids[1] for r in after[1][zone]),
            "bulk sent a new upstream mutation after originating session was revoked")
    print("PASS session revocation stops unsent bulk writes and reports partial outcome")


def ddns_revocation_smoke(app, mock):
    cookie = setup_session(app, {"IP6_PROVIDER": "literal:2001:db8::42"})
    zone = mock.module.ZONES[0]["id"]
    apex = next(r for r in mock.module.RECORDS[zone] if r["type"] == "A" and r["name"] == "example.com")
    mock.hold_mutation_id = apex["id"]
    before = mock.snapshot()
    results, failures = [], []

    def update():
        try:
            result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
            results.append(result)
        except (AssertionError, OSError, http.client.HTTPException) as exc:
            failures.append(str(exc))

    thread = threading.Thread(target=update, daemon=True)
    thread.start()
    try:
        require(mock.mutation_entered.wait(timeout=5), "first DDNS family write did not reach the upstream hold")
        password = PASSWORD + "-revoked"
        _, header = request(app.port, "POST", "/api/auth/password",
                            {"current_password": PASSWORD, "new_password": password, "confirm": password},
                            cookie=cookie)
        new_cookie = session_cookie(header, app.secure)
        request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    finally:
        mock.mutation_release.set()
        thread.join(timeout=10)
    require(not thread.is_alive() and not failures and len(results) == 1,
            "DDNS after revocation did not settle: " + ", ".join(failures))
    result = results[0]
    outcomes = {o["record_type"]: o for o in result["outcomes"] if o["domain"] == "example.com"}
    require(not result["success"] and outcomes["A"]["status"] == "updated"
            and outcomes["AAAA"]["status"] == "failed" and outcomes["AAAA"]["error"],
            "DDNS hid the unsent family failure after session revocation")
    after = mock.snapshot()
    require(after[0] == before[0] + 1 and apex["content"] == "203.0.113.42"
            and [r for r in after[1][zone] if r["type"] == "AAAA"]
            == [r for r in before[1][zone] if r["type"] == "AAAA"],
            "DDNS sent a new family mutation after originating session was revoked")
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=new_cookie)
    require(result["success"] and mock.snapshot()[0] == after[0] + 1,
            "DDNS singleflight guard or new valid session was not usable after revoked cycle")
    print("PASS session revocation stops unsent DDNS family writes with partial outcomes and guard reset")


def oversized_body_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    before = mock.snapshot()
    conn = http.client.HTTPConnection("127.0.0.1", app.port, timeout=5)
    try:
        conn.putrequest("POST", f"/api/zones/{zone}/import?filename=synthetic-zone.txt")
        conn.putheader("Cookie", cookie)
        conn.putheader("X-Requested-With", "fetch")
        conn.putheader("Content-Type", "text/plain")
        conn.putheader("Content-Length", str(2 * 1024 * 1024 + 1))
        conn.endheaders()
        response = conn.getresponse()
        response.read()
        require(response.status == 413 and response.getheader("Connection") == "close",
                "oversized declared import body must return 413 and close before receiving bytes")
    finally:
        conn.close()
    require(app.alive() and mock.snapshot() == before,
            "oversized import killed the release process or reached upstream")
    request(app.port, "GET", "/api/auth/me", cookie=cookie)
    print("PASS oversized import framing returns 413 before allocation or upstream writes")


def smoke(app, mock):
    app.start()
    app.ready()
    config, _ = request(app.port, "GET", "/api/config")
    require(config["configured"] is False, "fresh state unexpectedly configured")
    for path in ("/api/zones", "/api/auth/me", "/api/ddns/status"):
        request(app.port, "GET", path, expected=401)
    request(app.port, "GET", "/api/zones", cookie="cfddns_session=forged", expected=401)
    request(app.port, "POST", "/api/ddns/update", {}, expected=401)
    setup = {"password": PASSWORD, "confirm": PASSWORD}
    request(app.port, "POST", "/api/auth/setup", setup, mutation=False, expected=403)
    request(app.port, "POST", "/api/auth/setup",
            {"password": "short", "confirm": "short"}, expected=400)
    request(app.port, "POST", "/api/auth/setup",
            {"password": PASSWORD, "confirm": "mismatch"}, expected=400)
    config, _ = request(app.port, "GET", "/api/config")
    require(config["configured"] is False, "invalid setup changed identity state")
    _, header = request(app.port, "POST", "/api/auth/setup", setup)
    cookie = session_cookie(header, True)
    request(app.port, "POST", "/api/auth/setup", setup, expected=409)
    request(app.port, "POST", "/api/auth/login", {"password": PASSWORD},
            mutation=False, expected=403)
    request(app.port, "POST", "/api/auth/login", {"password": "wrong-synthetic"},
            expected=401)
    request(app.port, "GET", "/api/auth/me", cookie=cookie)
    zones, _ = request(app.port, "GET", "/api/zones", cookie=cookie)
    require(len(zones) == 1 and zones[0]["name"] == "example.com",
            "API must expose only the synthetic zone")
    path = f"/api/zones/{zones[0]['id']}/records"
    payload = {"type": "A", "name": "smoke.example.com", "content": "192.0.2.42",
               "proxied": True, "ttl": 3600}
    before = mock.snapshot()
    request(app.port, "POST", path, payload, cookie=cookie, mutation=False, expected=403)
    request(app.port, "POST", path, {**payload, "ttl": 2}, cookie=cookie, expected=400)
    request(app.port, "POST", path, {**payload, "type": "TXT"},
            cookie=cookie, expected=400)
    require(mock.snapshot() == before, "rejected record mutations reached Cloudflare")
    created, _ = request(app.port, "POST", path, payload, cookie=cookie, expected=201)
    require(created["proxied"] is True and created["ttl"] == 1,
            "proxied record TTL must be automatic")
    record_path = path + "/" + created["id"]
    listing, _ = request(app.port, "GET", path, cookie=cookie)
    require(any(r["id"] == created["id"] for r in listing["records"]),
            "created record missing from listing")
    updated, _ = request(app.port, "PUT", record_path,
                         {**payload, "content": "192.0.2.43", "proxied": False, "ttl": 600},
                         cookie=cookie)
    require(updated["content"] == "192.0.2.43" and updated["ttl"] == 600
            and updated["proxied"] is False, "DNS-only update lost content or TTL")
    request(app.port, "DELETE", record_path, cookie=cookie, mutation=False, expected=403)
    request(app.port, "DELETE", record_path, cookie=cookie)
    listing, _ = request(app.port, "GET", path, cookie=cookie)
    require(all(r["id"] != created["id"] for r in listing["records"]),
            "deleted record remains in listing")
    print("PASS setup validation, session protection, mutation header, cookies and DNS CRUD")

    before = mock.snapshot()
    request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie,
            mutation=False, expected=403)
    require(mock.snapshot() == before, "unprotected DDNS request wrote DNS")
    request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
    require(mock.snapshot()[0] > before[0], "DDNS update did not issue a DNS write")
    listing, _ = request(app.port, "GET", path, cookie=cookie)
    apex = [r for r in listing["records"] if r["type"] == "A" and r["name"] == "example.com"]
    require(apex and all(r["content"] == "203.0.113.42" for r in apex),
            "literal IPv4 DDNS did not update the synthetic apex")
    require([r for r in mock.snapshot()[1][zones[0]["id"]] if r["type"] == "AAAA"]
            == [r for r in before[1][zones[0]["id"]] if r["type"] == "AAAA"],
            "IPv6 none must preserve AAAA records")
    status, _ = request(app.port, "GET", "/api/ddns/status", cookie=cookie)
    require(status["ipv4"] == "203.0.113.42" and status["ipv6"] is None
            and all(d["in_sync"] for d in status["domains"]), "DDNS status is inconsistent")
    chunk_regression(app)
    print("PASS literal DDNS, disabled IPv6 preservation and max-chunk process survival")

    app.stop()
    app.secure = False
    app.start()
    app.ready()
    config, _ = request(app.port, "GET", "/api/config")
    require(config["configured"] is True, "restart lost persisted identity")
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    request(app.port, "POST", "/api/auth/setup", setup, expected=409)
    cookie = login(app)
    request(app.port, "GET", "/api/auth/me", cookie=cookie)
    request(app.port, "POST", "/api/auth/logout", {}, cookie=cookie)
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    print("PASS restart persistence, stale-session invalidation and logout")

    for kind in ("invalid", "wrong-family", "http-error", "non-2xx"):
        app.stop()
        app.start(f"url:http://127.0.0.1:{mock.port}/provider/{kind}")
        app.ready()
        cookie = login(app)
        before = mock.snapshot()
        calls = mock.calls
        status, _ = request(app.port, "GET", "/api/ddns/status", cookie=cookie)
        require(status["ipv4"] is None and status["ipv4_error"],
                f"{kind} provider must report detection failure")
        result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie)
        require(any("detection failed" in line for line in result["log"]),
                f"{kind} provider update did not report detection failure")
        require(mock.calls >= calls + 2, f"{kind} provider was not exercised")
        require(mock.snapshot() == before, f"{kind} provider changed DNS or sent a write")
    print("PASS malformed, wrong-family, HTTP-error and non-2xx providers issue zero DNS writes")
    app.stop()
    app.corrupt_state()
    print("PASS corrupt synthetic auth state fails startup with nonzero exit")
    if not app.image and os.name == "posix":
        app.stop()
        state_path = app.state_dir / "state.json"
        state_path.unlink()
        state_path.symlink_to("synthetic-missing-state.json")
        app.start()
        app.expect_startup_failure("dangling auth state symlink")
        print("PASS dangling synthetic auth state symlink fails startup without a listener")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container-image", metavar="IMAGE",
                        help="test an existing image with Linux host networking")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fixtures-only", action="store_true",
                      help="check synthetic fixture privacy without starting the app")
    mode.add_argument("--serve", action="store_true",
                       help="serve isolated mock and app for foreground browser review")
    parser.add_argument("--port", type=int, metavar="PORT",
                        help="loopback application port, valid only with --serve")
    suites = {"baseline": smoke, "auth": auth_smoke, "factor-lockout": factor_lockout_smoke,
              "auth-storage": auth_storage_smoke, "enrollment-storage": enrollment_storage_smoke,
              "metadata": metadata_smoke,
              "identifiers": identifier_smoke, "bind": bind_smoke,
              "bind-edge": bind_edge_smoke,
              "customization": customization_smoke, "config": config_smoke,
              "origin": origin_smoke, "ddns-contract": ddns_contract_smoke,
              "providers": provider_smoke, "malformed-upstream": malformed_upstream_smoke,
              "malformed-import": malformed_import_smoke,
              "concurrent-ddns": concurrent_ddns_smoke, "bulk-revocation": bulk_revocation_smoke,
              "ddns-revocation": ddns_revocation_smoke}
    suites["oversized-body"] = oversized_body_smoke
    parser.add_argument("--only", choices=suites, help="run one independent regression group")
    args = parser.parse_args()
    if args.port is not None and (not args.serve or not 1 <= args.port <= 65535):
        parser.error("--port requires --serve and a port between 1 and 65535")
    if args.only and (args.serve or args.fixtures_only):
        parser.error("--only cannot be combined with --serve or --fixtures-only")

    def terminate(signum, _frame):
        raise SystemExit(0 if args.serve else 128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    module = load_mock()
    if not args.serve:
        print("PASS synthetic fixture privacy")
    if args.fixtures_only:
        return
    if args.serve:
        with tempfile.TemporaryDirectory(prefix="cfddns-smoke-") as temp, Mock(module) as mock:
            app = App(temp, mock, args.container_image, True, args.port)
            try:
                app.secure = False
                app.start()
                app.ready()
                request(app.port, "POST", "/api/auth/setup",
                        {"password": PASSWORD, "confirm": PASSWORD})
                print(f"URL: http://127.0.0.1:{app.port}", flush=True)
                print(f"Synthetic password: {PASSWORD}", flush=True)
                threading.Event().wait()
            finally:
                app.close()
        return
    seed = copy.deepcopy(module.RECORDS)
    failures = []
    selected = {args.only: suites[args.only]} if args.only else suites
    for name, suite in selected.items():
        module.RECORDS = copy.deepcopy(seed)
        with tempfile.TemporaryDirectory(prefix="cfddns-smoke-") as temp, Mock(module) as mock:
            app = App(temp, mock, args.container_image)
            try:
                suite(app, mock)
            except (AssertionError, OSError, ValueError, KeyError, TypeError,
                    http.client.HTTPException, subprocess.SubprocessError, tarfile.TarError) as exc:
                failures.append(name)
                print(f"FAIL {name}: {exc}", file=sys.stderr, flush=True)
            finally:
                app.close()
    require(not failures, "regression groups failed: " + ", ".join(failures))
    print("PASS smoke workflow")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, http.client.HTTPException,
            subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
