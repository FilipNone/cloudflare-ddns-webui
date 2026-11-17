#!/usr/bin/env python3
"""Credential-free integration checks against an already-built binary or image."""

import argparse
import base64
import contextlib
import copy
import email.utils
import hashlib
import hmac
import http.client
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
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
import traceback
import uuid
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer
from urllib.parse import quote, parse_qs, urlparse


ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "Synthetic-smoke-password-42"
REPLACEMENT_PASSWORD = "Replacement-synthetic-password-84"
TOKEN = "synthetic-cloudflare-token-not-a-secret"
# Synthetic credentials. scrub() hides them in everything the harness prints.
SECRETS = (TOKEN, PASSWORD, REPLACEMENT_PASSWORD)
ADMIN_SETUP = {"password": PASSWORD, "confirm": PASSWORD}
DEFAULT_PROVIDER = "literal:203.0.113.42"
DOC_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"
))
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

# Timeouts and pauses, in seconds.
HTTP_TIMEOUT = 5       # one HTTP exchange with the app
HOLD_TIMEOUT = 5       # how long the mock holds a request open for a race test
QUICK_TIMEOUT = 2      # replies and exits that must not wait for anything
SHUTDOWN_LIMIT = 5     # time the app gets to exit after a stop signal
SETTLE_TIMEOUT = 10    # background requests and processes that should finish
STOP_GRACE = 10        # docker stop grace period before it kills the container
READY_TIMEOUT = 15     # app start until it answers HTTP
DOCKER_TIMEOUT = 30    # one docker CLI command
POLL_INTERVAL = 0.05
SHORT_PAUSE = 0.5      # lets the app notice closed sockets or a signal
TOTP_STEP = 30

# App limits, mirrored here to test their edges.
MAX_CONNECTIONS = 16              # MAX_CONNECTIONS in src/http.rs
MAX_BODY_BYTES = 2 * 1024 * 1024  # MAX_BODY_SIZE in src/http.rs
MAX_ICON_BYTES = 512 * 1024       # MAX_ICON_BYTES in src/customize.rs
MAX_BULK_IDS = 500                # bulk limit in src/routes.rs
MAX_2FA_ATTEMPTS = 5              # MAX_2FA_ATTEMPTS in src/auth.rs
CONTAINER_ID = 65534              # UID and GID of the image's non-root user

SERVER_LOG = "server.log"         # app and docker output, in each group's temp directory
LOG_TAIL_LINES = 40
TRACEBACK_FRAMES = 4
SECRET_FIELDS = {"secret", "backup_codes", "totp_secret", "backup_code_hashes"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def scrub(text):
    """Replace the synthetic token and passwords with <redacted>."""
    for secret in SECRETS:
        text = text.replace(secret, "<redacted>")
    return text


def find_record(records, message, **fields):
    """First record whose fields all match. Fails with `message` when there is none."""
    found = next((r for r in records if all(r.get(k) == v for k, v in fields.items())), None)
    require(found is not None, message)
    return found


def in_synthetic_zone(name):
    name = name.rstrip(".")
    return name == "example.com" or name.endswith(".example.com")


def check_synthetic_record(record, source):
    """Fail unless a mock record stays inside example.com and documentation addresses."""
    require(in_synthetic_zone(record["name"]), f"{source} owner is outside the synthetic zone")
    if record["type"] in ("A", "AAAA"):
        address = ipaddress.ip_address(record["content"])
        require(any(address in n for n in DOC_NETWORKS),
                f"{source} address is outside documentation ranges")
    elif record["type"] == "CNAME":
        require(record["content"].rstrip(".") == "example.com",
                f"{source} CNAME must target the synthetic zone")
    else:
        require(False, f"{source} has an unexpected record type; review synthetic fixture")


def check_fixture_privacy(module):
    require(
        len(module.ZONES) == 1 and module.ZONES[0]["name"] == "example.com",
        "mock fixture must contain only the synthetic example.com zone",
    )
    require(
        set(module.RECORDS) == {module.ZONES[0]["id"]},
        "mock fixture has unexpected record zones",
    )
    for records in module.RECORDS.values():
        for record in records:
            check_synthetic_record(record, "mock record")
    exported = module.parse_bind(module.EXPORT_BIND, "example.com")
    require([None if r is None else (r["name"], r["type"], r["ttl"], r["content"])
             for r in exported] == [
        None,  # SOA: parse_bind returns None for it
        ("example.com", "A", 1, "203.0.113.10"),
        ("example.com", "AAAA", 300, "2001:db8::10"),
    ], "mock export does not parse to the expected synthetic records")
    for record in exported:
        if record is not None:
            check_synthetic_record(record, "mock export")
    # parse_bind drops the SOA data, so also check every host name in the text.
    hosts = [word for word in module.EXPORT_BIND.split()
             if re.fullmatch(r"[\w-]+(?:\.[\w-]+)+\.?", word) and re.search(r"[A-Za-z]", word)]
    require(hosts and all(in_synthetic_zone(host) for host in hosts),
            "mock export names a host outside the synthetic zone")


def check_reference_parsers(module):
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


def load_mock():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "smoke_mock", ROOT / "scripts" / "mock-cloudflare-api.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    check_fixture_privacy(module)
    check_reference_parsers(module)
    return module


PROVIDER_REDIRECT = "/provider/redirect"
# IP provider endpoints served by the mock: path -> (HTTP status, body).
PROVIDER_REPLIES = {
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
# Malformed `result` values by fault kind. The kind "missing" leaves `result` out.
MALFORMED_RESULTS = {
    "null": None,
    "empty": {},
    "missing-added": {"total_records_parsed": 1},
    "missing-parsed": {"recs_added": 0},
}


def malformed_reply(kind):
    """A success envelope whose result is missing or malformed."""
    reply = {"success": True, "errors": [], "messages": []}
    if kind in MALFORMED_RESULTS:
        reply["result"] = copy.deepcopy(MALFORMED_RESULTS[kind])
    return reply


class FaultInjection:
    """Mixin for the mock's Handler. It serves the IP provider endpoints, checks
    the API token and injects the faults set on its Mock (self.server.owner)."""

    def route(self, method, body):
        owner = self.server.owner
        if self.path == PROVIDER_REDIRECT or self.path in PROVIDER_REPLIES:
            return self._provider_reply(owner)
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self._json({"success": False, "errors": []}, 401)
        url = urlparse(self.path)
        if method == "GET":
            return self._get(owner, url, body)
        return self._mutation(owner, method, url.path, body)

    def _provider_reply(self, owner):
        owner.count_provider_call(self.path)
        if self.path == PROVIDER_REDIRECT:
            self.send_response(302)
            self.send_header("Location", "/provider/redirect-target")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        status, text = PROVIDER_REPLIES[self.path]
        return self._text(text, status)

    def _get(self, owner, url, body):
        fault = owner.list_fault(url.path, url.query)
        if fault:
            return self._json(malformed_reply(fault))
        if url.path.endswith("/dns_records"):
            rows = owner.held_list(url.path.split("/")[-2])
            if rows is not None:
                return self._json(owner.module.envelope(rows))
        return super().route("GET", body)

    def _mutation(self, owner, method, api_path, body):
        with owner.lock:
            owner.writes += 1
        if method == "POST" and api_path.endswith("/dns_records/import") and owner.malformed_import:
            return self._json(malformed_reply(owner.malformed_import))
        record_id = api_path.rsplit("/", 1)[-1]
        if method != "POST":
            owner.hold_mutation(record_id)
            if record_id in owner.fail_ids:
                return self._json(owner.module.error_envelope("synthetic upstream write failure"), 503)
        elif api_path.endswith("/dns_records") and owner.fail_names:
            payload = owner.module.json_object(body) or {}
            if payload.get("name") in owner.fail_names:
                return self._json(owner.module.error_envelope("synthetic upstream create failure"), 503)
        return super().route(method, body)


class IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class Mock:
    def __init__(self, module):
        self.module = module
        # Guards the counters and hold flags below. Records use module.LOCK.
        self.lock = threading.Lock()
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

        class Handler(FaultInjection, module.Handler):
            pass

        self.server, self.thread = self._listen(ThreadingHTTPServer, "127.0.0.1", Handler)
        self.port = self.server.server_port
        self.server6 = None
        self.thread6 = None
        self.port6 = None
        if socket.has_ipv6:
            try:
                self.server6, self.thread6 = self._listen(IPv6Server, "::1", Handler)
            except OSError:
                pass
            else:
                self.port6 = self.server6.server_port

    def _listen(self, server_class, host, handler):
        server = server_class((host, 0), handler)
        server.daemon_threads = True
        server.owner = self
        return server, threading.Thread(target=server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        if self.thread6:
            self.thread6.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=SHUTDOWN_LIMIT)
        if self.server6:
            self.server6.shutdown()
            self.server6.server_close()
            self.thread6.join(timeout=SHUTDOWN_LIMIT)

    def snapshot(self):
        with self.lock:
            writes = self.writes
        return writes, self.module.snapshot_records()

    @contextlib.contextmanager
    def records(self):
        """The live mock records, locked against handler threads for the block."""
        with self.module.LOCK:
            yield self.module.RECORDS

    def count_provider_call(self, path):
        with self.lock:
            self.calls += 1
            self.provider_calls[path] = self.provider_calls.get(path, 0) + 1

    def list_fault(self, api_path, query):
        """Malformed-result kind to answer a zone or record list GET with, or None."""
        if api_path.endswith("/zones"):
            name = parse_qs(query).get("name", [None])[0]
            with self.lock:
                self.zone_queries.append(name)
            if name is not None and name == self.malformed_zone_lookup:
                return self.malformed_zone_result or "missing"
            return self.malformed_zone_list
        if api_path.endswith("/dns_records"):
            with self.lock:
                self.record_list_calls += 1
            return self.malformed_record_list
        return None

    def held_list(self, zone):
        """Hold the first record list after hold_next_list is set.

        Returns None when no hold is pending. Otherwise copies the zone's rows,
        sets list_entered, waits for list_release and returns the copied rows.
        """
        with self.lock:
            hold, self.hold_next_list = self.hold_next_list, False
        if not hold:
            return None
        rows = self.module.snapshot_records()[zone]
        self.list_entered.set()
        self.list_release.wait(timeout=HOLD_TIMEOUT)
        return rows

    def hold_mutation(self, record_id):
        """Hold one write to hold_mutation_id until mutation_release is set."""
        with self.lock:
            if record_id != self.hold_mutation_id:
                return
            self.hold_mutation_id = None
        self.mutation_entered.set()
        self.mutation_release.wait(timeout=HOLD_TIMEOUT)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def listening(port, timeout=QUICK_TIMEOUT):
    """Whether something accepts TCP connections on the loopback port."""
    with socket.socket() as sock:
        sock.settimeout(timeout)
        return sock.connect_ex(("127.0.0.1", port)) == 0


SECURITY_HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer", "Cross-Origin-Opener-Policy": "same-origin",
                    "Cross-Origin-Resource-Policy": "same-origin"}


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
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT)
    try:
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        content = response.read()
        require(TOKEN.encode() not in content, f"{path}: response exposed the server API token")
        require(response.status in (expected if isinstance(expected, tuple) else (expected,)),
                 f"{method} {path}: expected HTTP {expected}, got {response.status}")
        for key, value in SECURITY_HEADERS.items():
            require(response.getheader(key) == value, f"{path}: missing {key} protection")
        permissions = response.getheader("Permissions-Policy", "")
        require(all(f + "=()" in permissions for f in ("camera", "microphone", "geolocation")),
                f"{path}: missing Permissions-Policy")
        require(response.getheader("Strict-Transport-Security") in (None, "max-age=31536000"),
                f"{path}: unexpected HSTS value")
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


def cookie_name(secure):
    return "__Host-cfddns_session" if secure else "cfddns_session"


def parse_cookie(header, secure):
    require(header is not None, "response did not set a cookie")
    parsed = SimpleCookie()
    parsed.load(header)
    name = cookie_name(secure)
    require(set(parsed) == {name}, "unexpected session cookie name")
    cookie = parsed[name]
    require(cookie["httponly"] and cookie["samesite"] == "Strict" and cookie["path"] == "/"
            and not cookie["domain"], "session cookie lacks required security attributes")
    require(bool(cookie["secure"]) == secure, "Secure cookie configuration ignored")
    return cookie


def session_cookie(header, secure):
    cookie = parse_cookie(header, secure)
    require(int(cookie["max-age"]) > 0, "session cookie expires immediately")
    return cookie_name(secure) + "=" + cookie.value


def cleared_cookie(header, secure):
    cookie = parse_cookie(header, secure)
    require(cookie.value == "" and cookie["max-age"] == "0", "logout did not clear the cookie")


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
        self.packaging_checked = False
        self.public_origin = None
        self.docker = shutil.which("docker") if image else None
        self.binary = ROOT / "target" / "release" / "cloudflare-ddns-webui"
        self.host_env = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C",
                         "HOME": str(self.temp)}
        self.state_dir = self.temp / "state"
        self.state_dir.mkdir()
        self.log_path = self.temp / SERVER_LOG
        self.secure = True

    def log(self):
        """Open the server log for appending."""
        return open(self.log_path, "ab")

    def docker_run(self, *args, check=True, input_data=None, timeout=DOCKER_TIMEOUT):
        with self.log() as log:
            result = subprocess.run(
                [self.docker, *args], env=self.host_env, cwd=self.temp,
                input=input_data, stdout=subprocess.PIPE, stderr=log,
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

    def start(self, provider=DEFAULT_PROVIDER, overrides=None, output=None):
        """Start the app. For the native binary, `output` receives stdout and stderr
        (default: the server log)."""
        env = self.environment(provider)
        env.update(overrides or {})
        self.public_origin = env.get("PUBLIC_ORIGIN")
        if self.image:
            self._start_container(env)
            return
        require(self.binary.is_file(), "build the release binary before running smoke")
        with self.log() as log:
            self.process = subprocess.Popen(
                [str(self.binary)], cwd=self.temp, env={**self.host_env, **env},
                stdout=log if output is None else output, stderr=subprocess.STDOUT,
            )

    def _start_container(self, env):
        require(self.docker is not None, "docker executable is required")
        require(sys.platform.startswith("linux"),
                "container smoke requires Linux host networking")
        if not self.volume:
            user = self.docker_run("image", "inspect", "--format",
                                   "{{.Config.User}}", self.image).stdout.strip()
            expected_user = f"{CONTAINER_ID}:{CONTAINER_ID}"
            require(user == expected_user.encode(), "image User must be " + expected_user)
            self.volume = "cfddns-smoke-" + uuid.uuid4().hex
            self.docker_run("volume", "create", self.volume)
        name = "cfddns-smoke-" + uuid.uuid4().hex
        args = ["create", "--name", name, "--network", "host", "--mount",
                f"type=volume,source={self.volume},target=/data"]
        for key, value in env.items():
            args.extend(["--env", f"{key}={value}"])
        self.container = name
        self.docker_run(*args, self.image)
        if not self.packaging_checked:
            self._check_packaging(name)
        self.docker_run("start", name)

    def _check_packaging(self, name):
        archive = self.docker_run("cp", f"{name}:/data/.", "-").stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            members = tar.getmembers()
            require(members and all(m.isdir() for m in members),
                    "runtime /data must contain no compiler output or files")
            require(all(m.uid == CONTAINER_ID and m.gid == CONTAINER_ID for m in members),
                    "runtime /data must belong to the non-root user")
            require(all(m.mode & 0o300 == 0o300 for m in members),
                    "runtime /data must be writable by its owner")
        self.packaging_checked = True
        if not self.serve:
            print("PASS container user and empty writable /data packaging")

    def alive(self):
        if self.image:
            return self.docker_run("inspect", "--format", "{{.State.Running}}",
                                   self.container).stdout.strip() == b"true"
        return self.process.poll() is None

    def ready(self):
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline:
            require(self.alive(), "application exited before readiness")
            try:
                headers = {"Host": urlparse(self.public_origin).netloc} if self.public_origin else None
                wire_request(self.port, "GET", "/api/config", extra_headers=headers)
                return
            except (OSError, http.client.HTTPException):
                time.sleep(POLL_INTERVAL)
        raise AssertionError("application readiness timed out")

    def restart(self, provider=DEFAULT_PROVIDER, overrides=None):
        """Stop any running instance, start a new one and wait until it answers."""
        self.stop()
        self.start(provider, overrides)
        self.ready()

    def stop(self):
        if self.container:
            self._save_container_log()
            self.docker_run("rm", "--force", self.container, check=False)
            self.container = None
        if self.process:
            if self.process.poll() is None:
                self.process.send_signal(signal.SIGINT)
                try:
                    self.process.wait(timeout=SHUTDOWN_LIMIT)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=SHUTDOWN_LIMIT)
            self.process = None

    def _save_container_log(self):
        """Append the container's output to the server log before the container is removed."""
        try:
            with self.log() as log:
                subprocess.run([self.docker, "logs", self.container], env=self.host_env,
                               cwd=self.temp, stdout=log, stderr=subprocess.STDOUT,
                               timeout=DOCKER_TIMEOUT)
        except (OSError, subprocess.SubprocessError):
            pass  # The log only helps diagnose failures; removal must still happen.

    def close(self):
        try:
            self.stop()
        finally:
            if self.volume:
                self.docker_run("volume", "rm", "--force", self.volume, check=False)
                self.volume = None

    def wait_exit(self, timeout):
        """Exit code of the app. Raises subprocess.TimeoutExpired while it keeps running."""
        if self.image:
            return int(self.docker_run("wait", self.container, timeout=timeout).stdout.strip())
        return self.process.wait(timeout=timeout)

    def expect_startup_failure(self, reason):
        try:
            code = self.wait_exit(SETTLE_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(reason + " must fail startup") from exc
        require(code != 0, reason + " must produce a nonzero exit")
        require(not listening(self.port), reason + " must not leave an HTTP listener")

    def corrupt_state(self):
        content = b"{synthetic-corrupt-state"
        if self.image:
            self.start()
            self.docker_run("stop", "--time", str(QUICK_TIMEOUT), self.container)
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as tar:
                member = tarfile.TarInfo("state.json")
                member.size = len(content)
                member.uid = member.gid = CONTAINER_ID
                member.mode = 0o600
                tar.addfile(member, io.BytesIO(content))
            self.docker_run("cp", "--archive", "-", f"{self.container}:/data",
                            input_data=archive.getvalue())
            self.docker_run("start", self.container)
        else:
            (self.state_dir / "state.json").write_bytes(content)
            self.start()
        self.expect_startup_failure("corrupt auth state")


class Background:
    """Run one call on a daemon thread and keep its result or error message."""

    def __init__(self, call):
        self.result = None
        self.error = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._run, args=(call,), daemon=True)

    def _run(self, call):
        try:
            self.result = call()
        except Exception as exc:  # The group reports it through self.error.
            self.error = str(exc) if isinstance(exc, AssertionError) else f"{type(exc).__name__}: {exc}"
        finally:
            self.done.set()

    def start(self):
        self.thread.start()
        return self

    def join(self):
        if self.thread.ident is not None:
            self.thread.join(timeout=SETTLE_TIMEOUT)

    def ok(self):
        """Whether the call returned without raising."""
        return self.done.is_set() and self.error is None


def background_errors(*tasks):
    return ", ".join(task.error for task in tasks if task.error)


def login(app):
    _, header = request(app.port, "POST", "/api/auth/login", {"password": PASSWORD})
    return session_cookie(header, app.secure)


def create_admin(app):
    """Complete first-run setup and return the session cookie it issues."""
    _, header = request(app.port, "POST", "/api/auth/setup", ADMIN_SETUP)
    return session_cookie(header, app.secure)


def chunk_regression(app):
    with socket.create_connection(("127.0.0.1", app.port), timeout=HTTP_TIMEOUT) as sock:
        sock.settimeout(HTTP_TIMEOUT)
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
    return create_admin(app)


def totp(secret, timestamp=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int(time.time() if timestamp is None else timestamp) // TOTP_STEP
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
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


def submit_factor(app, pending, code, expected=200):
    """Answer a login challenge with a TOTP or recovery code."""
    return request(app.port, "POST", "/api/auth/login/2fa",
                   {"challenge": pending, "code": code}, expected=expected)


def factor_login(app, code, password=PASSWORD):
    result, header = submit_factor(app, challenge(app, password), code)
    return result, session_cookie(header, app.secure)


def ddns_update(app, cookie, mutation=True, expected=200):
    result, _ = request(app.port, "POST", "/api/ddns/update", {}, cookie=cookie,
                        mutation=mutation, expected=expected)
    return result


def revoke_by_password_change(app, cookie):
    """Change the password, check the old session is revoked and return the new one."""
    password = PASSWORD + "-revoked"
    _, header = request(app.port, "POST", "/api/auth/password",
                        {"current_password": PASSWORD, "new_password": password, "confirm": password},
                        cookie=cookie)
    new_cookie = session_cookie(header, app.secure)
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    return new_cookie


def auth_smoke(app, mock):
    secret, codes = auth_enrollment(app)
    cookie = auth_second_factor_logins(app, secret, codes)
    auth_password_change_with_totp(app, secret, codes, cookie)
    password = auth_password_change_with_recovery_code(app, secret, codes)
    auth_disable_factor(app, secret, codes, password)
    app.restart()
    result, header = request(app.port, "POST", "/api/auth/login", {"password": password})
    require(result["requires_2fa"] is False, "disabled factor persisted after restart")
    session_cookie(header, app.secure)
    require(mock.writes == 0, "authentication flows unexpectedly wrote Cloudflare")
    print("PASS TOTP enrollment retry/cancel, sessions, password/factor persistence and single-use recovery")


def auth_enrollment(app):
    """Enrollment needs the password and survives retry and cancel. Returns (secret, codes)."""
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
    return secret, codes


def auth_second_factor_logins(app, secret, codes):
    """Challenges and TOTP codes work once; a normalized recovery code logs in once.

    Returns the session from the recovery-code login.
    """
    pending = challenge(app)
    submit_factor(app, pending, "invalid", expected=401)
    # Each TOTP code works once and enrollment used the current one, so log in
    # with the next step's code, which the one-step drift allowance accepts.
    login_code = totp(secret, time.time() + TOTP_STEP)
    _, header = submit_factor(app, pending, login_code)
    session_cookie(header, app.secure)
    submit_factor(app, pending, login_code, expected=401)
    submit_factor(app, challenge(app), login_code, expected=401)
    result, cookie = factor_login(app, codes[0].lower().replace("-", " "))
    require(result["backup_code_used"] and result["backup_codes_remaining"] == 7,
            "normalized recovery login did not consume exactly one code")
    return cookie


def auth_password_change_with_totp(app, secret, codes, cookie):
    """After a restart, change PASSWORD to REPLACEMENT_PASSWORD with a TOTP code."""
    app.restart()
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    submit_factor(app, challenge(app), codes[0], expected=401)
    # The server keeps the last used TOTP step in memory only, so after a
    # restart the current code is accepted again.
    _, cookie = factor_login(app, totp(secret))
    password = REPLACEMENT_PASSWORD
    change = {"current_password": PASSWORD, "new_password": password, "confirm": password}
    request(app.port, "POST", "/api/auth/password", change, cookie=cookie, expected=401)
    request(app.port, "POST", "/api/auth/password",
            {**change, "current_password": "wrong-synthetic", "code": totp(secret)},
            cookie=cookie, expected=401)
    pending = challenge(app)
    _, header = request(app.port, "POST", "/api/auth/password",
                        {**change, "code": totp(secret, time.time() + TOTP_STEP)}, cookie=cookie)
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    session_cookie(header, app.secure)
    submit_factor(app, pending, totp(secret), expected=401)


def auth_password_change_with_recovery_code(app, secret, codes):
    """After a restart, change REPLACEMENT_PASSWORD again with a recovery code.

    Returns the new password.
    """
    app.restart()
    request(app.port, "POST", "/api/auth/login", {"password": PASSWORD}, expected=401)
    _, cookie = factor_login(app, totp(secret), REPLACEMENT_PASSWORD)
    pending = challenge(app, REPLACEMENT_PASSWORD)
    password = REPLACEMENT_PASSWORD + "-recovery"
    _, header = request(app.port, "POST", "/api/auth/password",
                        {"current_password": REPLACEMENT_PASSWORD, "code": codes[2],
                         "new_password": password, "confirm": password}, cookie=cookie)
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    cookie = session_cookie(header, app.secure)
    submit_factor(app, pending, totp(secret), expected=401)
    me, _ = request(app.port, "GET", "/api/auth/me", cookie=cookie)
    require(me["backup_codes_remaining"] == 6, "password mutation did not consume exactly one recovery code")
    return password


def auth_disable_factor(app, secret, codes, password):
    """After a restart, used recovery codes stay used and disabling 2FA needs a valid code."""
    app.restart()
    submit_factor(app, challenge(app, password), codes[2], expected=401)
    _, cookie = factor_login(app, totp(secret), password)
    request(app.port, "POST", "/api/auth/2fa/disable", {"code": "invalid"},
            cookie=cookie, expected=401)
    pending = challenge(app, password)
    _, header = request(app.port, "POST", "/api/auth/2fa/disable", {"code": codes[1]}, cookie=cookie)
    cookie = session_cookie(header, app.secure)
    submit_factor(app, pending, codes[2], expected=401)
    request(app.port, "POST", "/api/auth/2fa/disable", {"code": codes[2]},
            cookie=cookie, expected=400)
    me, _ = request(app.port, "GET", "/api/auth/me", cookie=cookie)
    require(not me["totp_enabled"] and me["backup_codes_remaining"] == 0,
            "disabled account retained factors")


def factor_lockout_smoke(app, mock):
    old_cookie = setup_session(app)
    secret, codes, cookie = enroll(app, old_cookie)
    pending = [challenge(app) for _ in range(MAX_2FA_ATTEMPTS + 1)]
    for token in pending[:MAX_2FA_ATTEMPTS]:
        submit_factor(app, token, "invalid", expected=401)
    submit_factor(app, pending[-1], codes[0], expected=429)
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
            require(not SECRET_FIELDS.intersection(result)
                    and all(value not in json.dumps(result) for value in (PASSWORD, secret, *codes)),
                    route + ": failed persistence disclosed authentication material")
        me, _ = request(app.port, "GET", "/api/auth/me", cookie=cookie)
        require(me["totp_enabled"] and me["backup_codes_remaining"] == 8,
                "failed saves changed in-memory identity or consumed recovery codes")
    finally:
        path.rmdir()
        saved.rename(path)
    app.restart()
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
        result, header = request(app.port, "POST", "/api/auth/setup", ADMIN_SETUP, expected=(400, 500))
        require(header is None and PASSWORD not in json.dumps(result),
                "failed setup save issued a cookie or disclosed the synthetic password")
        config, _ = request(app.port, "GET", "/api/config")
        require(not config["configured"], "failed setup persisted an in-memory administrator")
    finally:
        path.rmdir()
    cookie = create_admin(app)
    enrollment, _ = request(app.port, "POST", "/api/auth/2fa/begin",
                            {"password": PASSWORD}, cookie=cookie)
    saved = app.state_dir / "synthetic-saved-state.json"
    path.rename(saved)
    path.mkdir()
    try:
        result, header = request(app.port, "POST", "/api/auth/2fa/confirm",
                                 {"code": totp(enrollment["secret"])}, cookie=cookie, expected=500)
        require(header is None, "failed enrollment save issued an authentication cookie")
        require(not SECRET_FIELDS.intersection(result)
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
    app.restart()
    _, cookie = factor_login(app, totp(enrollment["secret"]))
    require(mock.writes == 0, "setup/enrollment unexpectedly wrote Cloudflare")
    print("PASS failed setup/enrollment saves rollback, retry, restrictive permissions and restart")


def metadata_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    path = f"/api/zones/{zone}/records"

    def stored(record_id):
        return find_record(mock.snapshot()[1][zone], f"record {record_id} is missing from the mock",
                           id=record_id)

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
        row = stored(rid)
        require((row["comment"] or "") == comment and row["tags"] == tags,
                "bulk update lost keep/set/clear metadata semantics")
    result, _ = request(app.port, "POST", path + "/bulk",
                         {"action": "update", "ids": [rid], "patch": {"proxied": True, "ttl": 3600}},
                         cookie=cookie)
    row = stored(rid)
    require(result["succeeded"] == 1 and row["proxied"] and row["ttl"] == 1,
            "bulk enabling proxy failed to force automatic TTL")
    request(app.port, "POST", path + "/bulk",
            {"action": "update", "ids": [rid], "patch": {"ttl": 600}}, cookie=cookie)
    require(stored(rid)["ttl"] == 1, "TTL-only bulk patch changed a proxied record away from auto")
    request(app.port, "POST", path + "/bulk",
            {"action": "update", "ids": [rid], "patch": {"proxied": False, "ttl": 600}}, cookie=cookie)
    row = stored(rid)
    require(row["ttl"] == 600 and not row["proxied"], "DNS-only bulk patch lost explicit TTL")
    other, _ = request(app.port, "POST", path, {**basic, "name": "partial.example.com"},
                        cookie=cookie, expected=201)
    mock.fail_ids.add(other["id"])
    for action, patch in (("update", {"comment": "partial-success"}), ("delete", None)):
        failed_before = stored(other["id"])
        result, _ = request(app.port, "POST", path + "/bulk",
                             {"action": action, "ids": [rid, other["id"]], "patch": patch}, cookie=cookie)
        require(result["succeeded"] == 1 and result["failed"] == 1
                and len(result["results"]) == 2, "partial bulk failure totals are inaccurate")
        results = {r["id"]: r for r in result["results"]}
        require(results[rid]["ok"] and not results[other["id"]]["ok"]
                and results[other["id"]]["error"], "bulk hid per-record upstream failure")
        records = mock.snapshot()[1][zone]
        require(find_record(records, "partial upstream failure removed the failed record",
                            id=other["id"]) == failed_before,
                "partial upstream failure changed the failed record")
        if action == "update":
            require(find_record(records, "partial update lost the successful record",
                                id=rid)["comment"] == "partial-success",
                    "partial result claimed success without applying the successful patch")
        else:
            require(all(r["id"] != rid for r in records),
                    "partial delete claimed success without deleting the successful record")
    print("PASS PUT/bulk metadata keep/set/clear, proxy TTL and per-record partial failures")


def identifier_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    before = mock.snapshot()
    rid = before[1][zone][0]["id"]
    path = f"/api/zones/{zone}/records"
    for invalid in ("../" + rid, "../../../zones/" + zone, rid + "?x=1", rid + "#suffix",
                    "", "bad\\identifier", rid + "/extra", "bad.identifier"):
        for action in ("delete", "update"):
            request(app.port, "POST", path + "/bulk",
                    {"action": action, "ids": [rid, invalid], "patch": {"ttl": 600}},
                    cookie=cookie, expected=400)
            require(mock.snapshot() == before, "bulk invalid identifier caused a write before validation")
    for ids in ([], [rid, rid], [rid] * (MAX_BULK_IDS + 1)):
        request(app.port, "POST", path + "/bulk", {"action": "delete", "ids": ids},
                cookie=cookie, expected=400)
        require(mock.snapshot() == before, "bulk invalid list caused upstream writes")
    for patch in ({}, {"content": "192.0.2.1"}):
        request(app.port, "POST", path + "/bulk", {"action": "update", "ids": [rid], "patch": patch},
                cookie=cookie, expected=400)
    request(app.port, "POST", path, {"type": "A", "name": "x.example.com", "content": "192.0.2.1",
                                     "zone_id": zone}, cookie=cookie, expected=400)
    request(app.port, "POST", path, {"type": "A", "name": "x.example.com", "content": "192.0.2.1",
                                     "data": {"priority": 1, "weight": 1, "port": 1, "target": "x"}},
            cookie=cookie, expected=400)
    for method in ("DELETE", "PUT", "GET"):
        request(app.port, method, path + "/bulk", cookie=cookie, expected=404)
    require(mock.snapshot() == before, "bulk route, empty patch or unknown fields reached upstream")
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
    print("PASS unsafe identifiers, duplicates, empty patches, unknown fields, record-type data, "
          "non-POST bulk and multipart filenames rejected with zero upstream writes")


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
    require(find_record(imported, "import lost import-b", name="import-b.example.com")["ttl"] == 600
            and find_record(imported, "import lost the TXT record", type="TXT")["content"]
            == "synthetic; quoted text",
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


def data_files(app):
    """Mode and owner UID of each regular file in the data directory, by name."""
    if app.image:
        archive = app.docker_run("cp", f"{app.container}:/data/.", "-").stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            return {Path(m.name).name: (m.mode & 0o777, m.uid)
                    for m in tar.getmembers() if m.isfile()}
    return {p.name: (p.stat().st_mode & 0o777, p.stat().st_uid)
            for p in app.state_dir.iterdir() if p.is_file()}


def icon_files(files):
    return [name for name in files if re.fullmatch(r"icon-[0-9a-f]{32}", name)]


def script_paths(page):
    """Script URLs in the served index page, in load order, without the version query."""
    paths = [p.decode() for p in re.findall(rb'<script src="(/static/[^"?]+)[^"]*"', page)]
    require(paths and paths[-1] == "/static/app.js", "index page must load app.js last")
    return paths


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
                       ("image/png", b""), ("image/png", b"x" * (MAX_ICON_BYTES + 1)),
                       ("text/html", b"<html>synthetic</html>")):
        wire_request(app.port, "POST", "/api/ui/icon?mime=" + quote(mime, safe=""), body,
                     cookie, expected=400, content_type=mime)
        content, headers = wire_request(app.port, "GET", "/static/favicon.svg")
        require(content == png and headers["Content-Type"] == "image/png",
                "rejected upload changed the saved safe raster")
        csp = headers.get("Content-Security-Policy", "")
        require("sandbox" in csp and "default-src 'none'" in csp,
                "uploaded raster lacks the required sandbox and deny-all favicon CSP")
    files = data_files(app)
    require(len(icon_files(files)) == 1 and "ui-settings.json" in files,
            "uploaded icon is not stored in its own file")
    require(all(mode == 0o600 for mode, _ in files.values()), "saved files must be owner-only")
    if app.image:
        require(all(uid == CONTAINER_ID for _, uid in files.values()),
                "the non-root container user must own the files it saves in /data")
    app.restart()
    cookie = login(app)
    config, _ = request(app.port, "GET", "/api/config")
    require(config["has_icon"] and config["accent"] == "#123ABC", "customization lost after restart")
    content, headers = wire_request(app.port, "GET", "/static/favicon.svg")
    require(content == png and headers["Content-Type"] == "image/png", "persisted raster differs")
    csp = headers.get("Content-Security-Policy", "")
    require("sandbox" in csp and "default-src 'none'" in csp,
            "persisted raster lacks the required sandbox and deny-all favicon CSP")
    page, _ = wire_request(app.port, "GET", "/")
    wire_request(app.port, "GET", "/static/style.css")
    for path in script_paths(page):
        _, headers = wire_request(app.port, "GET", path)
        require(headers["Content-Type"] == "application/javascript; charset=utf-8",
                f"{path}: not served as JavaScript")
    request(app.port, "DELETE", "/api/ui/icon", cookie=cookie)
    config, _ = request(app.port, "GET", "/api/config")
    require(not config["has_icon"], "icon reset was not reported")
    require(not icon_files(data_files(app)), "icon reset left the icon file behind")
    require(mock.writes == 0, "customization unexpectedly wrote Cloudflare")
    print("PASS raster upload persistence, SVG/spoof rejection, accent validation and security headers")
    if app.image:
        print("SKIP invalid and unreadable UI settings need host access to the data directory")
        return
    bad_ui_settings(app)


def bad_ui_settings(app):
    app.stop()
    settings = app.state_dir / "ui-settings.json"
    settings.write_text("{synthetic-invalid")
    app.start()
    app.ready()
    config, _ = request(app.port, "GET", "/api/config")
    require(config["accent"] is None and not config["has_icon"], "invalid UI settings were used")
    require((app.state_dir / "ui-settings.json.invalid").read_text() == "{synthetic-invalid"
            and not settings.exists(), "invalid UI settings were not renamed aside")
    app.stop()
    settings.mkdir()
    app.start()
    app.expect_startup_failure("unreadable UI settings")
    settings.rmdir()
    print("PASS invalid UI settings are renamed aside; unreadable settings stop startup")


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
            try:
                code = app.wait_exit(QUICK_TIMEOUT)
            except subprocess.TimeoutExpired:
                failures.append(name + "=" + value)
                continue
            require(code != 0, "invalid synthetic configuration exited successfully")
            require(not listening(app.port), "invalid configuration left HTTP listener")
        finally:
            app.stop()
    require(not failures, "invalid environment settings silently accepted: " + ", ".join(failures))
    require(mock.writes == 0, "invalid configuration issued upstream writes")
    print("PASS strict TTL/boolean/duration/provider/contract environment rejection")


def origin_smoke(app, mock):
    app.start()
    app.ready()
    before = mock.snapshot()
    setup = json.dumps(ADMIN_SETUP).encode()
    for headers in ({"Host": "attacker.example"},
                    {"Origin": "https://attacker.example"},
                    {"Host": "attacker.example", "Origin": "https://attacker.example"}):
        wire_request(app.port, "GET", "/api/config", extra_headers=headers, expected=403)
        wire_request(app.port, "POST", "/api/auth/setup", setup, expected=403,
                     content_type="application/json", extra_headers=headers)
    config, _ = request(app.port, "GET", "/api/config")
    require(not config["configured"] and mock.snapshot() == before,
            "untrusted host/origin configured identity or upstream")
    cookie = create_admin(app)
    wire_request(app.port, "POST", "/api/ddns/update", b"{}", cookie, expected=403,
                 content_type="application/json", extra_headers={"Origin": "https://attacker.example"})
    require(mock.snapshot() == before, "cross-origin session mutation reached upstream")
    wire_request(app.port, "GET", "/api/config", expected=403, extra_headers={"Origin": "null"})
    _, headers = wire_request(app.port, "GET", "/")
    require("Strict-Transport-Security" not in headers, "HSTS sent without an HTTPS origin")
    app.restart(overrides={"PUBLIC_ORIGIN": "https://admin.example.com"})
    _, headers = wire_request(app.port, "GET", "/api/config", extra_headers={
        "Host": "admin.example.com", "Origin": "https://admin.example.com"})
    require(headers.get("Strict-Transport-Security") == "max-age=31536000",
            "HTTPS public origin must send HSTS")
    wire_request(app.port, "GET", "/api/config", expected=403,
                 extra_headers={"Host": "attacker.example"})
    print("PASS untrusted Host/Origin rejection, exact configured reverse-proxy origin and HSTS")


def ddns_contract_smoke(app, mock):
    zone = mock.module.ZONES[0]["id"]
    apex = standalone_ddns_checks(app, mock, zone)
    shared_ddns_checks(app, mock, zone, apex)
    print("PASS structured DDNS families, unchanged writes, partial failures, ownership and duplicate refusal")


def standalone_ddns_checks(app, mock, zone):
    """Family domains, unchanged cycles and partial failures. Returns the live apex A record."""
    cookie = setup_session(app, {"DOMAINS": "", "IP4_DOMAINS": "example.com",
                                "IP6_DOMAINS": "www.example.com",
                                "IP6_PROVIDER": "literal:2001:db8::42"})
    status, _ = request(app.port, "GET", "/api/ddns/status", cookie=cookie)
    require(status["contract_version"] == "standalone-v1" and status["daemon_status"] == "not_observed"
            and status["manual_updates_enabled"], "DDNS status claims unsupported daemon observation")
    before = mock.snapshot()
    result = ddns_update(app, cookie)
    require(result["success"] and result["outcomes"], "family-specific DDNS failed")
    records = mock.snapshot()[1][zone]
    require(find_record(records, "IP4_DOMAINS apex A record is missing",
                        name="example.com", type="A")["content"]
            == "203.0.113.42", "IP4_DOMAINS not applied")
    require(find_record(records, "IP6_DOMAINS www AAAA record is missing",
                        name="www.example.com", type="AAAA")["content"]
            == "2001:db8::42", "IP6_DOMAINS not applied")
    require([r for r in records if r["name"] == "example.com" and r["type"] == "AAAA"]
            == [r for r in before[1][zone] if r["name"] == "example.com" and r["type"] == "AAAA"],
            "family-specific configuration touched excluded AAAA")
    before = mock.snapshot()
    result = ddns_update(app, cookie)
    require(result["success"] and all(o["status"] in ("unchanged", "skipped") for o in result["outcomes"])
            and mock.snapshot() == before, "unchanged DDNS performed unnecessary writes")
    app.restart(overrides={"DOMAINS": "example.com,www.example.com"})
    cookie = login(app)
    with mock.records() as records:
        apex = find_record(records[zone], "synthetic apex A record is missing", type="A", name="example.com")
        apex["content"] = "192.0.2.19"
    mock.fail_ids.add(apex["id"])
    result = ddns_update(app, cookie)
    require(not result["success"] and any(o["status"] == "failed" and o["error"] for o in result["outcomes"])
            and any(o["status"] in ("created", "updated", "unchanged") for o in result["outcomes"]),
            "partial DDNS upstream failure reported as full success")
    require(apex["content"] == "192.0.2.19", "failed DDNS overwrote existing content")
    mock.fail_ids.clear()
    app.stop()
    return apex


def shared_ddns_checks(app, mock, zone, apex):
    """shared-v1 needs the paused-updater flag, writes only owned records and refuses duplicates."""
    shared = {"GUI_DDNS_CONTRACT": "shared-v1", "RECORD_COMMENT": "owned-synthetic",
              "MANAGED_RECORDS_COMMENT_REGEX": "^owned-synthetic$"}
    for overrides in (shared, {**shared, "GUI_SHARED_UPDATER_PAUSED": "false"}):
        before = mock.snapshot()
        app.start(overrides=overrides)
        app.expect_startup_failure("shared contract without explicit paused-updater confirmation")
        require(mock.snapshot() == before, "unconfirmed shared contract issued upstream writes")
        app.stop()
    app.restart(overrides={**shared, "GUI_SHARED_UPDATER_PAUSED": "true"})
    cookie = login(app)
    before = mock.snapshot()
    result = ddns_update(app, cookie)
    require(not result["success"] and mock.snapshot() == before,
            "shared contract mutated an unowned existing DNS record")
    with mock.records() as records:
        apex["comment"] = "owned-synthetic"
        duplicate = copy.deepcopy(apex)
        duplicate["id"] = "abcdef0123456789abcdef0123456789"
        records[zone].append(duplicate)
    before = mock.snapshot()
    result = ddns_update(app, cookie)
    require(not result["success"] and mock.snapshot() == before,
            "shared contract reconciled duplicates without explicit supported policy")
    with mock.records() as records:
        records[zone].remove(duplicate)
    result = ddns_update(app, cookie)
    require(result["success"] and apex["content"] == "203.0.113.42",
            "shared exact-comment owner was not updated")


def provider_smoke(app, mock):
    cookie = setup_session(app)
    for kind in ("private", "loopback", "cloudflare", "oversized", "redirect"):
        app.restart("url:http://127.0.0.1:" + str(mock.port) + "/provider/" + kind)
        cookie = login(app)
        before = mock.snapshot()
        result = ddns_update(app, cookie)
        require(not result["success"] and any(o["status"] == "failed" for o in result["outcomes"]),
                f"{kind} fetched provider value was not rejected")
        require(mock.snapshot() == before, f"{kind} provider failure changed DNS")
    require(mock.provider_calls.get(PROVIDER_REDIRECT, 0) > 0
            and not mock.provider_calls.get("/provider/redirect-target", 0),
            "provider redirect was followed")
    if mock.port6 is None:
        print("SKIP IPv6 provider transport: host has no usable ::1 listener")
        return
    app.restart(overrides={"IP4_PROVIDER": "none",
                           "IP6_PROVIDER": f"url:http://[::1]:{mock.port6}/provider/wrong-family-v6"})
    cookie = login(app)
    before = mock.snapshot()
    status, _ = request(app.port, "GET", "/api/ddns/status", cookie=cookie)
    require(status["ipv6"] is None and status["ipv6_error"], "IPv6 family mismatch not reported")
    result = ddns_update(app, cookie)
    require(not result["success"] and mock.snapshot() == before, "IPv6 family mismatch issued writes")
    app.restart(overrides={"IP4_PROVIDER": "none",
                           "IP6_PROVIDER": f"url:http://[::1]:{mock.port6}/provider/valid-v6"})
    cookie = login(app)
    before = mock.snapshot()
    result = ddns_update(app, cookie)
    require(result["success"], "valid loopback synthetic IPv6 detection failed")
    zone = mock.module.ZONES[0]["id"]
    records = mock.snapshot()[1][zone]
    require(find_record(records, "apex AAAA record is missing",
                        name="example.com", type="AAAA")["content"]
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
        result = ddns_update(app, cookie)
        require(not result["success"] and any(o["status"] == "failed" for o in result["outcomes"]),
                "malformed upstream zone list was treated as a valid empty zone")
        require(mock.snapshot() == before, "malformed upstream zone list caused DNS creation")
        mock.malformed_zone_list = None
        mock.malformed_record_list = kind
        request(app.port, "GET", f"/api/zones/{zone}/records", cookie=cookie, expected=502)
        mock.zone_queries.clear()
        calls = mock.record_list_calls
        result = ddns_update(app, cookie)
        require(not result["success"] and any(o["status"] == "failed" for o in result["outcomes"]),
                "malformed upstream record list was treated as valid empty DNS")
        require(mock.zone_queries == ["example.com"] and mock.record_list_calls == calls + 1,
                "record-list failure fixture was not exercised after valid zone discovery")
        require(mock.snapshot() == before, "malformed upstream record list caused DNS creation")
        mock.malformed_record_list = None
    app.restart(overrides={"DOMAINS": "sub.example.com"})
    cookie = login(app)
    for kind in ("missing", "null"):
        mock.malformed_zone_lookup = "sub.example.com"
        mock.malformed_zone_result = kind
        mock.zone_queries.clear()
        before = mock.snapshot()
        result = ddns_update(app, cookie)
        require(not result["success"] and any(o["status"] == "failed" for o in result["outcomes"]),
                "malformed exact zone lookup was treated as a legitimate empty zone")
        require(mock.zone_queries == ["sub.example.com"] and mock.snapshot() == before,
                "malformed exact zone lookup fell back to the parent or wrote DNS")
    mock.malformed_zone_lookup = None
    mock.zone_queries.clear()
    before = mock.snapshot()
    result = ddns_update(app, cookie)
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
    with mock.records() as records:
        records[zone] = [r for r in records[zone] if r["type"] != "A"]
    before = mock.snapshot()
    mock.hold_next_list = True
    first = Background(lambda: ddns_update(app, cookie))
    second = Background(lambda: ddns_update(app, cookie, expected=409))
    first.start()
    try:
        require(mock.list_entered.wait(timeout=HOLD_TIMEOUT),
                "first DDNS request never reached the held DNS snapshot")
        second.start()
        require(second.done.wait(timeout=QUICK_TIMEOUT),
                "second DDNS request did not return while the first GET was held")
        require(first.error is None and second.ok(),
                "second DDNS request must return 409 before releasing the first GET: "
                + background_errors(first, second))
        require(first.thread.is_alive() and mock.snapshot() == before,
                "held first DDNS cycle unexpectedly settled or wrote before release")
    finally:
        mock.list_release.set()
        first.join()
        second.join()
    require(first.ok() and second.ok(),
            "concurrent DDNS failed or did not settle: " + background_errors(first, second))
    require(isinstance(first.result, dict) and first.result.get("success") is True,
            "concurrent DDNS returned no successful update")
    after = mock.snapshot()
    apex = [r for r in after[1][zone] if r["type"] == "A" and r["name"] == "example.com"]
    require(after[0] == before[0] + 1 and len(apex) == 1 and apex[0]["content"] == "203.0.113.42",
            "two concurrent GUI DDNS cycles created duplicate records")
    result = ddns_update(app, cookie)
    require(result["success"] and mock.snapshot() == after,
            "DDNS singleflight guard failed to reset after the first cycle completed")
    print("PASS held DDNS cycle rejects concurrent request with 409, creates one record and resets guard")


def bulk_revocation_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    before = mock.snapshot()
    ids = [r["id"] for r in before[1][zone]][:2]
    mock.hold_mutation_id = ids[0]
    bulk = Background(lambda: request(app.port, "POST", f"/api/zones/{zone}/records/bulk",
                                      {"action": "delete", "ids": ids}, cookie=cookie)[0]).start()
    try:
        require(mock.mutation_entered.wait(timeout=HOLD_TIMEOUT),
                "first bulk delete did not reach the upstream hold")
        new_cookie = revoke_by_password_change(app, cookie)
        request(app.port, "GET", "/api/auth/me", cookie=new_cookie)
    finally:
        mock.mutation_release.set()
        bulk.join()
    require(bulk.ok(), "bulk after revocation did not settle: " + background_errors(bulk))
    result = bulk.result
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
    with mock.records() as records:
        apex = find_record(records[zone], "synthetic apex A record is missing", type="A", name="example.com")
    mock.hold_mutation_id = apex["id"]
    before = mock.snapshot()
    update = Background(lambda: ddns_update(app, cookie)).start()
    try:
        require(mock.mutation_entered.wait(timeout=HOLD_TIMEOUT),
                "first DDNS family write did not reach the upstream hold")
        new_cookie = revoke_by_password_change(app, cookie)
    finally:
        mock.mutation_release.set()
        update.join()
    require(update.ok(), "DDNS after revocation did not settle: " + background_errors(update))
    result = update.result
    outcomes = {o["record_type"]: o for o in result["outcomes"] if o["domain"] == "example.com"}
    require(not result["success"] and outcomes["A"]["status"] == "updated"
            and outcomes["AAAA"]["status"] == "failed" and outcomes["AAAA"]["error"],
            "DDNS hid the unsent family failure after session revocation")
    after = mock.snapshot()
    require(after[0] == before[0] + 1 and apex["content"] == "203.0.113.42"
            and [r for r in after[1][zone] if r["type"] == "AAAA"]
            == [r for r in before[1][zone] if r["type"] == "AAAA"],
            "DDNS sent a new family mutation after originating session was revoked")
    result = ddns_update(app, new_cookie)
    require(result["success"] and mock.snapshot()[0] == after[0] + 1,
            "DDNS singleflight guard or new valid session was not usable after revoked cycle")
    print("PASS session revocation stops unsent DDNS family writes with partial outcomes and guard reset")


def oversized_body_smoke(app, mock):
    cookie = setup_session(app)
    zone = mock.module.ZONES[0]["id"]
    before = mock.snapshot()
    conn = http.client.HTTPConnection("127.0.0.1", app.port, timeout=HTTP_TIMEOUT)
    try:
        conn.putrequest("POST", f"/api/zones/{zone}/import?filename=synthetic-zone.txt")
        conn.putheader("Cookie", cookie)
        conn.putheader("X-Requested-With", "fetch")
        conn.putheader("Content-Type", "text/plain")
        conn.putheader("Content-Length", str(MAX_BODY_BYTES + 1))
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


def read_reply(sock):
    """Read one HTTP response head and its Content-Length body from a raw socket."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        require(chunk, "connection closed before a full response head")
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    if head.startswith(b"HTTP/1.1 1"):
        return head, body
    length = next((int(line.split(b":", 1)[1]) for line in head.split(b"\r\n")
                   if line.lower().startswith(b"content-length:")), 0)
    while len(body) < length:
        chunk = sock.recv(4096)
        require(chunk, "connection closed before the full response body")
        body += chunk
    return head, body


def http_smoke(app, mock):
    app.start()
    app.ready()
    conn = http.client.HTTPConnection("127.0.0.1", app.port, timeout=HTTP_TIMEOUT)
    try:
        # HEAD first: a leaked body would corrupt the GET that follows on the same connection.
        conn.request("HEAD", "/api/config")
        head = conn.getresponse()
        require(head.status == 200 and head.read() == b"", "HEAD /api/config must answer 200 without a body")
        conn.request("GET", "/api/config")
        get = conn.getresponse()
        body = get.read()
        require(get.status == 200 and head.getheader("Content-Length") == str(len(body)),
                "HEAD must send the Content-Length of the GET response")
        date = get.getheader("Date", "")
        require(re.fullmatch(r"[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT", date)
                and abs(email.utils.parsedate_to_datetime(date).timestamp() - time.time()) < 60,
                "responses must carry a current IMF-fixdate Date header")
        require(get.getheader("Connection") is None, "keep-alive responses need no Connection header")
    finally:
        conn.close()

    payload = json.dumps({"password": PASSWORD}).encode()
    with socket.create_connection(("127.0.0.1", app.port), timeout=HTTP_TIMEOUT) as sock:
        sock.sendall(f"POST /api/auth/login HTTP/1.1\r\nHost: 127.0.0.1:{app.port}\r\n"
                     "X-Requested-With: fetch\r\nContent-Type: application/json\r\n"
                     f"Expect: 100-continue\r\nContent-Length: {len(payload)}\r\n\r\n".encode())
        interim, _ = read_reply(sock)
        require(interim == b"HTTP/1.1 100 Continue", "Expect: 100-continue must be answered before the body")
        sock.sendall(payload)
        final, _ = read_reply(sock)
        require(final.startswith(b"HTTP/1.1 428 Precondition Required\r\n"),
                "login before setup must answer 428 with its reason phrase")

    # Let the server notice the closed connections above before filling every slot.
    time.sleep(SHORT_PAUSE)
    held = []
    try:
        for _ in range(MAX_CONNECTIONS):
            held.append(socket.create_connection(("127.0.0.1", app.port), timeout=HTTP_TIMEOUT))
        with socket.create_connection(("127.0.0.1", app.port), timeout=HTTP_TIMEOUT) as excess:
            head, body = read_reply(excess)
        require(head.startswith(b"HTTP/1.1 503 Service Unavailable\r\n")
                and b"\r\nRetry-After: 1" in head and json.loads(body).get("error"),
                "a connection over the limit must get 503 with Retry-After")
    finally:
        for sock in held:
            sock.close()
    deadline = time.monotonic() + HTTP_TIMEOUT
    while True:
        try:
            request(app.port, "GET", "/api/config")
            break
        except (AssertionError, OSError, http.client.HTTPException):
            require(time.monotonic() < deadline, "server did not recover after refusing connections")
            time.sleep(POLL_INTERVAL)
    require(app.alive() and mock.writes == 0, "HTTP protocol checks stopped the server or wrote DNS")
    print("PASS HEAD as GET, Date header, Expect 100-continue, reason phrases and 503 over the connection limit")


def shutdown_smoke(app, mock):
    graceful_shutdown(app, mock)
    if app.image:
        print("SKIP closed stdout/stderr check needs the native binary")
        return
    closed_output_shutdown(app)


def graceful_shutdown(app, mock):
    native = not app.image
    app.start(overrides={"QUIET": "false"})
    app.ready()
    cookie = create_admin(app)
    zone = mock.module.ZONES[0]["id"]
    mock.hold_next_list = True
    slow = Background(lambda: request(app.port, "GET", f"/api/zones/{zone}/records", cookie=cookie)[0])
    slow.start()
    stopper = None
    try:
        require(mock.list_entered.wait(timeout=HOLD_TIMEOUT), "request did not reach the held upstream call")
        started = time.monotonic()
        if native:
            app.process.send_signal(signal.SIGTERM)
        else:
            with app.log() as log:
                stopper = subprocess.Popen(
                    [app.docker, "stop", "--time", str(STOP_GRACE), app.container],
                    env=app.host_env, stdout=log, stderr=log)
        time.sleep(SHORT_PAUSE)
        require(not listening(app.port), "server kept accepting connections after SIGTERM")
    finally:
        mock.list_release.set()
        slow.join()
    require(slow.ok() and "records" in (slow.result or {}),
            "in-flight request did not finish during shutdown: " + background_errors(slow))
    try:
        if native:
            code = app.process.wait(timeout=SETTLE_TIMEOUT)
            output = app.log_path.read_bytes()
        else:
            stopper.wait(timeout=STOP_GRACE + SETTLE_TIMEOUT)
            code = int(app.docker_run("inspect", "--format", "{{.State.ExitCode}}",
                                      app.container).stdout.strip())
            output = app.docker_run("logs", app.container).stdout
    except subprocess.TimeoutExpired as exc:
        raise AssertionError("server did not exit after SIGTERM") from exc
    elapsed = time.monotonic() - started
    require(code == 0, f"SIGTERM must exit with code 0, got {code}")
    require(elapsed < SHUTDOWN_LIMIT, f"graceful shutdown took {elapsed:.1f}s")
    require(b"Stopping" in output, "shutdown did not log Stopping")
    print(f"PASS SIGTERM finishes the in-flight request, refuses new connections and exits 0 in {elapsed:.1f}s")


def closed_output_shutdown(app):
    app.stop()
    read_end, write_end = os.pipe()
    os.close(read_end)
    try:
        app.start(overrides={"QUIET": "false"}, output=write_end)
    finally:
        os.close(write_end)
    app.ready()
    request(app.port, "GET", "/api/config")
    app.process.send_signal(signal.SIGTERM)
    try:
        code = app.process.wait(timeout=SETTLE_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError("server with closed stdout did not exit after SIGTERM") from exc
    require(code == 0, f"server with closed stdout/stderr exited with {code}")
    print("PASS failed log writes to a closed pipe do not stop the server")


def smoke(app, mock):
    app.start()
    app.ready()
    cookie = baseline_setup(app)
    zone, path = baseline_crud(app, mock, cookie)
    baseline_ddns(app, mock, cookie, zone, path)
    baseline_restart(app, cookie)
    baseline_bad_providers(app, mock)
    baseline_bad_state(app)


def baseline_setup(app):
    """Fresh-state access rules and setup validation. Returns the admin session cookie."""
    config, _ = request(app.port, "GET", "/api/config")
    require(config["configured"] is False, "fresh state unexpectedly configured")
    require("totp_enabled" not in config, "public config exposes the 2FA state")
    for path in ("/api/zones", "/api/auth/me", "/api/ddns/status"):
        request(app.port, "GET", path, expected=401)
    request(app.port, "GET", "/api/zones", cookie="cfddns_session=forged", expected=401)
    request(app.port, "POST", "/api/ddns/update", {}, expected=401)
    request(app.port, "POST", "/api/auth/setup", ADMIN_SETUP, mutation=False, expected=403)
    request(app.port, "POST", "/api/auth/setup",
            {"password": "short", "confirm": "short"}, expected=400)
    request(app.port, "POST", "/api/auth/setup",
            {"password": PASSWORD, "confirm": "mismatch"}, expected=400)
    config, _ = request(app.port, "GET", "/api/config")
    require(config["configured"] is False, "invalid setup changed identity state")
    cookie = create_admin(app)
    request(app.port, "GET", "/api/zones", cookie="cfddns_session=" + cookie.split("=", 1)[1],
            expected=401)
    request(app.port, "POST", "/api/auth/setup", ADMIN_SETUP, expected=409)
    request(app.port, "POST", "/api/auth/login", {"password": PASSWORD},
            mutation=False, expected=403)
    request(app.port, "POST", "/api/auth/login", {"password": "wrong-synthetic"},
            expected=401)
    request(app.port, "GET", "/api/auth/me", cookie=cookie)
    return cookie


def baseline_crud(app, mock, cookie):
    """Record create, update and delete through the API. Returns (zone ID, records path)."""
    zones, _ = request(app.port, "GET", "/api/zones", cookie=cookie)
    require(len(zones) == 1 and zones[0]["name"] == "example.com",
            "API must expose only the synthetic zone")
    zone = zones[0]["id"]
    path = f"/api/zones/{zone}/records"
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
    return zone, path


def baseline_ddns(app, mock, cookie, zone, path):
    before = mock.snapshot()
    ddns_update(app, cookie, mutation=False, expected=403)
    require(mock.snapshot() == before, "unprotected DDNS request wrote DNS")
    ddns_update(app, cookie)
    require(mock.snapshot()[0] > before[0], "DDNS update did not issue a DNS write")
    listing, _ = request(app.port, "GET", path, cookie=cookie)
    apex = [r for r in listing["records"] if r["type"] == "A" and r["name"] == "example.com"]
    require(apex and all(r["content"] == "203.0.113.42" for r in apex),
            "literal IPv4 DDNS did not update the synthetic apex")
    require([r for r in mock.snapshot()[1][zone] if r["type"] == "AAAA"]
            == [r for r in before[1][zone] if r["type"] == "AAAA"],
            "IPv6 none must preserve AAAA records")
    status, _ = request(app.port, "GET", "/api/ddns/status", cookie=cookie)
    require(status["ipv4"] == "203.0.113.42" and status["ipv6"] is None
            and all(d["in_sync"] for d in status["domains"]), "DDNS status is inconsistent")
    chunk_regression(app)
    print("PASS literal DDNS, disabled IPv6 preservation and max-chunk process survival")


def baseline_restart(app, cookie):
    app.secure = False
    app.restart()
    config, _ = request(app.port, "GET", "/api/config")
    require(config["configured"] is True, "restart lost persisted identity")
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    request(app.port, "POST", "/api/auth/setup", ADMIN_SETUP, expected=409)
    cookie = login(app)
    request(app.port, "GET", "/api/auth/me", cookie=cookie)
    _, header = request(app.port, "POST", "/api/auth/logout", {}, cookie=cookie)
    cleared_cookie(header, app.secure)
    request(app.port, "GET", "/api/auth/me", cookie=cookie, expected=401)
    # An expired or revoked session can still clear its cookie.
    _, header = request(app.port, "POST", "/api/auth/logout", {}, cookie=cookie)
    cleared_cookie(header, app.secure)
    request(app.port, "POST", "/api/auth/logout", {}, cookie=cookie, mutation=False, expected=403)
    print("PASS restart persistence, stale-session invalidation and logout")


def baseline_bad_providers(app, mock):
    for kind in ("invalid", "wrong-family", "http-error", "non-2xx"):
        app.restart(f"url:http://127.0.0.1:{mock.port}/provider/{kind}")
        cookie = login(app)
        before = mock.snapshot()
        calls = mock.calls
        status, _ = request(app.port, "GET", "/api/ddns/status", cookie=cookie)
        require(status["ipv4"] is None and status["ipv4_error"],
                f"{kind} provider must report detection failure")
        result = ddns_update(app, cookie)
        require(any("detection failed" in line for line in result["log"]),
                f"{kind} provider update did not report detection failure")
        require(mock.calls >= calls + 2, f"{kind} provider was not exercised")
        require(mock.snapshot() == before, f"{kind} provider changed DNS or sent a write")
    print("PASS malformed, wrong-family, HTTP-error and non-2xx providers issue zero DNS writes")


def baseline_bad_state(app):
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


SUITES = {
    "baseline": smoke, "auth": auth_smoke, "factor-lockout": factor_lockout_smoke,
    "auth-storage": auth_storage_smoke, "enrollment-storage": enrollment_storage_smoke,
    "metadata": metadata_smoke,
    "identifiers": identifier_smoke, "bind": bind_smoke,
    "bind-edge": bind_edge_smoke,
    "customization": customization_smoke, "config": config_smoke,
    "origin": origin_smoke, "ddns-contract": ddns_contract_smoke,
    "providers": provider_smoke, "malformed-upstream": malformed_upstream_smoke,
    "malformed-import": malformed_import_smoke,
    "concurrent-ddns": concurrent_ddns_smoke, "bulk-revocation": bulk_revocation_smoke,
    "ddns-revocation": ddns_revocation_smoke,
    "oversized-body": oversized_body_smoke,
    "http": http_smoke,
    "shutdown": shutdown_smoke,
}


def log_tail(path, lines=LOG_TAIL_LINES):
    try:
        return path.read_bytes().decode("utf-8", "replace").splitlines()[-lines:]
    except OSError:
        return []


def report_failure(name, exc, server_output):
    """Print a failed group to stderr with synthetic secrets redacted.

    A failed check prints its message. Any other exception also prints its last
    traceback frames. The server output tail follows when there is one.
    """
    if isinstance(exc, AssertionError):
        lines = [f"FAIL {name}: {exc}"]
    else:
        detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        frames = traceback.format_tb(exc.__traceback__, limit=-TRACEBACK_FRAMES)
        lines = [f"FAIL {name}: {detail}", *"".join(frames).rstrip("\n").splitlines()]
    if server_output:
        lines.append(f"  last {len(server_output)} lines of server output:")
        lines += ["    " + line for line in server_output]
    sys.stdout.flush()  # keep earlier PASS lines ahead of the report
    print(scrub("\n".join(lines)), file=sys.stderr, flush=True)


def run_group(name, suite, module, image):
    """Run one group with its own temp directory, mock and app. Returns False if it failed."""
    with tempfile.TemporaryDirectory(prefix="cfddns-smoke-") as temp:
        try:
            with Mock(module) as mock:
                app = App(temp, mock, image)
                try:
                    suite(app, mock)
                finally:
                    app.close()
        except Exception as exc:  # Report the group and go on with the others.
            report_failure(name, exc, log_tail(Path(temp) / SERVER_LOG))
            return False
    return True


def run_groups(module, groups, image):
    seed = module.snapshot_records()
    failures = []
    for name, suite in groups.items():
        module.reset_records(seed)
        if not run_group(name, suite, module, image):
            failures.append(name)
    require(not failures, "regression groups failed: " + ", ".join(failures))
    print("PASS smoke workflow")


def serve(module, image, port):
    with tempfile.TemporaryDirectory(prefix="cfddns-smoke-") as temp, Mock(module) as mock:
        app = App(temp, mock, image, True, port)
        try:
            app.secure = False
            app.start()
            app.ready()
            create_admin(app)
            print(f"URL: http://127.0.0.1:{app.port}", flush=True)
            print("Password: the PASSWORD constant in scripts/smoke-test.py", flush=True)
            threading.Event().wait()
        finally:
            app.close()


def parse_args():
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
    parser.add_argument("--only", choices=SUITES, help="run one independent regression group")
    args = parser.parse_args()
    if args.port is not None and (not args.serve or not 1 <= args.port <= 65535):
        parser.error("--port requires --serve and a port between 1 and 65535")
    if args.only and (args.serve or args.fixtures_only):
        parser.error("--only cannot be combined with --serve or --fixtures-only")
    return args


def main():
    args = parse_args()
    # Keep PASS lines (stdout) and FAIL reports (stderr) in order when output is piped.
    sys.stdout.reconfigure(line_buffering=True)

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
        serve(module, args.container_image, args.port)
        return
    groups = {args.only: SUITES[args.only]} if args.only else SUITES
    run_groups(module, groups, args.container_image)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, http.client.HTTPException,
            subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
