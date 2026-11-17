# Architecture

One static Rust binary serves the API and the frontend. The HTTP/1.1 server is hand-written on Tokio (`current_thread` runtime), and the files in `web/` are compiled in with `include_str!`. The release profile sets `panic = "abort"`.

## Source map

```text
src/
  main.rs        startup: config, auth state, UI store, signals, listener
  http.rs        HTTP/1.1 parsing and framing, connection limit, timeouts, graceful shutdown
  routes.rs      API routes, Host/Origin and mutation-header checks, input validation, security headers, static files
  auth.rs        admin account, sessions, PBKDF2 hashes, backup codes, login limiter, state.json
  totp.rs        RFC 6238 TOTP and the enrollment QR code
  cloudflare.rs  Cloudflare API client, record types, batch endpoint
  ddns.rs        IP detection, DNS status, Update now
  bind.rs        BIND zone file check before an import
  config.rs      environment parsing, rejected updater settings
  customize.rs   accent colour, uploaded logo, ui-settings.json
  persist.rs     crash-safe file replacement shared by auth.rs and customize.rs
  pp.rs          log output (emoji, quiet mode, write errors ignored)
web/
  index.html style.css favicon.svg   page, stylesheet, default logo
  js/*.js, app.js                    frontend scripts, see frontend.md
  app.test.cjs appearance.test.cjs   Node test suites
scripts/
  mock-cloudflare-api.py   Cloudflare API mock with the synthetic example.com zone
  smoke-test.py            end-to-end harness against the mock
```

## Request flow

1. `http.rs` accepts at most 16 connections (more get `503`), reads one request with size caps and deadlines, and passes it to `routes::handle`. HEAD is served as GET without a body.
2. `routes.rs` checks the Host and Origin headers against `PUBLIC_ORIGIN` or the listening address, then adds the security headers to every response.
3. Every non-GET API request needs `X-Requested-With: fetch`. Everything except the routes below marked public needs a session cookie.
4. Hashing work (PBKDF2) runs on the blocking pool through `run_auth`; appearance saves go through `run_ui`.

## API

All routes are under `/api`.

| Route | Notes |
|---|---|
| `GET /config` | public |
| `POST /auth/setup`, `/auth/login`, `/auth/login/2fa`, `/auth/logout` | public; logout works with an expired session |
| `GET /auth/me`, `POST /auth/password`, `/auth/2fa/begin`, `/confirm`, `/cancel`, `/disable` | account |
| `POST /ui/accent`, `POST /ui/icon`, `DELETE /ui/icon` | appearance |
| `GET /zones`, `GET /zones/{id}/records`, `POST /zones/{id}/records` | zones and records |
| `PUT` / `DELETE /zones/{id}/records/{record}` | `PUT` is sent to Cloudflare as PATCH |
| `POST /zones/{id}/records/bulk` | bulk delete or update; always `200` with `{results, succeeded, failed}` |
| `GET /zones/{id}/export`, `POST /zones/{id}/import` | BIND export and checked import |
| `GET /ddns/status`, `POST /ddns/update` | DDNS page, see ddns.md |

Request bodies use `#[serde(deny_unknown_fields)]`, so the frontend must send only known fields.

## Data directory

`DATA_DIR` (default `/data`) holds:

- `state.json`: password hash and iteration count, TOTP secret, backup code hashes. Mode `600`. Missing means first-run setup; unreadable or invalid stops startup.
- `ui-settings.json`: accent colour and the icon's MIME type and file name. Invalid content is renamed to `ui-settings.json.invalid`.
- `icon-<32 hex>`: the uploaded logo.

Every write goes through `persist::replace_file`: a private temp file, fsync, rename, then a directory sync. Memory changes only after the save succeeds. Sessions, login challenges and limiter counters live in memory and reset on restart.
