# 🌍 Cloudflare DDNS - Web UI

A **lightweight, fast web GUI for [cloudflare-ddns](https://github.com/timothymiller/cloudflare-ddns)**, written in Rust. Built with the same philosophy as cloudflare-ddns: a tiny fully-static binary with zero runtime dependencies and minimal crates - no web framework, the HTTP/1.1 server is hand-rolled on top of tokio, and the entire frontend (vanilla JS + CSS, no build step) is embedded in the binary at compile time.

Manage your DNS records through a modern interface modelled after the Cloudflare dashboard, with DDNS-aware extras on top.

## ✨ Features

- 🔒 **First-run password setup** - the admin password is created through the UI on first access and stored only as a PBKDF2 hash. No password env vars, no plaintext anywhere
- 🛡️ **Two-factor authentication** - TOTP (RFC 6238) with QR-code enrollment and one-time **backup recovery codes** (shown once, downloadable as `.txt`). 2FA disable and password change both require identity confirmation
- 🎨 **Themes** - light, dark and **system default** (the default), plus a customizable accent color and a custom logo/favicon upload
- 🔑 **Token-based Cloudflare API** - uses the same `CLOUDFLARE_API_TOKEN` (or `CLOUDFLARE_API_TOKEN_FILE`) as cloudflare-ddns
- 🌐 **Zone selector** - switch between all zones visible to your token
- 🔍 **Filters & search** - full-text search across name/content/comment/tags, type filter, sortable columns
- 🗂️ **Columns** - show/hide any column; *Last updated* and *Created* are hidden by default (persisted per browser)
- 📥📤 **Import & export** - Cloudflare-native BIND zone files (append-only, honours `cf_tags=cf-proxied:true`, with pre-flight validation and clear error reporting)
- ➕ **Add record** - A, AAAA, CAA, CNAME, HTTPS, MX, NS, PTR, SRV, SVCB, TXT with per-type structured fields and **live input validation** (IPv4/IPv6/domain/port/...)
- ☑️ **Bulk operations** - select multiple records, **delete in bulk** or **modify in bulk** (TTL, proxy, comment). Proxy changes are DNS-type checked: only A/AAAA/CNAME records can be proxied, enforced server-side
- ☁️ **Cloudflare-correct proxy/TTL semantics** - TTL is forced to *Auto* while a record is proxied, exactly like the dashboard
- 🏠 **DDNS dashboard** - current public IPv4/IPv6 (same detection providers as cloudflare-ddns), per-domain sync status, and an **Update now** button that mirrors the cloudflare-ddns create-or-update behavior
- 🗣️ **Language selector** - English for now, structure ready for more
- 🤏 **Tiny & fast** - single static binary (~2.5 MB), `FROM scratch` Docker image, a few MB of RAM

## 🚀 Quick start (Docker)

```bash
docker run -d \
  --name cloudflare-ddns-webui \
  --restart unless-stopped \
  -p 8080:8080 \
  -v webui-data:/data \
  -e CLOUDFLARE_API_TOKEN=your-api-token \
  youruser/cloudflare-ddns-webui:latest
```

Open http://localhost:8080 - on first access you will be asked to **create the admin password**.

> ⚠️ Mount a volume at `/data`. It holds the password hash, the TOTP secret and UI settings. Without it, a container recreate resets the admin account.

## 🚢 Deploy on Dokploy

1. Push this repository to GitHub (or fork it).
2. In Dokploy: **Create Service -> Application**, pick your GitHub repo.
3. Build type: **Dockerfile** (repo root). No build args needed.
4. Set the environment variables (see below): `CLOUDFLARE_API_TOKEN` and optionally `DOMAINS`, `SECURE_COOKIES=true`.
5. Add a **volume** mounted at `/data` (Dokploy: *Mounts -> Add Volume*) so your admin account survives redeploys.
6. Attach a domain. Dokploy's Traefik terminates TLS and proxies to container port **8080**.
7. Deploy. With HTTPS enabled, set `SECURE_COOKIES=true` and redeploy.

A `docker-compose.yml` is also included for reference deployments.

## 🔑 Cloudflare API token preset

Create the token at [My Profile -> API Tokens](https://dash.cloudflare.com/profile/api-tokens):

1. **Create Token** -> use the **Edit zone DNS** template
2. Permissions: `Zone -> Zone -> Read` **and** `Zone -> DNS -> Edit`
3. Zone Resources: **Include -> Specific zone** (least privilege) or **All zones**

## 🛡️ Two-factor authentication & recovery

1. **Settings -> Security -> Enable 2FA**
2. Scan the QR code with your authenticator app (Aegis, Bitwarden, 2FAS, Google Authenticator...) and confirm with the 6-digit code
3. **Save the backup codes immediately** - they are shown only once and can be downloaded as a `.txt` file. Each code works exactly once
4. Signing in later accepts either the current TOTP code or one backup code
5. Disabling 2FA requires a valid TOTP (or backup) code; changing the password requires the current password **and** a 2FA code when 2FA is on

If you lose both the authenticator and the backup codes, delete `state.json` inside the `/data` volume to reset the admin account (first-run setup will run again).

## ⚙️ Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDFLARE_API_TOKEN` | - | 🔑 API token (required) |
| `CLOUDFLARE_API_TOKEN_FILE` | - | 📄 Path to a file containing the token (Docker secrets) |
| `LISTEN` | `0.0.0.0:8080` | 🌐 Bind address |
| `DATA_DIR` | `/data` | 💾 Persistent state dir (password hash, TOTP secret, UI settings) |
| `SESSION_TTL` | `24h` | ⏳ Session lifetime |
| `SECURE_COOKIES` | `false` | 🔒 `Secure` cookie attribute - enable behind HTTPS |
| `UPDATE_TIMEOUT` | `30s` | ⏳ Cloudflare API timeout |
| `DOMAINS` | - | 🏠 DDNS domains for the dashboard (same as cloudflare-ddns) |
| `IP4_PROVIDER` | `ipify` | 🔍 IPv4 detection (`ipify`, `cloudflare.trace`, `url:...`, `literal:...`, `none`) |
| `IP6_PROVIDER` | `cloudflare.trace` | 🔍 IPv6 detection |
| `TTL` | `1` (auto) | ⏱️ TTL applied by on-demand updates |
| `PROXIED` | `false` | ☁️ Proxied flag applied by on-demand updates |
| `RECORD_COMMENT` | - | 💬 Comment applied by on-demand updates |
| `DETECTION_TIMEOUT` | `5s` | ⏳ IP detection timeout |
| `EMOJI` | `true` | 🎨 Emoji in logs |
| `QUIET` | `false` | 🤫 Quiet logs |

## 🔨 Building from source

```bash
cargo build --release
DATA_DIR=./data ./target/release/cloudflare-ddns-webui
```

The Docker image builds with `./Dockerfile` (multi-stage, musl static, UPX-compressed, `FROM scratch`).

Run the test suite (TOTP RFC 6238 vectors, QR structure, backup codes, auth flows):

```bash
cargo test
```

### 🧪 Development with a mock Cloudflare API

A mock of the Cloudflare API (seeded with a realistic zone) is included so the UI can be developed without a real token:

```bash
python3 scripts/mock-cloudflare-api.py 8787 &
DATA_DIR=./data \
CLOUDFLARE_API_BASE=http://127.0.0.1:8787/client/v4 \
CLOUDFLARE_API_TOKEN=test \
cargo run
```

## 🔐 Security notes

- The admin password exists only as a PBKDF2-HMAC-SHA256 hash (100k iterations, per-account salt) in `/data/state.json` (`chmod 600`).
- Backup codes are stored as salted one-way hashes and are consumed on use.
- Sessions are random 256-bit tokens kept in memory only - a restart invalidates all sessions.
- After 5 failed logins (or 5 failed 2FA attempts), the source IP is locked out for 5 minutes.
- Every API mutation requires a session cookie **and** a custom header browsers cannot send cross-site.
- Strict Content-Security-Policy (`default-src 'self'`, no inline scripts/styles), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
- Uploaded SVG logos are sanitized (scripts, event handlers and `javascript:` URLs stripped) before being served.
- The Cloudflare token never leaves the server; the browser only talks to this app.

## 📄 License

GPL-3.0, like cloudflare-ddns.
