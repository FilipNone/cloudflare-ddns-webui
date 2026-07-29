# 🌍 Cloudflare DDNS — Web UI

A **lightweight, fast web GUI for [cloudflare-ddns](https://github.com/timothymiller/cloudflare-ddns)**, written in Rust. Built with the same philosophy as cloudflare-ddns: a tiny fully-static binary with zero runtime dependencies and minimal crates — no web framework, the HTTP/1.1 server is hand-rolled on top of tokio, and the entire frontend (vanilla JS + CSS, no build step) is embedded in the binary at compile time.

Manage your DNS records through a modern dark interface modelled after the Cloudflare dashboard, with DDNS-aware extras on top.

## ✨ Features

- 🔒 **Secure authentication** — single admin password (PBKDF2-hashed in memory at boot), in-memory sessions with `HttpOnly` + `SameSite=Strict` cookies, per-IP login rate limiting, strict CSP/security headers, CSRF protection on every mutation
- 🔑 **Token-based Cloudflare API** — uses the same `CLOUDFLARE_API_TOKEN` (or `CLOUDFLARE_API_TOKEN_FILE`) as cloudflare-ddns
- 🌐 **Zone selector** — switch between all zones visible to your token
- 🔍 **Filters & search** — full-text search across name/content/comment/tags, type filter, sortable columns
- 🗂️ **Columns** — show/hide any column; *Last updated* and *Created* are hidden by default (persisted per browser)
- 📥📤 **Import & export** — Cloudflare-native BIND zone files (identical to the dashboard, honours `cf_tags=cf-proxied:true`)
- ➕ **Add record** — A, AAAA, CNAME, TXT, MX, NS, SRV, CAA, PTR, HTTPS, SVCB with structured SRV/CAA fields
- ☑️ **Bulk operations** — select multiple records, **delete in bulk** or **modify in bulk** (TTL, proxy, comment). Proxy changes are DNS-type checked: only A/AAAA/CNAME records can be proxied, enforced server-side
- ☁️ **Inline proxy toggle** — orange cloud on/off right from the table (greyed out for non-proxiable types)
- 💬 **Tags & comments** — edit per record or in bulk
- 🏠 **DDNS dashboard** — current public IPv4/IPv6 (same detection providers as cloudflare-ddns), per-domain sync status, and an **Update now** button that mirrors the cloudflare-ddns create-or-update behavior
- 🗣️ **Language selector** — English for now, structure ready for more
- 🤏 **Tiny & fast** — single static binary (~few MB), `FROM scratch` Docker image, ~MBs of RAM

## 🚀 Quick start (Docker)

```bash
docker run -d \
  --name cloudflare-ddns-webui \
  --restart unless-stopped \
  -p 8080:8080 \
  -e CLOUDFLARE_API_TOKEN=your-api-token \
  -e ADMIN_PASSWORD=your-strong-password \
  youruser/cloudflare-ddns-webui:latest
```

Open http://localhost:8080 and sign in.

## 🚢 Deploy on Dokploy

1. Push this repository to GitHub.
2. In Dokploy: **Create Service → Application**, pick your GitHub repo.
3. Build type: **Dockerfile** (repo root). No build args needed.
4. Set the environment variables (see below): `CLOUDFLARE_API_TOKEN`, `ADMIN_PASSWORD`, and optionally `DOMAINS`, `SECURE_COOKIES=true`.
5. Attach a domain. Dokploy's Traefik terminates TLS and proxies to container port **8080** — no port mapping needed.
6. Deploy. With HTTPS enabled, set `SECURE_COOKIES=true` and redeploy.

A `docker-compose.yml` is also included for reference deployments.

## 🔑 Cloudflare API token preset

Create the token at [My Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens):

1. **Create Token** → use the **Edit zone DNS** template
2. Permissions: `Zone → Zone → Read` **and** `Zone → DNS → Edit`
3. Zone Resources: **Include → Specific zone** (least privilege) or **All zones**

## ⚙️ Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDFLARE_API_TOKEN` | — | 🔑 API token (required) |
| `CLOUDFLARE_API_TOKEN_FILE` | — | 📄 Path to a file containing the token (Docker secrets) |
| `ADMIN_PASSWORD` | — | 🔒 Web UI password, min 8 chars (required) |
| `ADMIN_PASSWORD_FILE` | — | 📄 Path to a file containing the password |
| `LISTEN` | `0.0.0.0:8080` | 🌐 Bind address |
| `SESSION_TTL` | `24h` | ⏳ Session lifetime |
| `SECURE_COOKIES` | `false` | 🔒 `Secure` cookie attribute — enable behind HTTPS |
| `UPDATE_TIMEOUT` | `30s` | ⏳ Cloudflare API timeout |
| `DOMAINS` | — | 🏠 DDNS domains for the dashboard (same as cloudflare-ddns) |
| `IP4_PROVIDER` | `ipify` | 🔍 IPv4 detection (`ipify`, `cloudflare.trace`, `url:…`, `literal:…`, `none`) |
| `IP6_PROVIDER` | `cloudflare.trace` | 🔍 IPv6 detection |
| `TTL` | `1` (auto) | ⏱️ TTL applied by on-demand updates |
| `PROXIED` | `false` | ☁️ Proxied flag applied by on-demand updates |
| `RECORD_COMMENT` | — | 💬 Comment applied by on-demand updates |
| `DETECTION_TIMEOUT` | `5s` | ⏳ IP detection timeout |
| `EMOJI` | `true` | 🎨 Emoji in logs |
| `QUIET` | `false` | 🤫 Quiet logs |

## 🔨 Building from source

```bash
cargo build --release
./target/release/cloudflare-ddns-webui
```

The Docker image builds with `./Dockerfile` (multi-stage, musl static, UPX-compressed, `FROM scratch`, ~2.2 MB).

### 🧪 Development with a mock Cloudflare API

A mock of the Cloudflare API (seeded with a realistic zone) is included so the UI can be developed without a real token:

```bash
python3 scripts/mock-cloudflare-api.py 8787 &
CLOUDFLARE_API_BASE=http://127.0.0.1:8787/client/v4 \
CLOUDFLARE_API_TOKEN=test ADMIN_PASSWORD=test-password-123 \
cargo run
```

## 🔐 Security notes

- The admin password is hashed with PBKDF2-HMAC-SHA256 (100k iterations, per-boot salt) and the plaintext is dropped from memory immediately after boot.
- Sessions are random 256-bit tokens kept in memory only — restart invalidates all sessions.
- After 5 failed logins, the source IP is locked out for 5 minutes.
- Every API mutation requires a session cookie **and** a custom header browsers cannot send cross-site.
- Strict Content-Security-Policy (`default-src 'self'`, no inline scripts), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
- The Cloudflare token never leaves the server; the browser only talks to this app.

## 📄 License

GPL-3.0, like cloudflare-ddns.
