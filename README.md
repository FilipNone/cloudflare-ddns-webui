# DO NOT INSTALL - APLHA RELEASE

# 🌍 Cloudflare DDNS - Web UI

A **lightweight, fast web GUI for [cloudflare-ddns](https://github.com/timothymiller/cloudflare-ddns)**, written in Rust. Built with the same philosophy as cloudflare-ddns: a tiny fully-static binary with zero runtime dependencies and minimal crates - no web framework, the HTTP/1.1 server is hand-rolled on top of tokio, and the entire frontend (vanilla JS + CSS, no build step) is embedded in the binary at compile time.

Manage your DNS records through a modern interface modelled after the Cloudflare dashboard, with DDNS-aware extras on top.

## Project recovery

Development follows the [Chris Titus AI workflow](https://christitus.com/my-ai-workflow/): a written specification, small tested tasks, independent review, latest-commit CI, and a human merge decision. See [SPEC.md](SPEC.md), [ROADMAP.md](ROADMAP.md), [TASKS.md](TASKS.md) and [AGENTS.md](AGENTS.md) for requirements and remaining work. Kilo commands `/phase`, `/verify` and `/prepare-pr` support that sequence without granting permission to publish or deploy.

The GUI calls Cloudflare directly. It does not start, configure, or monitor the companion updater, and supports only a subset of its environment settings. The local ignored `Cloudflare DDNS/` folder is reference material, not a dependency. Do not assume daemon integration or run manual GUI updates against domains whose updater ownership policy is unsupported by the GUI. The supported deployment model is a restricted administrative network or loopback behind an HTTPS proxy, not public-internet exposure. See `TASKS.md` for test evidence and outstanding owner verification.

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
- ☑️ **Bulk operations** - select multiple records, **delete in bulk** or **modify in bulk** (TTL, proxy, comment, tags). Comments and tags have explicit keep/set/clear choices. Proxy changes are DNS-type checked: only A/AAAA/CNAME records can be proxied, enforced server-side
- ☁️ **Cloudflare-correct proxy/TTL semantics** - TTL is forced to *Auto* while a record is proxied, exactly like the dashboard
- 🏠 **DDNS dashboard** - current IPv4/IPv6 from the supported providers, per-domain address sync status, and an **Update now** button that creates missing records or updates existing address content directly through Cloudflare
- 🗣️ **Language selector** - English for now, structure ready for more
- 🤏 **Static packaging** - one embedded-assets binary and a non-root `FROM scratch` Docker image. Binary size and memory use depend on the build and workload; no fixed RAM claim is made.

## 🚀 Quick start (Docker)

```bash
docker run -d \
  --name cloudflare-ddns-webui \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v webui-data:/data \
  -e CLOUDFLARE_API_TOKEN=your-api-token \
  youruser/cloudflare-ddns-webui:latest
```

Open http://localhost:8080 - on first access you will be asked to **create the admin password**.

Initialize on loopback before allowing remote access. Anyone who can reach an uninitialized instance can create its administrator account. Use a token limited to DNS edits in the required zones; the GUI does not need zone deletion or account-wide administration.

> ⚠️ Mount a volume at `/data`. It holds the password hash, the TOTP secret and UI settings. Without it, a container recreate resets the admin account.

## 🚢 Deploy on Dokploy

1. Push this repository to GitHub (or fork it).
2. In Dokploy: **Create Service -> Application**, pick your GitHub repo.
3. Build type: **Dockerfile** (repo root). No build args needed.
4. Set the environment variables (see below): `CLOUDFLARE_API_TOKEN`, `PUBLIC_ORIGIN=https://dns-admin.example.com`, and `SECURE_COOKIES=true`. Replace the synthetic hostname with your restricted administrative hostname. Set `DOMAINS` only if manual DDNS is needed.
5. Add a **volume** mounted at `/data` (Dokploy: *Mounts -> Add Volume*) so your admin account survives redeploys.
6. Restrict the proxy to your administrative network, initialize the account, and attach the trusted hostname. Keep the backend port unreachable from the public network.
7. Verify HTTPS, session-cookie attributes, persistence after redeployment, and rejection of other Host/Origin values. This target deployment still requires owner verification.

A `docker-compose.yml` is also included for reference deployments.

## 🔑 Cloudflare API token preset

Create the token at [My Profile -> API Tokens](https://dash.cloudflare.com/profile/api-tokens):

1. **Create Token** -> use the **Edit zone DNS** template
2. Permissions: `Zone -> Zone -> Read` **and** `Zone -> DNS -> Edit`
3. Zone Resources: **Include -> Specific zone** (least privilege) or **All zones**

## 🛡️ Two-factor authentication & recovery

1. **Settings -> Security -> Enable 2FA**, then enter the current password.
2. Scan the QR code with your authenticator app (Aegis, Bitwarden, 2FAS, Google Authenticator...) and confirm with the 6-digit code
3. **Save the backup codes immediately** - they are issued only once and can be downloaded as a `.txt` file. The same signed-in page retains a recovery-code notice until you choose Done; a full reload or logout clears that display. Each code works exactly once
4. Signing in later accepts either the current TOTP code or one backup code
5. Disabling 2FA requires a valid TOTP (or backup) code; changing the password requires the current password **and** a 2FA code when 2FA is on

If you lose both the authenticator and the backup codes, stop the service and remove remote access before resetting `state.json` in the volume. Restart on loopback and initialize the replacement account before reopening the proxy. Existing invalid state fails startup rather than silently resetting the account.

## ⚙️ Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDFLARE_API_TOKEN` | - | 🔑 API token (required) |
| `CLOUDFLARE_API_TOKEN_FILE` | - | 📄 Path to a file containing the token (Docker secrets) |
| `LISTEN` | `0.0.0.0:8080` | 🌐 Bind address |
| `DATA_DIR` | `/data` | 💾 Persistent state dir (password hash, TOTP secret, UI settings) |
| `SESSION_TTL` | `24h` | ⏳ Session lifetime |
| `SECURE_COOKIES` | `false` | 🔒 `Secure` cookie attribute - enable behind HTTPS |
| `PUBLIC_ORIGIN` | unset | Exact trusted proxy origin, such as `https://dns-admin.example.com`; HTTPS requires `SECURE_COOKIES=true`. Without it, only numeric-IP/localhost Host values on the listening port are accepted. |
| `UPDATE_TIMEOUT` | `30s` | ⏳ Cloudflare API timeout |
| `DOMAINS` | - | 🏠 DDNS domains for the dashboard (same as cloudflare-ddns) |
| `IP4_DOMAINS`, `IP6_DOMAINS` | unset | Additional family-specific domain lists; common `DOMAINS` are included in each enabled family. |
| `GUI_DDNS_CONTRACT` | `standalone-v1` | `shared-v1` also requires an exact ownership filter matching `RECORD_COMMENT`; neither contract observes the updater. |
| `GUI_SHARED_UPDATER_PAUSED` | `false` | Required operator confirmation for `shared-v1`: pause the companion before manual GUI updates. The GUI cannot verify or coordinate the companion. |
| `MANAGED_RECORDS_COMMENT_REGEX` | unset | Restricted to an anchored exact literal (`^...$` with punctuation escaped). Records outside this ownership marker are never updated by DDNS. General regular expressions are unsupported. |
| `REJECT_CLOUDFLARE_IPS` | `true` | Cloudflare addresses are rejected using the recorded range snapshot. Disabling this protection is unsupported. |
| `IP4_PROVIDER` | `ipify` | 🔍 IPv4 detection (`ipify`, `cloudflare.trace`, `url:...`, `literal:...`, `none`) |
| `IP6_PROVIDER` | `cloudflare.trace` | 🔍 IPv6 detection |
| `TTL` | `1` (auto) | ⏱️ TTL applied by on-demand updates |
| `PROXIED` | `false` | ☁️ Proxied flag applied by on-demand updates |
| `RECORD_COMMENT` | - | 💬 Comment applied by on-demand updates |
| `DETECTION_TIMEOUT` | `5s` | ⏳ IP detection timeout |
| `EMOJI` | `true` | 🎨 Emoji in logs |
| `QUIET` | `false` | 🤫 Quiet logs |

Invalid booleans, durations, providers, names and TTLs fail startup. Durations must be positive integer seconds with an optional `s`, `m` or `h` suffix, at most one year. TTL must be `1` or `30..86400`; Cloudflare may require at least 60 seconds for non-Enterprise zones. Proxying forces TTL to `1`.

`literal:` is an explicit operator choice and can contain private addresses; fetched provider responses must be public and match the requested family. Provider redirects are disabled and responses are bounded. Documentation-range responses from loopback URLs are reserved for synthetic tests. `CLOUDFLARE_API_BASE` is a loopback-only testing override.

Scheduling, deletion-on-failure/stop, WAF lists, notification integrations, policy/group/interface providers and unsupported companion configuration are rejected instead of silently ignored. Duplicate DDNS records fail closed and are reported; the GUI does not delete duplicates or reconcile records it does not own. See `SPEC.md` for the upstream comparison and supported contract.

Only one GUI DDNS cycle runs at a time; overlapping requests return `409`. This does not coordinate other processes, the companion or ordinary record edits. After a session expires or is revoked, bulk and DDNS operations stop unsent writes and report partial results; already-sent upstream requests may still finish.

## 🔨 Building from source

```bash
cargo build --locked --release
DATA_DIR=./data ./target/release/cloudflare-ddns-webui
```

The Docker image builds with `./Dockerfile` (multi-stage, musl static, UPX-compressed, `FROM scratch`).

Run the local acceptance checks (including TOTP RFC 6238 vectors, QR structure, backup codes, auth flows and isolated HTTP smoke tests):

```bash
git diff --check
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
node --check web/app.js
node --test web/app.test.cjs
python3 scripts/smoke-test.py
```

### 🧪 Development with a mock Cloudflare API

A mock of the Cloudflare API with synthetic `example.com` records is included so the UI can be developed without a real token. The smoke harness uses temporary state and never loads the local `.env` or `data/`:

```bash
python3 scripts/smoke-test.py --serve
```

For a fixed human-review port, use `python3 scripts/smoke-test.py --serve --port 8888`. The harness prints a synthetic password and stores disposable state outside the repository. This instance never uses the owner's Cloudflare account.

For container changes, build and verify the non-root image:

```bash
docker build -t cloudflare-ddns-webui:test .
python3 scripts/smoke-test.py --container-image cloudflare-ddns-webui:test
```

CI and security workflows are committed configuration. The owner still needs to enable the repository's applicable GitHub security features and require `CI` checks, CodeQL, dependency review, and review approval in branch protection. No automatic merge is configured.

## 🔐 Security notes

- The admin password exists only as a PBKDF2-HMAC-SHA256 hash (100k iterations, per-account salt) in `/data/state.json` (`chmod 600`).
- Backup codes are stored as salted one-way hashes and are consumed on use.
- Sessions are random 256-bit tokens kept in memory only - a restart invalidates all sessions.
- Password failures are limited by source IP. Factor failures share an account-wide five-attempt/five-minute limit across challenges and sensitive operations. Password and factor changes revoke old sessions and pending challenges.
- Every API mutation requires a session cookie **and** a custom header browsers cannot send cross-site.
- Strict Content-Security-Policy (`default-src 'self'`, no inline scripts/styles), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
- Uploaded and legacy stored SVG are rejected. PNG/JPEG/WebP/GIF uploads have MIME, container, byte and dimension checks; compressed pixels are not decoded. Uploaded favicon responses have a sandboxed CSP.
- HTTP requests have absolute read/write deadlines, finite connection admission and bounded framing. BIND imports are limited to 2 MiB with backend preflight validation; malformed or duplicate input fails before an upstream write.
- The HTTP server admits at most 16 connections, with 30-second total request-read and response-write deadlines. Retained request bodies are bounded to 32 MiB across those connections, not total process memory. Route execution and upstream work have separate timeouts. Configure a reverse proxy to use HTTP/1.1 upstream.
- BIND preflight supports the documented record types, default/inherited TTL, omitted owners, escaped names and multiline records, but is not a complete RFC parser. Only `$ORIGIN` and `$TTL` directives are supported. Import responses missing valid counts report an unknown outcome; do not automatically retry an import that may have already reached Cloudflare.
- Security changes persist a private temporary snapshot before replacing in-memory state. Failed saves do not consume recovery codes or grant authentication. Ordinary process-restart behavior is tested; abrupt power-loss durability is not claimed.
- The Cloudflare token never leaves the server; the browser only talks to this app.

## 📄 License

GPL-3.0, like cloudflare-ddns.
