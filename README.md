# 🌍 Cloudflare DDNS Web UI

A web interface for managing Cloudflare DNS, built to sit next to [cloudflare-ddns](https://github.com/timothymiller/cloudflare-ddns).

It is a single static Rust binary in a `FROM scratch` Docker image (2,341,533 bytes when last measured in October 2026). There is no web framework: the HTTP/1.1 server is written by hand on top of Tokio, and the frontend is plain JavaScript and CSS compiled into the binary. The record editor is modelled on the Cloudflare dashboard, and the dashboard page adds DDNS status and an update button for the domains your updater manages.

## ✨ Features

- Zone selector for every zone your API token can see, with search across name, content, comment and tags, a type filter, sortable columns and columns you can hide
- Add and edit A, AAAA, CAA, CNAME, HTTPS, MX, NS, PTR, SRV, SVCB and TXT records, with per-type fields and input validation as you type
- Bulk delete and bulk edit of TTL, proxy status, comments and tags, where comments and tags each have an explicit keep, set or clear choice
- The same proxy and TTL rules as the dashboard: only A, AAAA and CNAME records can be proxied, and proxied records use TTL Auto. The server enforces both
- BIND zone file import and export in Cloudflare's format, including `cf_tags=cf-proxied:true`. Imports are append-only and are checked before anything is sent
- A DDNS dashboard that shows your current IPv4 and IPv6 addresses and whether each domain's records match them, with an Update now button
- One admin account whose password is set in the browser on first run and stored only as a PBKDF2 hash. No password environment variable exists
- TOTP two-factor authentication with QR enrollment and single-use backup codes that you can download as a `.txt` file
- Light, dark and system themes, an accent colour, and your own logo and favicon
- Uses the same `CLOUDFLARE_API_TOKEN` and `DOMAINS` settings as cloudflare-ddns

## Contents

- [Quick start](#-quick-start)
- [How DDNS updates work](#-how-ddns-updates-work)
- [Configuration](#-configuration)
- [Environment variable reference](#-environment-variable-reference)
- [Deployment](#-deployment)
- [Two-factor authentication and recovery](#-two-factor-authentication-and-recovery)
- [Security notes](#-security-notes)
- [Troubleshooting](#-troubleshooting)
- [Development](#-development)

## 🚀 Quick start

### 1. Create an API token

In the Cloudflare dashboard go to [My Profile › API Tokens › Create Token](https://dash.cloudflare.com/profile/api-tokens) and start from the **Edit zone DNS** template, or create a custom token with:

| Permission | Needed for |
|------------|------------|
| Zone › DNS › Edit | Creating, editing, deleting, importing and exporting records |
| Zone › Zone › Read | Listing zones and finding the zone for each domain |

Under **Zone Resources**, include only the zones you want to manage. The GUI never needs zone deletion or account-level permissions.

### 2. Build and run it

No prebuilt image is published, so build it from this repository:

```bash
git clone https://github.com/FilipNone/cloudflare-ddns-webui.git
cd cloudflare-ddns-webui
docker build -t cloudflare-ddns-webui .

docker run -d \
  --name cloudflare-ddns-webui \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v webui-data:/data \
  -e CLOUDFLARE_API_TOKEN=your-api-token \
  cloudflare-ddns-webui
```

Open http://localhost:8080. The first visit asks you to create the admin password.

Set up the account over loopback before you allow remote access: anyone who reaches an uninitialized instance can create the admin account. The `/data` volume holds the password hash, the TOTP secret and the UI settings. Without it, recreating the container resets the account.

### 3. Or use Docker Compose

The included [`docker-compose.yml`](docker-compose.yml) builds the image and publishes it on loopback only:

```yaml
services:
  cloudflare-ddns-webui:
    build: .
    container_name: cloudflare-ddns-webui
    security_opt:
      - no-new-privileges:true
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - webui-data:/data
    environment:
      - CLOUDFLARE_API_TOKEN=your-api-token
      - DOMAINS=example.com,www.example.com
    restart: unless-stopped

volumes:
  webui-data:
```

```bash
docker compose up -d
```

## 🔄 How DDNS updates work

The GUI is not an updater. It has no schedule and does not start, configure or watch cloudflare-ddns. Keep cloudflare-ddns running for automatic updates and use the GUI to check on the result or to push one update by hand.

When you press **Update now**:

1. The GUI detects your public IPv4 and IPv6 addresses with the configured providers. Redirects are not followed, responses are size-limited, and an address must be public and belong to the requested family.
2. Addresses inside Cloudflare's ranges are rejected. The GUI checks them against a list of ranges recorded in the source; it does not download Cloudflare's current list.
3. For each domain, the GUI finds its zone, then creates the missing A or AAAA record or updates the content of the existing one.

Only one update runs at a time. A second request while one is in progress returns `409`. That lock covers the GUI process only; it does not coordinate with cloudflare-ddns, other processes, or ordinary record edits.

### Failure safety

If detection fails, returns a private or wrong-family address, or returns a Cloudflare address, that family is skipped and its records stay as they are. The GUI never deletes records because detection failed.

Duplicate records for a domain make the update fail for that domain. The GUI reports the duplicates and leaves them alone.

If your session expires or is revoked during a bulk edit or an update, writes that have not been sent yet are stopped and the result lists what finished. Requests already sent to Cloudflare can still complete.

## 🧰 Configuration

All settings are environment variables. Invalid values stop the program at startup with an error message instead of being ignored. See [`env-example`](env-example) for a commented template.

### Authentication

| Variable | Description |
|----------|-------------|
| `CLOUDFLARE_API_TOKEN` | API token ([permissions](#1-create-an-api-token)) |
| `CLOUDFLARE_API_TOKEN_FILE` | Path to a file that contains the token, for example a Docker secret |

The admin password is not configured here. You create it in the browser on first run.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN` | `0.0.0.0:8080` | Address and port to listen on |
| `DATA_DIR` | `/data` | Directory for the password hash, TOTP secret and UI settings |
| `SESSION_TTL` | `24h` | Session lifetime |
| `SECURE_COOKIES` | `false` | Adds the `Secure` attribute to the session cookie. Turn it on behind HTTPS |
| `PUBLIC_ORIGIN` | unset | The exact origin a reverse proxy serves, such as `https://dns-admin.example.com`. It must be HTTPS (plain HTTP is allowed only for loopback) and requires `SECURE_COOKIES=true`. When unset, only numeric IP or `localhost` Host values on the listening port are accepted |

### Domains

| Variable | Description |
|----------|-------------|
| `DOMAINS` | Comma-separated domains to show on the dashboard and update with both IPv4 (A) and IPv6 (AAAA) |
| `IP4_DOMAINS` | Comma-separated domains to update with IPv4 only |
| `IP6_DOMAINS` | Comma-separated domains to update with IPv6 only |

These mean the same as in cloudflare-ddns, so you can copy the values across. Record management works without them.

### IP detection providers

| Variable | Default | Description |
|----------|---------|-------------|
| `IP4_PROVIDER` | `ipify` | How to find the public IPv4 address |
| `IP6_PROVIDER` | `cloudflare.trace` | How to find the public IPv6 address |

| Provider | What it does |
|----------|--------------|
| `ipify` | Asks ipify.org |
| `cloudflare.trace` | Reads Cloudflare's `/cdn-cgi/trace` |
| `cloudflare.trace:<url>` | The same, from a trace URL you choose |
| `url:<url>` | Fetches a URL that returns the address as plain text |
| `literal:<ip>` | Uses a fixed address. It may be private, since you chose it on purpose |
| `none` | Disables that family |

Provider URLs must be `http` or `https` and must not contain credentials or a fragment. Interface binding (`ipify@eth1`), the `local` providers, `cloudflare.doh` and detection groups are not supported.

### DNS records

| Variable | Default | Description |
|----------|---------|-------------|
| `TTL` | `1` (Auto) | TTL for records created or updated by Update now. `1` or `30` to `86400`; Cloudflare may require at least 60 outside Enterprise zones |
| `PROXIED` | `false` | Proxy status for records created by Update now. Proxying forces TTL to `1` |
| `RECORD_COMMENT` | unset | Comment for records created or updated by Update now |

### Sharing a zone with cloudflare-ddns

`GUI_DDNS_CONTRACT` sets how careful Update now is about records that cloudflare-ddns also manages:

- `standalone-v1` (default) updates the A and AAAA records of the configured domains.
- `shared-v1` only touches records whose comment matches `MANAGED_RECORDS_COMMENT_REGEX`. That value must be an anchored exact match (`^...$`, with punctuation escaped) and must match `RECORD_COMMENT`. General regular expressions are not supported. This contract also requires `GUI_SHARED_UPDATER_PAUSED=true`, which is your statement that cloudflare-ddns is paused before you press Update now. The GUI cannot check this.

Both contracts were written against cloudflare-ddns 2.3.0 (commit `3f1a722`). Neither one watches the updater.

### Timeouts and output

| Variable | Default | Description |
|----------|---------|-------------|
| `UPDATE_TIMEOUT` | `30s` | Timeout for Cloudflare API requests |
| `DETECTION_TIMEOUT` | `5s` | Timeout for IP detection |
| `EMOJI` | `true` | Emoji in log messages |
| `QUIET` | `false` | Less log output |

### Value formats

Booleans are `true` or `false`. Durations are positive whole seconds with an optional `s`, `m` or `h` suffix (`90`, `30s`, `5m`, `24h`), up to one year.

### Updater settings the GUI rejects

The GUI refuses to start when it sees settings it does not implement, so you never get a silent mismatch. Rejected names are `UPDATE_CRON`, `UPDATE_ON_START`, `DELETE_ON_STOP`, `DELETE_ON_FAILURE`, `WAF_LISTS`, `WAF_LIST_DESCRIPTION`, `WAF_LIST_ITEM_COMMENT`, `MANAGED_WAF_LIST_ITEMS_COMMENT_REGEX`, `SHOUTRRR`, `HEALTHCHECKS`, `UPTIMEKUMA`, `CONFIG_PATH`, `CF_API_TOKEN`, `CF_API_TOKEN_FILE`, `CF_ACCOUNT_ID`, `IP4_POLICY`, `IP6_POLICY`, `PUID`, `PGID`, anything starting with `CF_DDNS_`, and numbered group settings such as `DOMAINS_2` or `IP4_PROVIDER_2`. `REJECT_CLOUDFLARE_IPS=false` is rejected as well.

Give the GUI its own environment rather than reusing the updater's env file.

## 📋 Environment variable reference

| Variable | Default | Section |
|----------|---------|---------|
| `CLOUDFLARE_API_TOKEN` | required | [Authentication](#authentication) |
| `CLOUDFLARE_API_TOKEN_FILE` | unset | [Authentication](#authentication) |
| `LISTEN` | `0.0.0.0:8080` | [Server](#server) |
| `DATA_DIR` | `/data` | [Server](#server) |
| `SESSION_TTL` | `24h` | [Server](#server) |
| `SECURE_COOKIES` | `false` | [Server](#server) |
| `PUBLIC_ORIGIN` | unset | [Server](#server) |
| `DOMAINS` | unset | [Domains](#domains) |
| `IP4_DOMAINS` | unset | [Domains](#domains) |
| `IP6_DOMAINS` | unset | [Domains](#domains) |
| `IP4_PROVIDER` | `ipify` | [IP detection providers](#ip-detection-providers) |
| `IP6_PROVIDER` | `cloudflare.trace` | [IP detection providers](#ip-detection-providers) |
| `REJECT_CLOUDFLARE_IPS` | `true` | [How DDNS updates work](#-how-ddns-updates-work) (cannot be disabled) |
| `TTL` | `1` | [DNS records](#dns-records) |
| `PROXIED` | `false` | [DNS records](#dns-records) |
| `RECORD_COMMENT` | unset | [DNS records](#dns-records) |
| `GUI_DDNS_CONTRACT` | `standalone-v1` | [Sharing a zone](#sharing-a-zone-with-cloudflare-ddns) |
| `MANAGED_RECORDS_COMMENT_REGEX` | unset | [Sharing a zone](#sharing-a-zone-with-cloudflare-ddns) |
| `GUI_SHARED_UPDATER_PAUSED` | `false` | [Sharing a zone](#sharing-a-zone-with-cloudflare-ddns) |
| `UPDATE_TIMEOUT` | `30s` | [Timeouts and output](#timeouts-and-output) |
| `DETECTION_TIMEOUT` | `5s` | [Timeouts and output](#timeouts-and-output) |
| `EMOJI` | `true` | [Timeouts and output](#timeouts-and-output) |
| `QUIET` | `false` | [Timeouts and output](#timeouts-and-output) |

`CLOUDFLARE_API_BASE` exists for tests against the local mock and only accepts loopback addresses.

## 🚢 Deployment

The supported setup is a private admin network, or loopback behind an HTTPS reverse proxy. The GUI is not hardened for direct exposure to the public internet.

### Behind a reverse proxy

1. Publish the container on loopback or on a network only the proxy can reach.
2. Set `PUBLIC_ORIGIN` to the exact HTTPS origin and `SECURE_COOKIES=true`.
3. Have the proxy talk HTTP/1.1 to the GUI.
4. Create the admin account before opening the proxy to anyone else.
5. Check that HTTPS works, that the session cookie is `Secure`, that the account survives a restart, and that requests with any other Host or Origin get `403`.

### Dokploy

1. Fork this repository or push it to your own GitHub account.
2. In Dokploy, choose **Create Service › Application** and pick the repository.
3. Set the build type to **Dockerfile** at the repository root. No build arguments are needed.
4. Set `CLOUDFLARE_API_TOKEN`, `PUBLIC_ORIGIN=https://dns-admin.example.com` (with your own hostname) and `SECURE_COOKIES=true`. Add `DOMAINS` only if you want the DDNS dashboard.
5. Under **Mounts › Add Volume**, mount a volume at `/data` so the admin account survives redeploys.
6. Restrict the domain to your admin network, create the account, then attach the hostname. Keep the container port unreachable from the public network.

### Build from source

```bash
cargo build --locked --release     # binary: target/release/cloudflare-ddns-webui
DATA_DIR=./data ./target/release/cloudflare-ddns-webui
docker build -t cloudflare-ddns-webui .
```

The Dockerfile builds a static musl binary, compresses it with UPX and copies it into a `FROM scratch` image that runs as UID/GID 65534 with a writable `/data`.

## 🛡️ Two-factor authentication and recovery

1. Go to **Settings › Security › Enable 2FA** and enter your current password.
2. Scan the QR code with an authenticator app (Aegis, Bitwarden, 2FAS, Google Authenticator and others) and confirm with a 6-digit code.
3. Save the backup codes right away. They are shown once, can be downloaded as a `.txt` file, and each one works once. The page keeps showing them until you press Done; reloading the page or logging out clears them.
4. Later logins accept either the current TOTP code or one backup code.
5. Disabling 2FA needs a valid TOTP or backup code. Changing the password needs the current password, plus a 2FA code when 2FA is on.

If you lose both the authenticator and the backup codes, stop the service and remove remote access. Then delete `state.json` from the data volume, start the GUI on loopback, and create the new account before reopening the proxy. If `state.json` is present but unreadable or invalid, the GUI refuses to start instead of resetting the account.

## 🔒 Security notes

- The admin password is stored only as a PBKDF2-HMAC-SHA256 hash (100,000 iterations, per-account salt) in `state.json` with mode `600`. Backup codes are stored as salted one-way hashes and are consumed when used.
- Sessions are random 256-bit tokens kept in memory, so a restart logs everyone out. Changing the password or 2FA revokes existing sessions and pending login challenges.
- Failed passwords are rate-limited per source IP. Failed 2FA codes share one account-wide limit of five attempts per five minutes across logins and sensitive actions. These counters reset when the process restarts.
- Every write needs both the session cookie and a custom header that browsers will not send cross-site.
- Responses carry a strict Content-Security-Policy (`default-src 'self'`, no inline scripts or styles), `X-Frame-Options: DENY`, `nosniff` and `no-referrer`.
- Logo and favicon uploads accept PNG, JPEG, WebP and GIF only, with checks on type, container format, size and dimensions. SVG is rejected. The image data itself is not decoded.
- The HTTP server accepts at most 16 connections, limits request bodies to 2 MiB, and gives each request 30 seconds to arrive and 30 seconds to be answered.
- The BIND import check supports the documented record types, `$ORIGIN` and `$TTL`, default and inherited TTLs, omitted owners, escaped names and multi-line records. It is not a complete RFC parser. If Cloudflare's reply to an import is missing its counts, the result is reported as unknown; check the zone before you retry, because the import may already have gone through.
- State changes are written to a private temporary file, synced and renamed before the in-memory state changes. A failed save does not consume a backup code or log you in. Durability after a power loss is not guaranteed, because the parent directory is not synced.
- The Cloudflare token stays on the server. The browser only talks to the GUI.

## 🩺 Troubleshooting

### "... is unsupported by the GUI DDNS v1 contract"

The GUI found one of the [updater settings it rejects](#updater-settings-the-gui-rejects), usually because it was given the updater's env file. Remove the setting from the GUI's environment.

### "untrusted Host or Origin"

The request came through a hostname the GUI does not trust. Set `PUBLIC_ORIGIN` to the exact origin your proxy serves, including the scheme and any non-default port. Without it, only numeric IP and `localhost` addresses work.

### The admin account is gone after an update

The container was recreated without a volume at `/data`. Mount one, then create the account again over loopback.

### "Permission denied" writing to `/data`

The image runs as UID 65534. A bind-mounted directory must be writable by that user, or start the container with `--user` set to the directory owner's UID and GID.

### Update now skips IPv6

Docker's default bridge network has no IPv6, so `cloudflare.trace` cannot reach Cloudflare over IPv6. Run the container with host networking, or set `IP6_PROVIDER=none` if you do not need AAAA records.

### "no matching Cloudflare zone"

The token cannot see the zone for that domain. Add **Zone › Zone › Read** and include the zone under **Zone Resources**.

## 🧪 Development

[`scripts/mock-cloudflare-api.py`](scripts/mock-cloudflare-api.py) mocks the Cloudflare API with a synthetic `example.com` zone, so you can work on the UI without a real token. The smoke harness starts the GUI against it with temporary state and never reads the local `.env` or `data/`:

```bash
cargo build --locked --release
python3 scripts/smoke-test.py --serve              # disposable instance on a random loopback port
python3 scripts/smoke-test.py --serve --port 8888  # fixed port
```

The harness prints a synthetic password for the instance.

Checks to run before opening a PR:

```bash
git diff --check
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
node --check web/app.js
node --test web/app.test.cjs web/appearance.test.cjs
python3 scripts/smoke-test.py
```

For container changes, also run `docker build -t cloudflare-ddns-webui:test .` and `python3 scripts/smoke-test.py --container-image cloudflare-ddns-webui:test`.

Contributors and AI agents should read [AGENTS.md](AGENTS.md) first.

## 🔗 Helpful links

- [cloudflare-ddns](https://github.com/timothymiller/cloudflare-ddns), the updater this GUI is built to sit beside
- [Cloudflare API tokens](https://dash.cloudflare.com/profile/api-tokens) ([how to create one](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/))
- [Cloudflare IP ranges](https://www.cloudflare.com/ips/)

## 📜 License

This project is licensed under the GNU General Public License, version 3 (GPLv3).