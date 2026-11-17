<p align="center"><img width="200" src="web/favicon.svg" alt="Cloudflare DDNS Web UI logo"/></p>

# 🌍 Cloudflare DDNS Web UI

Edit your Cloudflare DNS records and check on your dynamic DNS from a page you host yourself.

A web interface for Cloudflare DNS, written in Rust: one static binary in a `FROM scratch` Docker image of about 2.4 MB, with the frontend compiled in. The record editor follows the Cloudflare dashboard, and the DDNS page shows whether the domains [cloudflare-ddns](https://github.com/timothymiller/cloudflare-ddns) manages point at your current IP address, with a button to update them now.

## ✨ Features

- Every zone your API token can see, with search, a type filter, sortable columns and columns you can hide
- Add and edit A, AAAA, CAA, CNAME, HTTPS, MX, NS, PTR, SRV, SVCB and TXT records, with fields and checks for each type
- Bulk delete, and bulk edit of TTL, proxy status, comments and tags through Cloudflare's batch endpoint
- The dashboard's proxy rules, enforced by the server: only A, AAAA and CNAME records can be proxied, and proxied records use TTL Auto
- BIND zone file export, and append-only import that is checked before anything is sent
- A DDNS page with your current IPv4 and IPv6 addresses, whether each domain's record matches, and an Update now button
- One admin account with TOTP two-factor login and single-use backup codes
- Light, dark and system themes, an accent colour, and your own logo
- The same `CLOUDFLARE_API_TOKEN` and `DOMAINS` settings as cloudflare-ddns

## Contents

- [Quick start](#-quick-start)
- [How it works](#-how-it-works)
- [Configuration](#-configuration)
- [Environment variable reference](#-environment-variable-reference)
- [Deployment](#-deployment)
- [Two-factor authentication](#-two-factor-authentication)
- [Security notes](#-security-notes)
- [Troubleshooting](#-troubleshooting)
- [Development](#-development)

## 🚀 Quick start

### 1. Create an API token

In the Cloudflare dashboard go to [**My Profile › API Tokens › Create Token**](https://dash.cloudflare.com/profile/api-tokens) and start from the **Edit zone DNS** template, or grant:

| Permission | Needed for |
|------------|------------|
| **Zone › DNS › Edit** | Reading, changing, importing and exporting records |
| **Zone › Zone › Read** | Listing zones and finding each domain's zone |

Under **Zone Resources**, include only the zones you want to manage.

### 2. Run it

No image is published, so build it from this repository:

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

Open http://localhost:8080 and create the admin password. Do this over loopback before you allow remote access, because anyone who reaches a new instance can create the account. The `/data` volume keeps the account; without it, recreating the container resets it.

### 3. Or use Docker Compose

The included [`docker-compose.yml`](docker-compose.yml) builds the image and publishes it on loopback only. Uncomment the settings you need, such as `DOMAINS`:

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

## 🔄 How it works

The GUI has no schedule, and it does not start, configure or watch cloudflare-ddns. Keep cloudflare-ddns running for automatic updates and use the GUI to check the result or push one update by hand.

When you press **Update now**:

1. Detect the public IPv4 and IPv6 addresses with the configured providers. Redirects are not followed, replies are size-limited, and an address must be public and of the right family.
2. Reject Cloudflare IPs. Addresses inside Cloudflare's ranges are discarded, using a list built into the binary.
3. Update each domain that has an address: find its zone, then create the A or AAAA record, or update the address, TTL, proxy status and comment of the existing one.

Only one update runs at a time, and a second request gets `409`. That lock does not coordinate with cloudflare-ddns or with record edits.

### Failure safety

A failed IP lookup never changes your DNS.

- A detection that fails or returns a private, wrong-family or Cloudflare address skips that family, and its records stay as they are.
- Duplicate records, or two zones with the same name, fail that domain without changing anything. The GUI leaves the duplicates alone.
- Bulk edits go to Cloudflare in groups of up to 200 records, the Free plan limit. Cloudflare applies a group completely or not at all, so one failing record fails its whole group. If the reply is lost or does not list the records sent, the result says the outcome is unknown; reload the records before you retry.
- If your session ends during an update or a bulk edit, writes that have not been sent are stopped, and the result lists what finished.

## 🧰 Configuration

All settings are environment variables, and [`.env.example`](.env.example) is a commented template. Invalid values stop the program at startup with an error message.

### Authentication

| Variable | Description |
|----------|-------------|
| `CLOUDFLARE_API_TOKEN` | API token ([permissions](#1-create-an-api-token)) |
| `CLOUDFLARE_API_TOKEN_FILE` | File holding the token, such as a Docker secret. Read only when `CLOUDFLARE_API_TOKEN` is unset; at most 4 KiB |

There is no password setting. You create the password in the browser on first run.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN` | `0.0.0.0:8080` | Address and port to listen on |
| `DATA_DIR` | `/data` | Where the account and UI settings are saved |
| `SESSION_TTL` | `24h` | Session lifetime |
| `SECURE_COOKIES` | `false` | Marks the session cookie `Secure` and names it `__Host-cfddns_session`. Turn it on behind HTTPS |
| `PUBLIC_ORIGIN` | unset | The exact origin your reverse proxy serves, such as `https://dns-admin.example.com`. It must be HTTPS (HTTP only on loopback) and needs `SECURE_COOKIES=true`; an HTTPS origin also turns on HSTS. When unset, only IP addresses and `localhost` are accepted as the host |

### Domains

| Variable | Description |
|----------|-------------|
| `DOMAINS` | Domains to show on the DDNS page and update with A and AAAA records |
| `IP4_DOMAINS` | Domains for A records only |
| `IP6_DOMAINS` | Domains for AAAA records only |

The lists are comma-separated and mean the same as in cloudflare-ddns, so you can copy the values across. Record editing works without them.

### IP detection providers

| Variable | Default | Description |
|----------|---------|-------------|
| `IP4_PROVIDER` | `ipify` | How to detect the IPv4 address |
| `IP6_PROVIDER` | `cloudflare.trace` | How to detect the IPv6 address |

| Provider | Description |
|----------|-------------|
| `ipify` | Asks ipify.org |
| `cloudflare.trace` | Reads Cloudflare's `/cdn-cgi/trace` |
| `cloudflare.trace:<url>` | The same, from your own trace URL |
| `url:<url>` | Any `http` or `https` URL that returns the address as plain text |
| `literal:<ip>` | A fixed address, which may be private because you chose it |
| `none` | Don't detect this family |

URLs must not contain credentials or a fragment. Interface binding (`ipify@eth1`), the `local` providers, `cloudflare.doh` and detection groups are not supported.

### DNS records

| Variable | Default | Description |
|----------|---------|-------------|
| `TTL` | `1` (Auto) | TTL for records written by Update now: `1`, or `30` to `86400`. Cloudflare may require at least 60 outside Enterprise zones |
| `PROXIED` | `false` | Proxy status for records created by Update now. Proxied records use TTL `1` |
| `RECORD_COMMENT` | unset | Comment for records written by Update now. At most 500 bytes; Free zones allow 100 characters |
| `GUI_DDNS_CONTRACT` | `standalone-v1` | How Update now treats records that cloudflare-ddns also manages |

With `standalone-v1`, Update now updates the A and AAAA records of the configured domains. With `shared-v1`, it only touches records whose comment matches `MANAGED_RECORDS_COMMENT_REGEX`. That value must be an anchored exact match (`^...$`, punctuation escaped) that also matches `RECORD_COMMENT`, and the contract needs `GUI_SHARED_UPDATER_PAUSED=true` to say that you paused cloudflare-ddns before pressing Update now. The GUI cannot check that. Both contracts were written against cloudflare-ddns 2.3.0 (commit `3f1a722`).

### Timeouts and output

| Variable | Default | Description |
|----------|---------|-------------|
| `UPDATE_TIMEOUT` | `30s` | Timeout for each Cloudflare API request |
| `DETECTION_TIMEOUT` | `5s` | Timeout for IP detection |
| `EMOJI` | `true` | Emoji in log output |
| `QUIET` | `false` | Less log output |

### Value formats

- Booleans: `true`, `yes` or `1`, and `false`, `no` or `0`, in any case. Anything else stops startup.
- Durations: whole seconds with an optional `s`, `m` or `h` suffix (`90`, `30s`, `5m`, `24h`), from 1 second to 365 days.
- Empty values: a variable set to an empty string counts as unset, so the default applies.

### Updater settings the GUI rejects

The GUI refuses to start when it finds a cloudflare-ddns setting it does not implement, even with an empty value: `UPDATE_CRON`, `UPDATE_ON_START`, `DELETE_ON_STOP`, `DELETE_ON_FAILURE`, `WAF_LISTS`, `WAF_LIST_DESCRIPTION`, `WAF_LIST_ITEM_COMMENT`, `MANAGED_WAF_LIST_ITEMS_COMMENT_REGEX`, `SHOUTRRR`, `HEALTHCHECKS`, `UPTIMEKUMA`, `CONFIG_PATH`, `CF_API_TOKEN`, `CF_API_TOKEN_FILE`, `CF_ACCOUNT_ID`, `IP4_POLICY`, `IP6_POLICY`, `PUID`, `PGID`, names starting with `CF_DDNS_`, numbered groups such as `DOMAINS_2`, and `REJECT_CLOUDFLARE_IPS=false`. Give the GUI its own environment instead of the updater's env file.

## 📋 Environment variable reference

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDFLARE_API_TOKEN` | required | API token, or use the file below |
| `CLOUDFLARE_API_TOKEN_FILE` | unset | File holding the API token |
| `LISTEN` | `0.0.0.0:8080` | Listen address |
| `DATA_DIR` | `/data` | Data directory |
| `SESSION_TTL` | `24h` | Session lifetime |
| `SECURE_COOKIES` | `false` | `Secure`, `__Host-` session cookie |
| `PUBLIC_ORIGIN` | unset | Origin your reverse proxy serves |
| `DOMAINS` | unset | Domains for A and AAAA records |
| `IP4_DOMAINS` | unset | Domains for A records only |
| `IP6_DOMAINS` | unset | Domains for AAAA records only |
| `IP4_PROVIDER` | `ipify` | IPv4 detection provider |
| `IP6_PROVIDER` | `cloudflare.trace` | IPv6 detection provider |
| `REJECT_CLOUDFLARE_IPS` | `true` | Discard detected Cloudflare IPs; `false` is rejected |
| `TTL` | `1` | TTL for Update now |
| `PROXIED` | `false` | Proxy status for Update now |
| `RECORD_COMMENT` | unset | Comment for Update now |
| `GUI_DDNS_CONTRACT` | `standalone-v1` | `standalone-v1` or `shared-v1` |
| `MANAGED_RECORDS_COMMENT_REGEX` | unset | Comment match for `shared-v1` |
| `GUI_SHARED_UPDATER_PAUSED` | `false` | Confirms the updater is paused, for `shared-v1` |
| `UPDATE_TIMEOUT` | `30s` | Cloudflare API timeout |
| `DETECTION_TIMEOUT` | `5s` | IP detection timeout |
| `EMOJI` | `true` | Emoji in output |
| `QUIET` | `false` | Less output |

`CLOUDFLARE_API_BASE` is only for tests against the local mock and accepts loopback addresses only.

## 🚢 Deployment

Run the GUI on a private admin network, or on loopback behind an HTTPS reverse proxy. It is not hardened for direct exposure to the internet.

### Behind a reverse proxy

1. Publish the container on loopback or on a network only the proxy can reach.
2. Set `PUBLIC_ORIGIN` to the exact HTTPS origin, and `SECURE_COOKIES=true`.
3. Talk HTTP/1.1 to the GUI; nginx older than 1.29.7 needs `proxy_http_version 1.1`. The GUI closes idle connections after 5 seconds, so set the proxy's upstream idle timeout lower (nginx `keepalive_timeout` in the `upstream` block, Traefik `idleConnTimeout`).
4. Create the admin account before anyone else can reach the proxy.
5. Check that the session cookie is `__Host-cfddns_session` and `Secure`, that the account survives a restart, and that other Host or Origin values get `403`.

### Dokploy

1. Push this repository to your own GitHub account. In Dokploy, choose **Create Service › Application** and pick it.
2. Set the build type to **Dockerfile** at the repository root.
3. Set `CLOUDFLARE_API_TOKEN`, `PUBLIC_ORIGIN` with your hostname and `SECURE_COOKIES=true`. Add `DOMAINS` if you want the DDNS page.
4. Under **Mounts › Add Volume**, mount a volume at `/data`.
5. Restrict the domain to your admin network, create the account, then attach the hostname. Keep the container port off the public network.

### Build from source

```bash
cargo build --locked --release     # binary: target/release/cloudflare-ddns-webui
DATA_DIR=./data ./target/release/cloudflare-ddns-webui
```

The Dockerfile builds a static musl binary, compresses it with UPX and runs it in a `FROM scratch` image as UID/GID 65534. On SIGTERM (`docker stop`) or SIGINT (Ctrl+C) the GUI stops accepting connections, gives requests in progress up to 5 seconds and exits with status 0, inside Docker's 10-second stop timeout.

## 🛡️ Two-factor authentication

1. Go to **Settings › Security › Enable 2FA**, enter your password, scan the QR code with an authenticator app and confirm with a 6-digit code.
2. Save the backup codes. They are shown once, can be downloaded as a `.txt` file, and each one works once.
3. Logins then need the current TOTP code or one backup code. Each TOTP code works once, so right after logging in, wait for the next code before disabling 2FA or changing the password.

Disabling 2FA needs a code, and changing the password needs the current password plus a code.

If you lose both the authenticator and the backup codes, stop the service and remove remote access. Delete `state.json` from the data volume, then create a new account over loopback. If `state.json` is present but unreadable or invalid, the GUI refuses to start instead of resetting the account.

## 🔒 Security notes

- The password is stored in `state.json` (mode `600`) as a PBKDF2-HMAC-SHA256 hash with 600,000 iterations. Hashes from older versions use 100,000 and are upgraded at your next login. Older versions then reject the password, so keep a copy of `state.json` before upgrading if you might roll back; restoring it also undoes later password and 2FA changes.
- Backup codes are stored as salted PBKDF2 hashes with 100,000 iterations and removed when used. Codes from older versions have no salt of their own; while any are left, the GUI logs a warning at startup, and disabling and re-enabling 2FA replaces them.
- Sessions are random 256-bit tokens kept in memory, so a restart logs everyone out. Changing the password or 2FA signs out existing sessions.
- Failed passwords are limited per IP address, or per /64 for IPv6. Behind a reverse proxy every client shares the proxy's address and its limit. Failed 2FA codes share one account-wide limit of five per five minutes. Both counters reset on restart.
- Every write needs the session cookie and a header that browsers won't send cross-site. Request bodies with unknown fields are rejected.
- Responses carry a strict Content-Security-Policy with no inline scripts or styles, plus anti-framing, `nosniff`, `no-referrer`, COOP, CORP and `Permissions-Policy` headers. An HTTPS `PUBLIC_ORIGIN` adds HSTS.
- Logo uploads accept PNG, JPEG, WebP and GIF after checks on format, size and dimensions. SVG is rejected.
- The server keeps at most 16 connections and answers more with `503`. Request bodies are capped at 2 MiB, each request and each response gets 30 seconds, and idle connections close after 5 seconds. It speaks HTTP/1.1 only and rejects absolute-form targets, which RFC 9112 §3.2.2 says a server must accept.
- The BIND import check handles the supported record types, `$ORIGIN`, `$TTL` and multi-line records, but it is not a full RFC parser. If Cloudflare's import reply lacks its counts, the result is reported as unknown; check the zone before you retry.
- Changes are written to a private temporary file, synced and renamed into place before the GUI's state changes, so a failed save never applies a password or 2FA change or uses up a backup code. An invalid `ui-settings.json` is renamed to `ui-settings.json.invalid` and the default appearance is used; an unreadable one stops startup.
- The Cloudflare token stays on the server. The browser only talks to the GUI.

## 🩺 Troubleshooting

### "... is unsupported by the GUI DDNS v1 contract"

The GUI found a [setting it rejects](#updater-settings-the-gui-rejects), usually from the updater's env file. Remove it from the GUI's environment.

### "untrusted Host or Origin"

Set `PUBLIC_ORIGIN` to the exact origin your proxy serves, with the scheme and any non-default port. Without it, only IP addresses and `localhost` work.

### The admin account is gone after an update

The container was recreated without a volume at `/data`. Mount one, then create the account again over loopback.

### "Permission denied" writing to `/data`

The image runs as UID 65534. Make the bind-mounted directory writable by that user, or start the container with `--user` set to the directory owner's UID and GID.

### "cannot load UI settings"

The GUI cannot read `ui-settings.json` or the icon file it names. Fix the permissions, or move the file out of the data directory to start with the default appearance.

### Update now skips IPv6

Docker's default bridge network has no IPv6, so `cloudflare.trace` cannot reach Cloudflare over IPv6. Use host networking, or set `IP6_PROVIDER=none` if you don't need AAAA records.

### "no matching Cloudflare zone"

The token cannot see the zone. Add **Zone › Zone › Read** and include the zone under **Zone Resources**.

## 🧪 Development

[`scripts/mock-cloudflare-api.py`](scripts/mock-cloudflare-api.py) mocks the Cloudflare API with three synthetic zones: `acme.example` (a business), `homelab.example` (self-hosting, where the smoke test runs DDNS) and `rossi.example` (personal use). The smoke harness runs the GUI against it with temporary state and never reads `.env` or `data/`:

```bash
cargo build --locked --release
python3 scripts/smoke-test.py --serve --port 8888   # disposable instance on loopback
python3 scripts/smoke-test.py                        # full smoke test
```

Log in to the disposable instance with the `PASSWORD` constant from `scripts/smoke-test.py`. Its public IP changes every minute, so you can try Update now. Contributors and AI agents should read [AGENTS.md](AGENTS.md) first; it lists every check to run before a PR.

## 🔗 Helpful links

- [cloudflare-ddns](https://github.com/timothymiller/cloudflare-ddns), the updater this GUI sits beside
- [Cloudflare API tokens](https://dash.cloudflare.com/profile/api-tokens) ([how to create one](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/))
- [Cloudflare IP ranges](https://www.cloudflare.com/ips/)

## 📜 License

This project is licensed under the GNU General Public License, version 3 (GPLv3).

## 👨‍💻 Author

FilipNone

[View my GitHub profile 💡](https://github.com/FilipNone)
