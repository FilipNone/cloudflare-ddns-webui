# AGENTS.md: guide for AI agents and contributors

Cloudflare DDNS Web UI (`FilipNone/cloudflare-ddns-webui`) is a small self-hosted admin page for Cloudflare DNS. It manages zones and records and runs on-demand DDNS updates for the same domains that [timothymiller/cloudflare-ddns](https://github.com/timothymiller/cloudflare-ddns) keeps up to date. It follows the same approach as that project: one static Rust binary, few crates, settings in environment variables, and a `FROM scratch` container. The backend is Rust with a hand-written HTTP/1.1 server on Tokio. The frontend in `web/` is vanilla JavaScript, HTML and CSS embedded into the binary at compile time. It has no package manager, framework or build step, and must stay that way.

The GUI talks to Cloudflare directly. It does not start, configure, schedule or watch the companion updater. Read this file first, then `README.md`.

## Owner rules

- Use only `165696124+FilipNone@users.noreply.github.com` for author or committer email. Never print or publish another owner email. Do not change global Git configuration.
- Do not read or copy `.env`, `data/`, tokens, account state, or local DNS exports into logs, tests, documentation, commits, or PRs. Use synthetic fixtures and mock credentials.
- Preserve existing comments unless the repair needs to change them.
- Before every PR, load the `humanizer` skill and rewrite comments added by that PR. Keep their technical meaning; leave unrelated old comments alone. If the skill is unavailable, report that the PR preparation is blocked.
- Commit, push, open a PR, deploy, and merge only when explicitly requested. A human approves the merge.
- Never add AI co-author trailers or attribution lines to commits or PRs. Keep one fix per commit.

## 1. Orientation

| Read | Why |
|---|---|
| `README.md` | Features, configuration, the DDNS contract, deployment and security limits. Keep it accurate when behaviour changes. |
| `env-example`, `docker-compose.yml`, `Dockerfile` | Supported settings and the container layout |
| `docs/Cloudflare DDNS/` | Local copy of the upstream updater, for comparison only (section 7) |
| `docs/GUI riferimento/` | Saved Cloudflare dashboard pages used as the design reference (section 8) |
| `.github/workflows/` | What CI runs on every PR |

Both folders under `docs/` are ignored by Git. They are reference material, not dependencies. Do not edit them, vendor them, or commit them.

## 2. Source map

```text
src/
  main.rs        startup: load config, open auth state, start the listener
  http.rs        HTTP/1.1 parsing, framing, connection admission and deadlines
  routes.rs      API routes: authentication checks, Host/Origin checks, input validation, CSP headers
  auth.rs        admin identity, sessions, PBKDF2 password hashes, recovery codes, lockouts, state persistence
  totp.rs        RFC 6238 TOTP
  cloudflare.rs  Cloudflare API requests and response types
  bind.rs        BIND zone file preflight for imports
  ddns.rs        IP detection, DNS status, manual DDNS updates
  config.rs      environment parsing and rejection of unsupported updater settings
  customize.rs   UI settings and uploaded logo/favicon checks
  pp.rs          log output with optional emoji and quiet mode
web/
  index.html app.js style.css favicon.svg   the embedded frontend
  app.test.cjs appearance.test.cjs          Node test suites for the frontend
scripts/
  mock-cloudflare-api.py   local Cloudflare API mock with the synthetic example.com zone
  smoke-test.py            end-to-end smoke harness (temporary state, loopback, mock token)
```

## 3. Golden rules

### Never crash

The release profile sets `panic = "abort"`, so one panic stops the server for every user. Malformed requests, bad config, odd Cloudflare responses, corrupt state files and full disks must produce an error the operator can act on.

- Non-test code must not add new `unwrap()`, `expect()`, `panic!`, `unreachable!` or `todo!` calls. Some older call sites remain; remove them when you work on that code.
- Treat lengths, offsets and numbers from requests, uploads, zone files and Cloudflare responses as hostile. Use `get()`, checked or saturating arithmetic, and size caps before allocating.
- A crash fix comes with a small synthetic regression test that failed before the fix.

### Security

- Every DNS route requires a session. Every write also requires the mutation header that browsers cannot send cross-site.
- Tokens, passwords, recovery codes and TOTP secrets never appear in logs or API responses. The only exception is the one-time enrollment and recovery display.
- Persist password and 2FA changes before reporting success. If existing identity state is unreadable or invalid, startup fails; it must never fall back to first-run setup.
- Keep the strict CSP. Do not add inline scripts, inline styles or third-party assets to `web/`.
- Authentication changes need restart and persistence tests, plus failure-path tests.

### DDNS safety

- Parse detected addresses and check the address family before any DNS write. A failed or wrong-family detection leaves existing records untouched.
- Report provider and API errors as failures. Never show a failed or partial update as a success.
- Keep proxy and TTL rules the same in the backend and frontend: proxied records use TTL 1 (Auto), and only A, AAAA and CNAME records can be proxied.
- After a session is revoked, multi-record operations stop unsent writes and report partial results.
- Duplicate DDNS records fail closed. The GUI does not delete or reconcile records it does not own.
- DDNS changes need address-family tests and proof that detection failures preserve DNS records.

### Scope

- Do not claim daemon integration or full upstream environment compatibility unless you implement and test a contract for it. Settings the GUI does not support are rejected at startup (see `unsupported_setting` in `src/config.rs`); keep it that way.
- Keep the dependency list short. Add a crate only when the standard library or an existing dependency cannot do the job, and say why in the PR. Do not upgrade dependencies as part of an unrelated fix.
- Tests run against `scripts/mock-cloudflare-api.py` and the synthetic `example.com` zone. Never test against the owner's account or real DNS records.

## 4. Picking work

1. Start from the owner's request or an open GitHub issue. Pick one bounded task with acceptance criteria you can observe.
2. Run `git status --short` and keep changes you did not make, including lockfile edits.
3. Add a regression test that fails before the repair.
4. Make the smallest repair. Avoid unrelated rewrites.
5. Run the checks in section 5. Write down failures and anything you could not test instead of calling the task done.
6. Have an independent reviewer read the diff with fresh context. Fix actionable findings and rerun the checks.
7. Put the evidence (checks run, manual checks, known gaps) in the PR description. Prepare a PR only when asked, humanize its new comments, and wait for CI on its latest commit.
8. The owner verifies the target environment and decides whether to merge. Never auto-merge or resolve unverified feedback.

## 5. Before you finish a task

```sh
git diff --check
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
node --check web/app.js
node --test web/app.test.cjs web/appearance.test.cjs
python3 scripts/smoke-test.py
```

Build the release binary before the smoke test. `python3 scripts/smoke-test.py --only <group>` runs one group while you iterate, and `--serve` starts a disposable instance on loopback for manual checks (add `--port 8888` for a fixed port). CI currently runs `web/app.test.cjs` only, so run the appearance suite yourself.

For container changes, also run:

```sh
docker build -t cloudflare-ddns-webui:test .
python3 scripts/smoke-test.py --container-image cloudflare-ddns-webui:test
```

Check that the non-root container (UID/GID 65534) can write `/data` and that no build output ends up there.

For visible changes, check the affected flow in a browser at desktop (1440x900) and mobile (390x844) sizes against the `--serve` instance.

Toolchain: Rust 1.99.1 with rustfmt and Clippy (pinned in `rust-toolchain.toml` and the Dockerfile), Node.js 24 or newer, Python 3.12 or newer (standard library only), and Docker for image checks. Builds and tests use `--locked`. Do not regenerate `Cargo.lock` to get past a failed build.

## 6. Parallel agents

- Use your own target directory (`CARGO_TARGET_DIR=target/agent-<name>`) to avoid the Cargo build lock. Delete it when you finish.
- Give each `--serve` instance its own `--port`.
- Edit only the files your task owns. `src/routes.rs` and `web/app.js` are large shared files; make small edits and re-read them before each edit.
- If someone else's unfinished edit breaks the build, wait and retry. Do not fix their files.

## 7. Upstream reference

`docs/Cloudflare DDNS/` is a local copy of `timothymiller/cloudflare-ddns`. It has no Git history of its own, so check provenance before relying on it.

- On 2026-11-03 the copy matched upstream `master` at commit `1cd73f0c523deba2b87d98210c43ed172debb27d` (Cargo version 2.3.1), apart from the missing `.github/` folder.
- The GUI DDNS contracts (`standalone-v1` and `shared-v1`, described in `README.md`) were defined against commit `3f1a7220645a3f56eac94a6975b167bfd0f4ac5e` (version 2.3.0), inspected on 2026-10-12. Changes in upstream after that commit have not been reviewed against the contract.

When a task depends on upstream behaviour, compare against the public repository, record the commit you compared in the PR, and update this section if the reference copy changes. Upstream is also GPL-3.0, but do not copy updater code into `src/` without the owner's decision. Whether to share updater code or add a control interface is an open design question.

## 8. Design reference

`docs/GUI riferimento/` holds saved Cloudflare dashboard pages (the DNS records menu and the new-record form). The UI copies their layout and behaviour. Use them for structure, spacing and interaction only. Do not copy Cloudflare's scripts, stylesheets, fonts, icons or logos into `web/`; colours and sizes live in `web/style.css`.

The folder also contains a `.txt` DNS export from the owner's account. Do not open, quote or use it. Build fixtures from the synthetic `example.com` zone instead.

## 9. CI and repository settings

CI (`.github/workflows/ci.yml`) runs the local checks, the container build and container smoke test, and `cargo audit`. CodeQL and dependency review have their own workflows, and Dependabot is configured in `.github/dependabot.yml`. Do not change CI as part of a feature or fix PR; propose CI changes on their own.

Branch protection, required checks and GitHub security features are owner settings. Adding a workflow file does not turn them on or enforce human approval.
