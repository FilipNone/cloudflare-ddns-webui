# Repository instructions

## Owner rules

- Use only `165696124+FilipNone@users.noreply.github.com` for author or committer email. Never print or publish another owner email. Do not change global Git configuration.
- Do not read or copy `.env`, `data/`, tokens, account state, or local DNS exports into logs, tests, documentation, commits, or PRs. Use synthetic fixtures and mock credentials.
- Preserve existing comments unless the repair needs to change them.
- Before every PR, load the `humanizer` skill and rewrite comments added by that PR. Keep their technical meaning; leave unrelated old comments alone. If the skill is unavailable, report that the PR preparation is blocked.
- Commit, push, open a PR, deploy, and merge only when explicitly requested. A human approves the merge.

## Architecture and boundaries

This is a Rust binary with a hand-written Tokio HTTP server. `web/` contains embedded vanilla JavaScript, HTML, and CSS; it has no package manager or frontend build step.

- `src/http.rs`: HTTP parsing and response framing.
- `src/auth.rs`, `src/totp.rs`: persistent admin identity, sessions, password hashing, TOTP and recovery codes.
- `src/routes.rs`: authentication checks, input validation, and API routes.
- `src/cloudflare.rs`: Cloudflare API requests and response types.
- `src/ddns.rs`, `src/config.rs`: environment configuration, IP detection, status and manual updates.
- `src/customize.rs`: UI settings and uploaded branding.
- `scripts/mock-cloudflare-api.py`: local API mock. Use the synthetic `example.com` zone for tests.

`Cloudflare DDNS/` and `GUI riferimento/` are ignored local reference folders. They are not dependencies or authoritative upstream checkouts. Do not edit or vendor them as part of a GUI repair. Verify upstream versions against `timothymiller/cloudflare-ddns` and record the commit being compared.

The GUI talks directly to Cloudflare. It does not start, configure, or observe the companion updater. Do not claim daemon integration or full environment compatibility without implementing and testing a contract.

## Working sequence

1. Read `SPEC.md`, `ROADMAP.md`, and `TASKS.md`. Select one bounded task with observable acceptance criteria.
2. Inspect existing work with `git status --short`. Preserve changes you did not make, including lockfile edits.
3. Add a regression test that fails before the repair. Use local mocks, never the owner's account or DNS records.
4. Implement the smallest repair. Avoid unrelated rewrites and dependency upgrades.
5. Run the checks below. Record failures and untested behavior instead of declaring the phase complete.
6. Have an independent reviewer inspect the diff with fresh context. Fix actionable findings and rerun checks.
7. Update task evidence. Prepare a PR only if asked, humanize its new comments, and wait for CI on its latest commit.
8. The owner verifies the target environment and decides whether to merge. Never auto-merge or resolve unverified feedback.

## Required checks

```sh
git diff --check
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
node --check web/app.js
node --test web/app.test.cjs
python3 scripts/smoke-test.py
```

`scripts/smoke-test.py` uses temporary state, loopback listeners, and a mock token. Build the release binary first. For container changes also run `docker build -t cloudflare-ddns-webui:test .` and check that the non-root container can write `/data` without shipping build output there.

For visible changes, check the affected flow in a browser on desktop and mobile. Authentication changes require restart/persistence tests and failure-path tests. DDNS changes require address-family tests and proof that detection failures preserve DNS records.

CI includes the local gates, container checks, CodeQL, RustSec auditing, dependency review, and Dependabot. GitHub branch protection and security feature availability are separate owner settings; adding workflow files does not enable required checks or enforce human approval.
