# Workflow

## Doing a task

1. Start from the owner's request or a GitHub issue, with acceptance criteria you can observe.
2. Run `git status --short` and keep changes you didn't make, including lockfile edits.
3. Write a regression test that fails, then make the smallest change that passes it.
4. Run the checks below. Report failures and anything you couldn't test instead of calling the task done.
5. Have an independent reviewer read the diff with fresh context, fix what they find and rerun the checks.
6. Only when asked: prepare the PR with the evidence (checks, manual checks, known gaps) and wait for CI on its last commit. The owner merges.

## Checks

```sh
git diff --check
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
node --check web/app.js
(for f in web/js/*.js; do node --check "$f" || exit 1; done)
node --test web/app.test.cjs
python3 scripts/smoke-test.py
```

- Build the release binary before the smoke test. `app.test.cjs` also loads `appearance.test.cjs`, so the command above runs both suites.
- `python3 scripts/smoke-test.py --only <group>` runs one group (for example `baseline`, `auth`, `metadata`, `bulk-revocation`, `ddns-contract`, `http`, `shutdown`).
- `--serve --port 8888` starts a disposable instance on loopback for manual checks. Log in with the `PASSWORD` constant from `scripts/smoke-test.py`.

For container changes:

```sh
docker build -t cloudflare-ddns-webui:test .
python3 scripts/smoke-test.py --container-image cloudflare-ddns-webui:test
```

Check that the non-root container (UID/GID 65534) can write `/data`. For visible changes, check the flow in a browser at 1440x900 and 390x844.

Toolchain: Rust 1.99.1 with rustfmt and Clippy (pinned in `rust-toolchain.toml` and the Dockerfile), Node.js 24+, Python 3.12+ (standard library only), Docker. Always use `--locked`, and don't regenerate `Cargo.lock` to get past a failed build.

## Library docs

Check documentation for third-party crates and APIs (tokio, reqwest, rustls, ring, serde, the Cloudflare API). Prefer version-matched docs over memory: check the locked version in `Cargo.lock`.

## Parallel agents

- Use your own target directory (`CARGO_TARGET_DIR=target/agent-<name>`) and delete it when done.
- Give each `--serve` instance its own `--port`.
- Edit only the files your task owns. `src/routes.rs` is large and shared, and `web/js/*.js` share one global scope; make small edits and re-read a file before each edit.
- If someone else's unfinished edit breaks the build, wait and retry. Don't fix their files.

## CI

`.github/workflows/ci.yml` runs the checks above, the container build and smoke test, and `cargo audit`. CodeQL and dependency review have their own workflows; Dependabot is in `.github/dependabot.yml`. Propose CI changes in their own PR, not inside a fix.

Branch protection, required checks and GitHub security features are owner settings. Adding a workflow does not turn them on.
