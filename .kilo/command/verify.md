---
description: Run the project's local acceptance checks
---
Read AGENTS.md and inspect git status. Run git diff --check, cargo fmt -- --check, cargo clippy --locked --all-targets -- -D warnings, cargo test --locked, cargo build --locked --release, node --check web/app.js, node --test web/app.test.cjs, and python3 scripts/smoke-test.py. Validate Docker changes with a local image build and non-root persistent-state check. For visible changes inspect desktop and mobile flows using isolated state and mock credentials. Report each result and any missing target check. Do not use .env, data/, or real Cloudflare credentials. Do not modify source, commit, push, open a PR or deploy as part of verification.
