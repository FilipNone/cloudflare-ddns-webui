---
description: Run the project's local acceptance checks
---
Read AGENTS.md and inspect git status. Run every command in the Checks section of docs/workflow.md, plus the container checks there when Docker files changed. For visible changes, check desktop and mobile flows against a --serve instance with isolated state and mock credentials. Report each result and any check you could not run. Do not use .env, data/ or real Cloudflare credentials. Do not modify source, commit, push, open a PR or deploy as part of verification.
