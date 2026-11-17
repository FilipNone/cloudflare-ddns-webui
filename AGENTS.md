# AGENTS.md

Cloudflare DDNS Web UI: a self-hosted admin page for Cloudflare DNS with on-demand DDNS updates, built to sit next to [timothymiller/cloudflare-ddns](https://github.com/timothymiller/cloudflare-ddns). One static Rust binary (hand-written HTTP/1.1 server on Tokio) with a vanilla JS frontend compiled in, shipped in a `FROM scratch` image.

Keep this file short. Details live in `docs/`.

## Read

| File | Covers |
|---|---|
| [docs/rules.md](docs/rules.md) | Owner rules, never crash, security, DDNS safety, scope |
| [docs/workflow.md](docs/workflow.md) | Doing a task, checks, smoke harness, parallel agents, CI |
| [docs/architecture.md](docs/architecture.md) | Source map, request flow, API routes, data directory |
| [docs/ddns.md](docs/ddns.md) | Update now, fail-closed rules, contracts, bulk batches, upstream copy |
| [docs/frontend.md](docs/frontend.md) | Script order, CSP and escaping, conventions, design reference |
| [README.md](README.md) | User-facing features, settings and deployment. Keep it accurate when behaviour changes |
| [.env.example](.env.example) | Every supported setting |

`docs/Cloudflare DDNS/` is an ignored copy of the upstream updater, for comparison only. Don't edit or commit it.

## Rules

- Never read or copy `.env`, `data/`, tokens or real DNS exports. Test against `scripts/mock-cloudflare-api.py` and the synthetic `example.com` zone.
- No new `unwrap`, `expect` or `panic!` in non-test code: the release build aborts on panic.
- No package manager, framework or build step in `web/`, and no inline scripts or styles.

## How to work

- **Think first.** State your assumptions. If something is unclear or has several readings, ask instead of picking one. Say so when a simpler approach exists.
- **Keep it simple.** Write the minimum code that solves the task: no extra features, single-use abstractions or unrequested options.
- **Change only what you must.** Match the existing style and keep old comments. Mention unrelated dead code instead of deleting it, and remove only what your change left unused.
- **Prove it.** Turn the task into a check, usually a test that fails first, and loop until it passes. Run the checks in [docs/workflow.md](docs/workflow.md#checks) before you finish.
