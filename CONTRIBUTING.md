# Contributing

Thank you for helping improve Cloudflare DDNS Web UI.

## Before you start

- Read [AGENTS.md](AGENTS.md) and the linked rules, workflow, architecture, and DDNS safety documentation.
- Open an issue before a large change so its scope and expected behaviour can be agreed first.
- Keep each pull request focused on one change and update the user-facing documentation when behaviour changes.
- Never include API tokens, passwords, account state, real DNS exports, or production domains. Tests use the synthetic `.example` fixtures in `scripts/mock-cloudflare-api.py`.

## Development checks

Run the complete checklist in [docs/workflow.md](docs/workflow.md#checks) before opening a pull request. Authentication changes also need restart, persistence, and failure-path coverage. Container changes need the container smoke workflow, and visible changes need desktop and mobile browser review.

## Pull requests

Describe the behaviour changed, the security or compatibility impact, the checks you ran, and anything you could not verify. CI, dependency review, CodeQL, and RustSec must pass on the final commit. A maintainer reviews and merges the change.
