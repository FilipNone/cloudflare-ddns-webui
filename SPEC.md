# Project specification

## Purpose

`FilipNone/cloudflare-ddns-webui` provides a small self-hosted interface for managing Cloudflare DNS and inspecting domains also used by `timothymiller/cloudflare-ddns`.

The intended user is an administrator running the GUI on a private network or behind an HTTPS reverse proxy. The Cloudflare token stays on the server. First-run setup creates one admin account in persistent storage.

## Current implementation

Version 1.1.0 is a Rust 2021 binary. Tokio handles HTTP connections; reqwest calls Cloudflare and IP providers. The frontend is vanilla JavaScript and CSS embedded at compilation. There is no frontend build pipeline or upstream updater dependency.

The GUI supports zone/record management, bulk edits, BIND import/export, manual DDNS updates, TOTP with recovery codes, and UI settings. Existing tests cover portions of authentication, TOTP, QR generation and customization. These tests do not establish that every advertised feature works.

## Supported development baseline

- Rust 1.98.0, with rustfmt and Clippy, pinned in `rust-toolchain.toml`.
- Dependencies resolved by the committed `Cargo.lock`; builds and tests use `--locked`.
- Node.js 24 or newer for JavaScript syntax checks; no npm dependencies.
- Python 3.12 or newer for the local mock and smoke harness; standard library only.
- Docker with BuildKit for the musl/scratch image.

Verify version changes and security advisories before updating dependencies. Do not replace the lockfile to silence a failed build.

## Upstream integration contract

The ignored local `Cloudflare DDNS/` snapshot declares version 2.2.0 and has no verified commit provenance. The public upstream `master` at commit `3f1a7220645a3f56eac94a6975b167bfd0f4ac5e`, inspected on 2026-10-12, documents 2.3.0. This is a comparison baseline, not a runtime dependency or a verified local deployment.

The GUI calls Cloudflare independently; it does not reuse updater code, expose a daemon control interface, monitor the daemon or schedule recurring updates. Its status reports DNS state and `daemon_status: not_observed`. This bounded design avoids a claim of full upstream compatibility.

`standalone-v1` supports common and family-specific domains, the documented provider subset, strict address-family/public-address policy and explicit metadata. `shared-v1` additionally requires an exact anchored ownership filter matching `RECORD_COMMENT`, and operator confirmation `GUI_SHARED_UPDATER_PAUSED=true`. The operator must pause the companion before manual updates; the GUI cannot verify that confirmation. Duplicate records fail closed rather than being deleted or reconciled. GUI update cycles are single-flight, but other processes and ordinary record edits are not coordinated.

Provider groups/interfaces, general ownership regular expressions, scheduling, WAF and notification settings are unsupported and rejected at startup. Cloudflare addresses are rejected against a recorded range snapshot, not a live range subscription. Keep scheduling in the companion service. Verification against a disposable live zone and companion remains an owner-authorized gate.

## Required behavior

- Authenticate all DNS access; require the mutation header as well as a session for writes.
- Persist password and 2FA changes before reporting success. Existing unreadable or invalid identity state must never reopen first-run setup.
- Keep tokens, passwords, recovery codes and TOTP secrets out of logs and API responses except the deliberate enrollment/recovery display.
- Use only the owner's noreply address from `AGENTS.md` in contribution metadata.
- Parse detected addresses and verify the requested family before any DDNS write. Detection failures preserve existing records.
- Surface provider and API errors without reporting a failed update as success.
- Keep Cloudflare proxy/TTL rules and explicit metadata clearing consistent between backend and frontend.
- Ignore stale responses after zone or page navigation. Dropdowns and security flows must work on desktop and mobile.
- After session revocation, multi-record operations must stop unsent writes and report partial outcomes. Already-sent Cloudflare requests cannot be rolled back.
- Preserve import bytes; malformed upstream success responses must report an unknown/failure outcome, never invented zero counts or automatic retries.
- Produce a non-root static container with writable persistent storage and no compiler artifacts in the runtime image.

## Acceptance criteria

Each roadmap task must name automated checks and any target-environment verification. The local gate in `AGENTS.md` passes against the locked dependency graph. Smoke tests run without real credentials, use isolated state, exercise authenticated API access, and verify state after restart.

Security and dependency checks run on PR updates. An independent review has no unresolved actionable findings before the owner verifies the latest revision and merges it.

## Non-goals

This recovery does not replace the upstream updater, introduce a frontend framework, provide multi-user accounts, deploy to the owner's services, alter real DNS, or automatically merge generated changes. No public-internet readiness claim is made while security tasks remain open.
