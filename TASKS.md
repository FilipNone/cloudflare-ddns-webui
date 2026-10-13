# Recovery tasks

## Current slice

Scope: complete locally verifiable safety, DNS/UI and bounded companion-contract work, then hand off a synthetic instance for human review. Remote CI, owner deployment, live companion verification and release approval remain separate gates.

- [x] Add repository instructions, specification, roadmap and Kilo phase/verification/PR-preparation commands.
- [x] Add locked format/lint/test/build checks and isolated mock smoke tests.
- [x] Add PR CI, container validation, Dependabot, RustSec, dependency review and CodeQL configuration. Remote execution remains below.
- [x] Fix runtime image copying compiler output into `/data`; exclude local secrets from build context and bind example published ports to loopback.
- [x] Replace account-derived mock fixtures with the synthetic `example.com` zone and documentation-range addresses.
- [x] Validate provider addresses and pin detection to the requested family; regress malformed, wrong-family and HTTP-error responses.
- [x] Fail closed on existing malformed, unreadable, credentialless or dangling-symlink auth state before opening the listener.
- [x] Reject overflowing/malformed chunk sizes, extension control bytes and invalid terminators without aborting the release process.
- [x] Apply the minimum patched rustls release for RUSTSEC-2026-0285 while preserving the pre-existing lockfile edit.
- [x] Complete independent review of this slice and record local validation evidence.
- [ ] Run remote CI and configure required checks/review approval. Owner action required; no PR or settings change has been requested.

## Next safety work

- [x] Make security mutations transactional on disk failure, including recovery-code consumption and restrictive temporary-file permissions.
- [x] Reject ambiguous/truncated HTTP framing and add socket-level parser tests.
- [x] Revoke pending login challenges on password changes and enforce factor lockout across challenges and sensitive operations.
- [x] Validate recovery-code verification paths and persistence failures on restart.
- [x] Replace incomplete SVG sanitization with a safe upload policy and regression coverage.
- [x] Validate bulk/path identifiers and multipart filenames before upstream requests; reject path escapes and duplicate IDs.
- [x] Validate configuration rather than silently accepting invalid TTL, booleans, durations and unsupported updater settings.
- [x] Stop unsent bulk/DDNS writes after originating-session revocation and report partial outcomes; already-sent requests may still complete.
- [x] Fail closed on malformed Cloudflare listing/lookup/import success responses rather than invent empty lists or import counts.

## DNS and UI work

- [x] Fix zone dropdown overlay stacking and verify on desktop/mobile.
- [x] Restore reachable mobile navigation and logout; the 390px dashboard now has a visible menu control.
- [x] Discard stale zone/page responses and prevent automatic load-error retry loops.
- [x] Return structured DDNS outcomes and retain failure logs after dashboard refresh and same-session navigation.
- [x] Implement and test explicit keep/set/clear comment and tag semantics.
- [x] Accept valid BIND default/inherited TTL, class and owner syntax; test import errors, canonical duplicates and oversized origin-relative names without process crashes.
- [x] Preserve raw import bytes so invalid UTF-8 is rejected rather than replacement-decoded by the browser.
- [x] Retain enrollment recovery-code results across navigation; cancel dismissed enrollment and reject stale auth/modal callbacks.

## Integration and release work

- [x] Define the bounded `standalone-v1`/`shared-v1` GUI contract against upstream commit `3f1a7220645a3f56eac94a6975b167bfd0f4ac5e`; test unsupported settings, ownership and explicit operator pause confirmation.
- [x] Add family-specific domain/provider coverage and duplicate/ownership failure tests. Duplicate reconciliation is deliberately unsupported, not claimed complete.
- [x] Define and test public-address and recorded Cloudflare-range rejection policy. No live range-refresh or full upstream-detection parity claim.
- [ ] Verify the bounded contract with an owner-authorized disposable live zone and companion instance. The GUI cannot observe whether the companion is paused.
- [ ] Verify HTTPS, persistent volumes and target deployment with owner approval.
- [ ] Record latest CI, independent review, manual checks and human merge approval before release.

## Baseline evidence

Inspected on 2026-10-12. `cargo test --locked`: 11 passed. Formatting fails on the existing sources. Strict Clippy reports an indexed loop in `auth.rs` and a zero-prefixed decimal test vector in `totp.rs`. A pre-existing `Cargo.lock` edit is retained.

## Earlier slice evidence

Validated on 2026-10-12 against the repaired working tree:

- `git diff --check`, `cargo fmt -- --check`, strict locked Clippy and `node --check web/app.js`: passed. Formatting-only changes normalize the existing Rust sources so the formatter can become a required check.
- `cargo test --locked`: 38 passed, up from 11. Auth, DDNS and HTTP regressions were demonstrated failing before their repairs. Review follow-ups also failed before the dangling-symlink and chunk-extension fixes.
- `cargo test --locked --release http::tests`: all 7 parser regressions passed in the optimized test build. The production-process smoke separately verifies oversized-chunk survival.
- `cargo build --locked --release`: passed after the final source review fixes.
- Host smoke: passed, including setup/session protection, proxy/TTL CRUD, record preservation on detection failure, restart persistence, oversized-chunk process survival, corrupt state and dangling-symlink startup rejection. Poisoned inherited settings were tested using synthetic values only.
- Final Docker build and container smoke: passed. User is `65534:65534`; `/data` starts empty and writable; setup and restart persist through a named volume. Runtime image size measured 2,285,945 bytes. No deployment was performed.
- RustSec with cargo-audit 0.22.2: passed after upgrading rustls to 0.23.45 and its required webpki patch to 0.103.15. The owner's existing ipnet 2.12.1 lockfile change is preserved.
- Actionlint, Compose configuration with `/dev/null` as its env file, and filename-only `.env` variant ignore checks: passed. Workflow action pins were verified against public GitHub commits.
- Fresh-context source and workflow reviewers rechecked their findings and reported no actionable findings in this slice. Fixes include dangling auth symlinks, extension controls, committed-whitespace CI, explicit Node 24, env-file ignores and SIGTERM cleanup.
- Browser checks at 1440x900 and 390x844 verified login and dashboard loading with a synthetic account. Desktop invalid-password feedback and logout worked. Mobile dashboard navigation/logout is inaccessible and remains an open task. Screenshots are local test artifacts, not owner-account captures.
- Remote CI, branch protection/security settings, Kilo command loading in a fresh client, live providers, full TOTP failure-path coverage, HTTPS proxy and owner target deployment were not verified. No commit, push, PR, deploy or merge was requested or performed. Local upstream reference folders were not edited.

## Current validation evidence

Local candidate checked on 2026-10-13 after recovering the interrupted reviews:

- `git diff --check`, `cargo fmt -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked` and `cargo build --locked --release`: passed, with 120 Rust tests. `node --check web/app.js` and `node --test web/app.test.cjs`: passed, with 38 JavaScript tests. Independent reviewers reran these checks against the final candidate.
- Fail-before regressions cover auth transaction/recovery failures, challenge revocation and account-wide factor lockout; HTTP ambiguity/resource bounds; SVG policy; strict config and IP-family/ownership safety; stale UI responses and enrollment races; import byte preservation and same-session outcome retention. Latest root regressions failed before unsent DDNS write gating, malformed-list status, missing import counts and malformed exact-zone lookup repairs.
- Independent runtime checks confirmed malformed list responses return 502 without DNS writes, long BIND names return 400 without killing the process, GUI single-flight returns 409 while another cycle is held, and session revocation stops unsent bulk/DDNS mutations with partial outcomes. A legitimate empty zone-query result can still search the parent zone; a missing result cannot.
- Final Docker build and container smoke passed. The 20-group suite explicitly skips only the two host-only state-rename fault-injection groups; those pass on the host. Non-root user `65534:65534`, initially empty writable `/data`, named-volume restart persistence and corrupt-state failure were verified. Final image size: 2,341,533 bytes; host release binary: 2,512,032 bytes. These are artifact measurements, not runtime memory claims.
- Cargo-audit 0.22.2 scanned 138 locked dependencies against 1,309 current RustSec advisories and reported no vulnerabilities. It was installed outside the repository under `/tmp/kilo`; no dependency upgrade was needed after the earlier rustls patch.
- Fresh integrated DNS/UI review found no unresolved actionable findings in its source/unit/loopback scope. It independently checked separate malformed zone/record responses, five malformed import envelopes, bulk-update preflight revocation, GUI concurrency and final embedded JavaScript.
- Independent host smoke passed all 20 groups without skips, then passed with deliberately poisoned inherited configuration/proxies using synthetic values only. Coverage includes both address families, separate malformed zone/record stages, missing import counts, recovery restart/replay and held-request revocation/concurrency tests.
- Expanded workflow/harness review passed synthetic fixture and helper/oracle checks, isolated mock stages, exact sanitized child environment and checksum-verified actionlint 1.7.12 for all workflows. Its final failed-save output assertion gap was closed: setup, enrollment confirmation, recovery login, password change and 2FA disable failures return no session cookie or sensitive authentication material. Focused storage groups and both full 20-group host runs passed after that change; the independent static recheck was clear.
- Independent final browser checks at 1440x900 and 390x844 verified reachable navigation/logout, dropdown hit testing/keyboard/Escape, metadata operations, bulk feedback, valid and invalid imports, original-byte invalid UTF-8 rejection, raster upload/SVG rejection and security flows including recovery-code retention during navigation. Delayed responses and injected failures verified zone/page fencing, no load-error retry loop, escaped DDNS failure logs retained after refresh/navigation and a late real password-change response leaving a replacement enrollment modal open. These timing/partial-failure tests used explicit Playwright gates or synthetic responses, not live Cloudflare latency/failures. Screenshots are local synthetic artifacts under `/tmp/kilo/`.
- The specific obsolete-401 browser injection could not be delivered because Playwright reported an already-handled route; that browser assertion remains unverified. Actual-API JavaScript regressions for stale 401 responses pass. Console inspection found expected negative-test HTTP/accessibility diagnostics and no observed uncaught application JavaScript exception. Physical mobile devices and live Cloudflare/HTTPS proxy behavior were not tested.
- Headless Chrome initially crashed during export/download capture while the application stayed healthy. The browser worker recovered and verified a real `example.com.txt` download with the dedicated click tool and a 200 export response containing the synthetic BIND body. The transient tool failure was resolved without a production change; export/reimport integration also passes.
- Human-review instance started on `http://localhost:8888` with the isolated harness, disposable account and synthetic `example.com` mock, as a tracked persistent process. The localhost config endpoint and browser sign-in page were verified. `HUMAN_REVIEW.md` contains the checklist and recreation instructions; the initial synthetic password is `Synthetic-smoke-password-42`. Human acceptance is not yet performed.

## Security review

The independent final score is **9.0/10**, up from 6.0/10, for the same restricted loopback/private administrative network plus HTTPS proxy threat model with trusted operator configuration and files. It is not a public-internet readiness rating or release approval. The final reviewer independently ran all 120 Rust tests, 38 JavaScript tests and 20 host smoke groups, plus custom malformed-envelope reproductions; previous actionable review blockers were resolved.

| Area | Baseline | Final | Maximum |
| --- | ---: | ---: | ---: |
| Authentication | 1.2 | 2.3 | 2.5 |
| Persistence | 0.8 | 1.3 | 1.5 |
| HTTP and resource bounds | 0.6 | 1.4 | 1.5 |
| Outbound and DNS confinement | 0.9 | 1.4 | 1.5 |
| Browser and content policy | 1.3 | 1.4 | 1.5 |
| Deployment and evidence | 1.2 | 1.2 | 1.5 |
| Total | 6.0 | 9.0 | 10.0 |

The remaining deductions cover TOTP-window reuse and restart-reset limiters; no parent-directory fsync or full storage-fault injection; bounded but nontrivial resource use without saturation/proxy proof; static address ranges and no cross-process/updater coordination; memory-only browser displays and structural raster validation; and external CI/deployment/human gates. Later container, dependency-audit and browser evidence does not automatically increase this independent score.

## Residual limits

- State persistence uses private random temporary files, file sync and atomic rename before committing memory. Parent directories are not fsynced; abrupt power-loss durability is not established. Fault injection forces rename failure, not actual ENOSPC or sync failure.
- Password/factor limiters are in memory and reset on restart. Recovery codes and challenges are single-use, but a valid TOTP can be reused in separate challenges within its accepted time window; persistent TOTP anti-replay is not implemented.
- GUI DDNS cycles are single-flight only within one process. No multi-process file coordination or companion/ordinary-record-edit coordination is implemented. Shared mode requires the operator to pause the companion; it cannot verify that assertion.
- HTTP admission is 16 connections with 2 MiB request bodies and 30-second read/write deadlines. The 32 MiB retained-body bound is not total process RAM; parsed copies, responses and route work add memory. Real saturation/proxy-desynchronization tests were not run.
- Raster containers and dimensions are checked, not compressed pixel decoding. BIND preflight is bounded and intentionally supports only `$TTL`/`$ORIGIN` directives, not every RFC feature.
- DDNS logs and enrollment recovery-code displays are kept only in the signed-in page's memory. Full reload/logout clears them. Unknown import outcomes must be checked before manually retrying; an upstream mutation may already have occurred.
- Remote CI, branch protection/security settings, actual HTTPS proxy, owner deployment, live zone/companion tests and human merge approval remain unverified owner gates. The owner requested commit and push on 2026-10-13; no PR, owner deployment, release or merge was requested.

## Commit preparation

Rechecked on 2026-10-13 for the requested commit and push:

- `git diff --check`, `cargo fmt -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, `cargo build --locked --release`, `node --check web/app.js` and `node --test web/app.test.cjs`: passed again after the frontend follow-up below, with 120 Rust tests and 46 JavaScript tests.
- Before the frontend follow-up, `cargo test --locked --release` passed all 120 tests in the optimized build. The follow-up changed only frontend code and its tests; the release binary was rebuilt and its host/container smoke suites passed afterward.
- `python3 scripts/smoke-test.py`: passed without skips using isolated synthetic state. `docker build -t cloudflare-ddns-webui:test .` and `python3 scripts/smoke-test.py --container-image cloudflare-ddns-webui:test`: passed. The container run skips the two host-only storage-fault groups; both passed on the host. Docker used its deprecated legacy builder because Buildx was unavailable.
- Cargo-audit 0.22.2 rechecked 138 locked dependencies against 1,310 RustSec advisories and reported no vulnerabilities.
- A fresh read-only backend reviewer found no actionable correctness or security blockers. This source review did not reproduce the runtime checks above.
- The fresh frontend reviewer found retained recovery codes surviving logout/expiry and stale enrollment confirmation restoring codes after authentication changed. Eight new tests plus the strengthened current-401 test failed before the repair. Authentication boundaries now clear retained codes, including failed logout requests, and confirmation checks its authentication generation before assigning or displaying codes. The reviewer independently reran all 46 JavaScript tests and confirmed both findings resolved with no new actionable findings; the separate documentation review also found no blockers.
- Browser checks against the rebuilt isolated harness at 1440x900 and 390x844 passed logout/relogin cleanup, current-401 recovery-modal cleanup and a held confirmation delivered after logout/login. Code-display state and late confirmation/401 responses were synthetic injections; logout and login used the real local APIs. Same-session navigation retention remains covered by the JavaScript suite. Console errors were only expected 401 responses. The browser script initially used the wrong logout label, then passed using the actual control; the disposable verification instance was stopped afterward.
