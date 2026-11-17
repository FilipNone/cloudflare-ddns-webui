# Rules

## Owner rules

- Use only `165696124+FilipNone@users.noreply.github.com` as author or committer email. Never print or publish another owner email, and don't change global Git configuration.
- Never read or copy `.env`, `data/`, tokens, account state or real DNS exports into logs, tests, docs, commits or PRs. Use synthetic fixtures and mock credentials.
- Commit, push, open a PR, deploy or merge only when asked. A human approves the merge.
- No AI co-author trailers or attribution lines. One fix per commit.
- Keep existing comments unless the change makes them wrong. Before a PR, run the `humanizer` skill over the comments the PR adds; if the skill is unavailable, say the PR is blocked.

## Never crash

The release build aborts on panic, so one panic stops the server for everyone.

- No new `unwrap()`, `expect()`, `panic!`, `unreachable!` or `todo!` in non-test code. A `NonZeroU32::new(..).unwrap()` in a `const` is fine because it runs at compile time. Remove older ones when you work on that code.
- Treat lengths, offsets and numbers from requests, uploads, zone files and Cloudflare replies as hostile: use `get()`, checked or saturating arithmetic, and size caps before allocating.
- A crash fix comes with a synthetic regression test that failed before the fix.

## Security

- Every DNS route needs a session, and every write also needs the mutation header.
- Tokens, passwords, backup codes and TOTP secrets never reach logs or API responses, except the one-time enrollment display.
- Save password and 2FA changes before reporting success. If `state.json` exists but is unreadable or invalid, startup fails; it never falls back to first-run setup.
- Keep the strict CSP: no inline scripts or styles and no third-party assets in `web/`.
- Auth changes need restart, persistence and failure-path tests.

## DDNS safety

See [ddns.md](ddns.md) for the full behaviour.

- Parse a detected address and check its family before any DNS write. A failed or wrong-family detection leaves records untouched.
- Report provider and API errors as failures. Never show a failed, partial or unconfirmed update as a success.
- Proxy and TTL rules match in backend and frontend: only A, AAAA and CNAME can be proxied, and proxied records use TTL 1.
- After a session is revoked, multi-record operations stop unsent writes and report partial results.
- Duplicate DDNS records fail closed. The GUI never deletes or reconciles records it doesn't own.
- DDNS deletes records only when the admin turns on `DELETE_ON_STOP` or `DELETE_ON_FAILURE`, and only the records the active contract lets it touch (see ddns.md). `DELETE_ON_FAILURE` acts when a provider reports that there is no address of that family, never after a failed lookup.

## Scope

- Work listed in [roadmap.md](roadmap.md) is in scope, including the updater features it names: scheduled updates, record deletion, more IP providers, detection groups, per-domain proxy status, WAF lists, notifications and heartbeats. Build it within the rules above.
- Don't claim daemon integration or full upstream compatibility without a tested contract. Updater settings the GUI doesn't implement yet are rejected at startup (`unsupported_setting` in `src/config.rs`). Take a setting off that list in the change that implements it.
- Keep the dependency list short. Add a crate only when std or an existing crate can't do the job, and explain why in the PR. Don't upgrade dependencies inside an unrelated fix.
- Tests run against `scripts/mock-cloudflare-api.py` and its synthetic `.example` zones, never the owner's account. Fixture names stay under the reserved `.example` TLD and addresses in the documentation ranges; the smoke test's fixture check enforces both.
