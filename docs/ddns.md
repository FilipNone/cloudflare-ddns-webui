# DDNS and Cloudflare

The GUI never starts, configures or watches cloudflare-ddns. Today it has no schedule: it shows DDNS status and runs one update when the admin presses **Update now**. Scheduled updates, record deletion and the other updater settings in [roadmap.md](roadmap.md) are planned; each one moves out of the rejected list when it is built.

## Update now (`ddns.rs`)

1. Detect IPv4 and IPv6 together with two prebuilt clients bound to `0.0.0.0` and `::`. No proxy, no redirects, a size cap, and no reused connections, so a WAN change can't return a stale address.
2. Keep an address only if it is public, of the right family and outside Cloudflare's ranges (a list built into the binary). `literal:` addresses may be private.
3. For each domain with an address, look up its zone once, fetch its A or AAAA records with one filtered request (`type` and `name.exact`), then create the record or update address, TTL, proxy status and comment.
4. Re-check the session before each write. `success` is false if any outcome failed.

Only one update runs at a time; a second request gets `409`. Status and Update now use the same `record_matches` rule, so "in sync" means address, TTL, proxy status and comment all match. Addresses are compared as parsed IPs, not strings.

## Fail closed

- Failed or wrong-family detection: skip that family, look up no zones and send nothing.
- Two zones with the same name, duplicate records, or an incomplete listing (missing `result_info` or fewer items than `total_count`): fail that domain without writing.
- Errors never include request URLs or zone IDs (`without_url()`).

## Contracts with cloudflare-ddns

- `standalone-v1` (default): update the A and AAAA records of the configured domains.
- `shared-v1`: only touch records whose comment matches `MANAGED_RECORDS_COMMENT_REGEX`, an anchored exact match that must equal `RECORD_COMMENT`. Needs `GUI_SHARED_UPDATER_PAUSED=true`, which the GUI cannot verify.

Both were written against cloudflare-ddns 2.3.0, commit `3f1a7220645a3f56eac94a6975b167bfd0f4ac5e`, inspected on 2026-10-12. Later upstream changes have not been reviewed against them.

## Bulk edits and deletes

`POST /api/zones/{id}/records/bulk` sends `POST /zones/{id}/dns_records/batch` in groups of `BATCH_LIMIT` = 200 (the Free plan limit).

- The session is checked before each group; after a revocation the rest are reported as not sent.
- A Cloudflare error reply means nothing in that group was applied, so every record in it is reported failed.
- A lost or unreadable reply, or a success reply whose IDs don't match the request (compared as a set), means the outcome is unknown. Report those records as failed with an error that says so, never as success.
- Later groups are still sent. The response shape `{results, succeeded, failed}` is what `bulkResultToast` reads.

## Upstream reference copy

`docs/Cloudflare DDNS/` is an ignored local copy of `timothymiller/cloudflare-ddns`, for comparison only. Don't edit or commit it. It has no Git history; on 2026-11-03 it matched upstream `master` at `1cd73f0c523deba2b87d98210c43ed172debb27d` (2.3.1), minus `.github/`.

When a task depends on upstream behaviour, compare against the public repository and record the commit in the PR. Upstream is GPL-3.0 too, but don't copy updater code into `src/` without the owner's decision.
