# Local human review

Review URL: http://localhost:8888

The review instance uses disposable state, a mock Cloudflare token and the synthetic `example.com` zone. It cannot modify the owner's DNS. The initial password is `Synthetic-smoke-password-42`; password changes during review replace this value for that running instance.

To recreate the review environment after stopping it:

```sh
cargo build --locked --release
python3 scripts/smoke-test.py --serve --port 8888
```

The harness prints its URL and synthetic password. Stopping it removes the disposable account and DNS state. Do not put a real token in this environment.

## Desktop and mobile

- [ ] Sign in with an incorrect password and check the error, then sign in with the synthetic password.
- [ ] Open the zone selector with mouse and keyboard. Use arrow keys, Enter and Escape; check that it does not block the underlying page after closing.
- [ ] At a 390-pixel-wide viewport, open the navigation menu, visit Dashboard, Records and Settings, and reach Logout. Check that the menu closes and keyboard focus returns to its control.
- [ ] Switch between pages while requests are loading. Check for stale records, endless retries, stuck spinners or errors attributed to another page.
- [ ] After a fresh login or password change, check that an older request's authentication failure does not sign out the new session. Automated JavaScript regressions pass; the dedicated browser injection for this case could not be delivered.
- [ ] Change theme and accent, reload, and check persistence. Upload a small PNG/JPEG/WebP/GIF, then reset it. SVG, mismatched formats and oversized images should be rejected.

## DNS management

- [ ] Create `review.example.com` with an A record containing `192.0.2.42`. Enable proxy and verify automatic TTL; disable proxy and set a numeric TTL.
- [ ] Edit comment and tags using Keep, Set and Clear. Check the saved record after reopening its editor.
- [ ] Select multiple synthetic records and modify TTL, proxy and metadata. Check success/failure counts and per-record errors. Non-proxiable types must reject proxy changes.
- [ ] Delete only records created for review and verify that the list refreshes.
- [ ] Export the zone. Import the synthetic BIND sample below, then reimport it and check duplicate/skipped reporting. Invalid addresses, malformed directives and duplicate records within one file should fail before any write.
- [ ] Run Update Now and check the outcome log. Refresh the dashboard and navigate away/back; the latest update result should remain visible in the running page. A full browser reload clears in-memory update history.

Synthetic BIND sample:

```bind
$ORIGIN example.com.
$TTL 300
review-import IN A 192.0.2.50
              AAAA 2001:db8::50
review-alias IN 600 CNAME review-import.example.com.
review-text TXT "synthetic; review fixture"
```

Use a filename such as `review-zone.txt`. Imports are limited to 2 MiB. The mock supports the tested synthetic record types; it does not establish Cloudflare account-specific import behavior.

Export API, export/reimport and the final browser download passed. The browser harness initially crashed during download capture, then recovered with its dedicated click tool. Verify the downloaded zone file in your normal browser as part of the checklist.

## Account security

- [ ] Start 2FA enrollment with an incorrect current password; it must fail. Retry with the synthetic password, then cancel and verify that 2FA remains disabled.
- [ ] Enroll using a disposable authenticator entry. Try an invalid code before confirming a valid code. Check that recovery codes are shown and can be downloaded.
- [ ] Navigate away while confirming enrollment, then reopen the recovery-code notice. The codes must remain available in the same signed-in page until Done; logout or full reload clears them.
- [ ] Keep another signed-in tab open while enabling 2FA or changing the password. Its old session must stop working on its next request; the successful initiating flow should receive a fresh session.
- [ ] Sign out and sign in with password plus TOTP. Repeat using one recovery code, then verify that the consumed code cannot be reused.
- [ ] Change the password with the required factor. Confirm the old password fails and the new one works. Save only synthetic test credentials.
- [ ] Disable 2FA using a valid TOTP or unused recovery code. Verify that invalid proof is rejected and password-only login works afterward.
- [ ] Logout and reload. Protected DNS pages must require sign-in again.

The automated suite separately exercises persistence failure, process restart, challenge revocation, factor lockout, malformed HTTP, invalid identifiers and concurrent DDNS updates. Triggering five factor failures deliberately locks this synthetic account for five minutes; recreate the disposable instance if a fresh review account is needed.

Session revocation stops later unsent bulk/DDNS writes. An upstream request already sent before revocation may still complete; the GUI cannot roll it back.

## Before a real deployment

- [ ] Review the final security score, test evidence and residual risks in `TASKS.md`; the score applies to the documented restricted administrative deployment model.
- [ ] Initialize the real account on loopback before allowing remote access. Restrict the proxy/backend and use a least-privilege DNS-edit token.
- [ ] Configure `PUBLIC_ORIGIN` for the exact trusted HTTPS origin and `SECURE_COOKIES=true`. Verify cookie attributes and rejection of unexpected Host/Origin values through the actual proxy.
- [ ] Configure proxy upstream HTTP/1.1 and verify restart/volume behavior on the target host. Local mock/container tests do not certify Dokploy or another owner deployment.
- [ ] Keep scheduling in the companion updater. For shared manual updates, pause it and explicitly confirm `GUI_SHARED_UPDATER_PAUSED=true`; the GUI does not observe or coordinate that daemon. Verify the exact ownership marker and supported settings first.
- [ ] Review the uncommitted diff, enable the repository's applicable required checks/security settings, and verify latest-commit remote CI before approving a release or merge.

Human approval is still required. No publication, deployment to owner services or merge is part of this local review.
