# Recovery roadmap

Use one reviewable task at a time. Phase completion requires evidence for every exit criterion, including manual checks where listed.

## Phase 0: development workflow

Deliver repository instructions, this specification, a task ledger, reusable Kilo commands, locked local checks, a credential-free smoke harness, and CI/security workflows.

Exit: local checks pass; the owner has enabled required CI/review checks in GitHub; the first remote CI run has passed. Local files alone do not complete the remote requirements.

## Phase 1: safety repairs

Depends on the Phase 0 test harness. Fix identity persistence/failure handling, IP detection validation, request framing, recovery-code handling and uploaded-content security. Correct the container data directory and exclude local secrets from its build context.

Exit: corrupt or unreadable auth state fails closed; failed saves cannot leave an in-memory identity change; invalid/wrong-family provider responses cause no writes; HTTP framing and authentication failure paths have regressions; container checks pass. Independent security review is required before public exposure.

## Phase 2: usable DNS management

Depends on Phase 1. Repair dropdown stacking, mobile navigation/logout, navigation races, retained DDNS failure feedback, keep/set/clear metadata semantics and BIND preflight validation.

Exit: mock integration tests cover record operations and partial failures; browser verification covers desktop/mobile, switching zones during slow requests, import/export and bulk edits. The UI must show failures without retry loops or false success messages.

## Phase 3: companion integration

Depends on Phase 2. Review upstream 2.3.0 at a recorded commit and define a versioned contract for supported settings, ownership and update coordination. Decide whether to share updater code or use a control interface before implementation.

Exit: supported/unsupported settings are explicit; ownership restrictions prevent unintended writes; family-specific domains and duplicate handling have contract tests; status distinguishes DNS state from daemon health. Verify with a disposable zone and companion instance, with owner authorization.

## Phase 4: release

Depends on the previous phases. Verify HTTPS proxy behavior, restart/volume persistence, target deployments, dependency advisories and documentation. Measure binary/image size rather than repeating unverified size claims.

Exit: latest-commit CI and independent review pass, manual target checks are recorded, all actionable review feedback is resolved, and the owner approves the release and merge. Publishing requires a separate request.
