# Current recovery fencing for downloads

C-04's `RecoveryReader` projects the current primary-database installation trust row into a maximum five-second observation. Missing, suspended, recovery-blocked or stale fleet trust is unavailable. The projection identifies the immutable installation, issuer epoch and accepted source revision; reading it cannot clear recovery or refresh its source lease. The original source observation remains bounded to 30 seconds.

C-03's [context authorizer](download-authority.md) requires this state as part of the accepted download environment. It preserves the exact store/location and principal/client plus the environment deadline in `DownloadAuthority`. The environment also needs an independent current regional/processing/client restriction decision. That producer remains unfinished; the integration fixture labels its regional acceptance synthetic.

C-14's SQL download adapter requires both retention and recovery transaction guards for effects. The recovery guard's installation-to-permission-root association comes from private composition; a caller cannot select a different unblocked installation. Each reserve, batch start, content permit and metadata permit locks the installation trust row **before** the permission root, validates the exact epoch/revision and current state, and checks time again after blocking work. Holding a database lock never extends a proof's original validity. The accepted environment's storage location must match the verified catalog registration. Accounting, cancellation and audit completion can proceed without creating new disclosure authority.

The download SQL role can read and lock fleet trust, but cannot clear `recovery_blocked`, rotate `issuer_epoch`, change accepted configuration or extend freshness. Recovery activation, restore checkpoint reconciliation and protected installation provisioning remain separate unimplemented prerequisites. The tests seed completed activation explicitly; the new reader/guard must never be interpreted as a restore-clear protocol.

## Verification

Real SQL/S3/native HTTPS tests passed in `test/results/download-recovery-second-integration.log`; the archived `download-recovery-passed-custody.log` records 55.855 seconds. Its environment report records unchanged source, exit 0 and no cleanup failures. Tests cover suspended/blocked/expired trust, changed issuer epoch/configuration, an already prepaid content batch, caller-selected installation rejection, a lock waiter expiring without new spend and SQL role write restrictions. Existing quota races, retention fences and native file downloads still pass.

The first run rejected a test fixture that evaluated two separate clock timestamps around a strict 30-second database constraint. The fixture now uses one statement timestamp; neither the constraint nor production freshness was relaxed. Failure evidence is retained as `download-recovery-first-custody.*`.

This implements part of REQ-DB-005 and REQ-DLD-002/003. It does not qualify public ingress, regional routing, complete restore or a full end-user investigation.

## Capture and publication continuation

`EffectTransactionGuards` now composes the same private installation/root association with retention for context admission, verification and catalog publication. `artifact.RecoveryProof` is the shared bounded observation; C-04's `RecoveryState` aliases that value. The current proof stays separate from the user's collection/approval digest. Final transactions lock recovery before permissions and storage, and recheck its original deadline after blocking operations. Historical audit completion does not grant new work or access and remains separately scoped. Read-only facets may omit the guards; all effect methods reject an unguarded composition.

The regression first reproduced all three missing fences: a blocked installation could admit a new context and record/publish verification through these internal facets (`context-recovery-before-custody.log`). The corrected real SQL/S3/native HTTPS run passed in `context-recovery-after.log`, with unchanged source and complete cleanup. It also rejects omitted/wrong installation, issuer epoch and revision proofs. The full context-to-download fixture now uses one installation recovery identity throughout, rather than synthesizing an unrelated download installation. No production restore activation is implemented by this change.
