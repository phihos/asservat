# Context publication

C-14/C-15/C-21 under S-01/S-02 and TASK-03/07. Publication makes a stored
capture visible in the catalog.

## Publish on commit

The producer validates the native format before encryption (headers-only or
capped packets, approved HTTP header values, schema checks;
[manifest verification](manifest-verification.md)) and writes the data,
index, manifest and commit objects with streamed SHA-256 checksums. Its writer
completion carries the copy receipts, the native size and, for Go profiles,
the acquisition window. When the hub records that stored outcome, the same SQL
transaction publishes:

1. Store the copy receipts and mark the attempt stored.
2. Insert the catalog row from the hub's admitted facts (target, capture,
   action, audience, deadlines) plus the reported copy digest and native facts.
   The INSERT triggers add the case/occurrence association, any capture-time
   share and the progress `NOTIFY`.
3. Settle the charge to the stored size.

There is no separate verification stage and the hub never decrypts the
artifact. Every read authenticates the commit, manifest, index and frames and
checks the manifest against the catalog row; a mismatch fails the read with
`Integrity`. A retry of the same outcome finds the row. The transaction locks
the permission root, allocation, attempt and capture rows in that order.
Authority was checked at admission
([ADR-311](../decisions/311-operation-authority-recheck.md)).

`RetainedAudience` reads joined catalog and accepted records and refuses
deleted or read-expired artifacts. The authorization evaluator checks the
principal, scope and denies first and intersects the original audience
afterwards; owner changes never rewrite the original audience.

## Capture-time share (ADR-235)

When the accepted capture carries a sharing instruction
(`context_capture.share_instruction`), the `materialize_capture_share` trigger
on the case-locator INSERT, which the catalog INSERT causes once per published
artifact, inserts one `evidence_share` row in the publication transaction.
Publication code gains no grant. The row binds the copy digest and the
locator's target; its expiry is bounded by the artifact's access end. An
expired instruction or no current management assignment skips the share
without blocking publication (`get_capture` reports `SharingUnavailable`). See
[ADR-235](../decisions/235-capture-time-sharing.md).

## Recurring policy share (ADR-239)

A policy executor's capture receives its instruction at admission: the
`claim_policy_capture_share` BEFORE INSERT trigger on `context_capture`
consumes one slot of the policy acceptance's `shares_spent` counter while under
`maxCaptures`, before `notAfter` (maintainer requirement of explicitly bounded
recurring-policy sharing; `notAfter` defaults to the evidence retention end
with no weekly renewal, ADR-335 D7), unrevoked and at the accepted DebugPolicy
generation, and copies an ADR-235 instruction naming the acceptance.
`materialize_capture_share` records `evidence_share.policy_acceptance_id` and
materializes nothing for a revoked acceptance (it takes a KEY SHARE lock on the
acceptance row, which revoke-all locks FOR UPDATE). See
[ADR-239](../decisions/239-recurring-policy-sharing.md).
