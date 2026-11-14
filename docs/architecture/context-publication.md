# Context publication

C-14/C-15/C-21 under S-01/S-02 and TASK-03/07. Publication makes a stored
capture visible in the catalog.

## Publish on commit

The producer validates the native format before encryption and writes the
data, index and manifest objects. When it reports the stored outcome, the hub
publishes in one SQL transaction:

1. Check each object's size and ETag/checksum from a HEAD against the commit
   receipt and the accepted expectation (capture, attempt, scope, reservation).
2. Insert the catalog entry with the stored effective retention deadlines.
3. Write the audit row (D6) and `NOTIFY` capture progress.

The hub does not decrypt the artifact to publish it; AEAD detects corruption
when a reader decrypts it. A retry of the same outcome is idempotent on the
capture and artifact IDs. A failed check leaves the output stored, charged and
invisible until deletion.

The transaction locks only the capture's attempt and workload rows. Authority
was checked at admission ([ADR-311](../decisions/311-operation-authority-recheck.md));
publication checks the stored retention deadline and the capture's
cancellation state, not a fresh authority proof.

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
`maxCaptures`, before `notAfter`, unrevoked and at the accepted DebugPolicy
generation, and copies an ADR-235 instruction naming the acceptance.
`materialize_capture_share` records `evidence_share.policy_acceptance_id` and
materializes nothing for a revoked acceptance (it takes a KEY SHARE lock on the
acceptance row, which revoke-all locks FOR UPDATE). See
[ADR-239](../decisions/239-recurring-policy-sharing.md).
