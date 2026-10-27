# ADR-255 — Encrypted parameterized capture history

Date: 2026-10-27. Status: implementation in progress; qualification below.
Requirements: REQ-HIS-001–004, REQ-PRV-008; S-04 increment 5, S-06 increment 12.
Migration 00100 follows approved-plan acceptance (00099).

## Requirement and observed gap

The maintainer requires every specified feature in the first release, including
repeatable capture settings and bounded private history. Those outcomes and their
privacy/retention rules are maintainer requirements. The mechanisms below are
engineering choices under the complexity gate, not additional maintainer demands.

ADR-236 reconstructs pod-status settings from an accepted scope, always returns
the pod-status recipe, and cannot restore recorder filters or windows. Recorder
history must use an immutable encrypted parameter snapshot; incidental execution
scope JSON does not become a new history parameter store.

## Decision

Reuse the existing four-object framed codec, three wrap-only key preparations,
version-pinned ciphertext receipts, custody allocations, and verified inventory
purge. A separate typed HistoryExpectation binds the accepted capture, original
execution digest, keyed selector/settings identity and independent storage dates.
It is control data, never a ContextExpectation, public artifact or fake execution.
No parameter plaintext, native hash, reason, grant or recipient list enters SQL.

The hub already receives authored parameters. It uses its existing protected
control-key seal/open facets under history-specific AAD and media type; evidence
keys remain unavailable to the hub. Ciphertext crosses the existing authenticated
outbound connector connection in a separate bounded frame family. Common frames
retain their existing bounds. No hub-to-regional-store reachability is assumed.
The connector receives a metadata-prefix-only object capability; evidence write
credentials remain write-only and no key is delivered to the collector or node.

Summary visibility and settings readability are separate from durable execution,
audience, accounting and audit records. History quotas cannot roll back capture
admission. Settings become available only after the exact immutable encrypted
snapshot verifies. Unknown writes retain their charges. Typed current signed
operation authority and independently established writer completion precede
physical cleanup; neither expiry, local Close nor a lookup refunds storage.

The existing immutable account-key projection supplies keyed selector/settings
identities, under distinct MAC domains. Ordinary audit-input key rotation does
not regroup history. A parameter snapshot preserves requested values, original
effective values, authored composition/edits, expanded recipe and dependency pins.
Repeat uses fresh eligibility, privacy, retention, budgets and any new approval;
old grants, sharing, reason and selected runtime members confer no authority.
Opaque repeat lineage has its own finite deadline and never grants source access.

## Complexity gate

| # | Benefit/cost | Answer |
|---|---|---|
| 1 | Observed harm | Every recorder repeat is currently unavailable; no production frequency claim. |
| 2 | Maintainer acceptance | History outcomes/privacy are required; this mechanism is an engineering choice. |
| 3 | Typical deployment | Yes: reuse of a manual filter/window is an ordinary investigation workflow. |
| 4 | Precedent | Reuses this repository's independently qualified immutable framed custody. |
| 5 | Added privileges | One prefix-only metadata storage capability per region; no evidence read/delete, new ingress, wrapping root or artifact unwrap. |
| 6 | Degraded states | SettingsUnavailable and HistoryUnavailable; reuse reserved/stored/deleting/deleted custody states. |
| 7 | Configuration | Required administrator-lowerable history ceilings; no self-tuning machinery knobs. |
| 8 | External dependency | Existing connector, S3 backend and KMS only; no new storage engine or component. |
| 9 | Aggregate cost | Four PUTs and four exact verification GETs per snapshot; three key wraps. Up to four GETs/three unwraps per settings read/repeat. Work scales with captures, never packets/Pods. Retirement uses existing version/upload inventory and bounded sweep. Counts and combined workflow cost require native measurement. |
| 10 | Upgrade/rollback | Additive schema; old pod-status history remains compatible. Stopping new history writes cannot abandon retained cleanup or charges. |
| 11 | Smaller alternative | Plaintext parameters, uncharged objects and durable audit retention violate the accepted contract. A single-object ledger would add a second lifecycle instead of reusing four receipts. |

Registration has no purpose-specific role bounds. At a 128 KiB parameter limit it
reserves **1,671,168 bytes (1.59375 MiB)** and four object slots: about 159 MiB
for 100 snapshots, 1.56 GiB for 1,000 and 155.6 GiB at the installation ceiling
of 100,000. These are conservative reservations, not physical measurements or
capacity promises; insufficient history capacity leaves collection functioning.
Do not change shared registration digests/retirement rules solely to shrink this
bounded over-reservation before a measured capacity problem exists.

## Qualification

Synthetic real-Tink component run `history-parameters-component-1.log` passed
round trips, exact ciphertext/manifest/expectation substitutions and bounded
bundle decoding. For 482 / 33,214 / 123,326 parameter bytes it measured 3,708 /
36,652 / 126,763 physical ciphertext bytes, and 4,961 / 48,885 / 169,037 encoded
bundle bytes. Each round trip used exactly three wraps and three unwraps; no
payload entered the key service. Key wrapping was an explicit test-only adapter,
so these are codec costs, not native provider or installed workflow measurements.

The history-specific role limits (192 KiB data, 4 KiB index, 128 KiB encrypted
manifest, 32 KiB commit) fit within a 512 KiB base64/JSON bundle. Both endpoints
must enforce it before allocation, including exact four-object cardinality.

SQL, protected provider/connector composition, actual retirement and full
filter/window repeat qualification remain pending while implementation proceeds.
