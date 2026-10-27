# ADR-255 — Encrypted parameterized capture history

Date: 2026-10-27. Status: implementation in progress; qualification below.
Requirements: REQ-HIS-001–004, REQ-PRV-008; S-04 increment 5, S-06 increment 12.
Migration 00101 follows approved-recording funding (00100) and approved-plan acceptance (00099).

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
admission. Settings become available only after four acknowledged, version-pinned
receipts bind the exact sealed input and its manifest commit. This is advisory
settings availability, never an evidence verification or publication verdict.
Before returning any plaintext or preparing a repeat, the reader verifies all
four objects, the authenticated manifest/commit and the keyed settings identity.
There are **zero eager verification GETs** on the write path. Unknown or incomplete
writes remain unavailable and charged; corrupt reads return unavailable without
reconstructing parameters from plaintext execution scope. Typed current signed
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
| 9 | Aggregate cost | Three wraps and four PUTs per snapshot, zero eager verification GETs; four version-pinned GETs and three unwraps per settings read/repeat. Each preview still uses the existing current identity, workload, capability, permission, retention and capacity checks. Added SQL transactions reserve history quota/custody, claim a selected regional writer and settle its receipts; reads authorize before and after remote/KMS work. One supervised, joined cleanup loop per hub checks a small SQL candidate page every three seconds (0.33 idle SQL reads/s/replica, zero idle API/KMS/S3); it processes at most 16 records serially, drains successful full pages and paces failures. Retirement inventories object versions/uploads and deletes them before typed completion/refund. Work scales with captures, never packets/Pods. Combined installed workflow latency remains to be measured. |
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
manifest, 32 KiB commit) derive an exact **486,077-byte** JSON/base64 bundle bound:
13 JSON punctuation bytes plus `4 * sum(ceil(roleMaximum / 3))`. Both endpoints
enforce the total and each encoded role before allocating decoded ciphertext,
including exact four-object cardinality. The existing common 32 KiB frames are
unchanged. Only signed history operations use the separately derived finite
authority, bundle and escaped receipt envelope bounds.

The prior schema-100 history checkpoint’s focused real PostgreSQL/S3 run
`history-parameters-native-10` passed encrypted
write/read, own-selector eviction without premature refund, ordinary evidence
deletion-path refusal and actual history-prefix inventory before charge release.
It measured **4,214 physical ciphertext bytes** against **1,671,168 reserved
bytes** for its synthetic parameter record. The selected subtest took 7.67 s;
the Go fixture took 9.142 s, with unchanged relevant sources and no
cleanup failures. This is component evidence, not installed recorder performance.
Runs 9–10 additionally cover positive persisted lineage, source-expiry extension
and unknown-source refusal, nanosecond request-deadline normalization, required
encrypted snapshots with no scope fallback, and settled projection/counter
pruning. Runs 1–5 exposed fixture role/eligibility/time issues and a production
registration normalization mismatch; run 6 passed the initial custody slice.
Run 7 found a source-read fixture permission omission. Run 8 reproduced a real
ordering bug: per-selector eviction hid the chosen source before the new
snapshot's source check. Source authority now precedes eviction in the same
locked transaction, and its original expiry bounds the final check. All earlier
actual failure reports remain retained alongside runs 9–10.

## Composition and independent lifetimes

`public_context_compose.go` composes the existing protected account-key MAC and
control sealer/opener with the typed SQL history facet and regional dispatcher.
The dispatcher uses the existing outbound `contextstart.Router`, selecting the
actual executor epoch before SQL issues a writer claim. The regional adapter uses
its separately projected `history-storage.json` capability on the existing store
and bucket, restricted to `history/v1/<root>/<cluster>/`; it cannot access evidence
or another root/cluster prefix. No hub S3 address or evidence credential is added.
The provider recipe proposes the exact prefix policy; existing external provider
provisioning remains administrator-owned.

Metadata policy uses the existing explicit case-metadata defaults/maxima and
general privacy restrictions, independently of evidence lifetime. New history
never uses scope JSON as parameter storage. Source-derived repeats retain their
original content cutoff and policy origins; rereading or repeating cannot renew
that deadline. Lowered quotas hide oldest history only from the originating
allocation, with physical obligations retained until verified cleanup. Original
summary deadlines and unknown writer spend are never rewritten to meet a lower
limit. Expired, fully settled projections and unused zero counters are pruned in
bounded pages; durable execution/audit records remain independent.

A deterministic scheduling audit also found that always retrying the first 16
due records would starve another region behind a persistently unavailable one.
This is a reproduced algorithmic case, not a measured production outage. The
existing indexed capture-ID keyset and one process-local cursor now advance past
failed candidates, including partial passes stopped by the original budget, and
reset at the end. The hint grants no authority; every candidate still needs its
own current SQL authority and exact completion. No retry map, durable phase,
extra request, configuration or overlapping pass is added. Deterministic
two-region and partial-pass regressions verify both progress and retained spend.

The first 100,000-row real-SQL probe found two complete scans behind the bounded
16-row output: 64.47 ms for an idle hint and 62.82 ms with one due row. These are
synthetic minimal TEMP columns and warm local storage, not production CPU or row
width measurements. An indexed UNION of four separately bounded 16-ID branches
selects at most 64 IDs before deduplication and the unchanged 16-row keyset/order.
The fourth probe passed old/new equivalence for 81 IDs across six pages. Its
original predicate took 67.54 ms, the UNION without active indexes 10.65 ms, and
the custom plan with two partial active-state indexes 0.049 ms. The third probe
also exposed a real cached generic-plan regression: about 0.54 s after the fifth
execution despite a fast custom EXPLAIN. Only this read-only hint now uses pgx
CacheDescribe through a scoped DBTX wrapper around the generated query; pool
policy and all effect transactions remain unchanged. Ten repeated actual adapter
calls past that transition took 0.605–0.958 ms; EXPLAIN was 0.033 ms and the named
generic-plan counter did not advance. This sends about 3 KiB query text per
three-second idle request instead of retaining the demonstrated half-second scan.

Each new partial index occupied 90,112 bytes after 1,000-row churn; the existing
summary index occupied 6,144,000 bytes. For 1,000 minimal TEMP rows, history insert
time changed from 9.17 to 10.81 ms, available transitions from 10.90 to 11.86 ms,
and hiding from 9.20 to 11.04 ms. The unrelated custody insert measurement varied
from 4.57 to 108.29 ms; it is retained, not attributed to history indexes.
These local warm TEMP/no-WAL probes are neither production latency nor installed
aggregate cost. All four reports, including failures, are retained; run 4 had
actual exit 0, identical source hashes and no cleanup failures. No cadence,
authority check, durable state, privilege or configuration changes for this fix.

## Large browser settings

The shared MCP result contract remains 24 KiB (and the MCP socket writer 64 KiB).
Only authenticated browser `get_capture_settings` receives a private server-owned
160 KiB prepared-response budget and fixed client read cap. It uses the same
current authorization, existing public audit lane and original source deadlines.
Canonical JSON is written directly, so HTML-sensitive/multibyte strings cannot
grow through a second HTML-escaping serialization. Snapshot admission already
bounds the initial escaped JSON to 128 KiB before canonicalizing it. The audit
contains only existing HMAC/count/references; its encrypted record cap stays
64 KiB, and general digest/output limits remain unchanged.

One settings invocation performs four history GETs/three unwraps, plus its
existing two public audit records (two PUTs, two exact GETs, two wraps and two
unwraps): **2 PUTs, 6 GETs, 2 wraps, 5 unwraps**, excluding current authority SQL/API
work and later audit retirement. Each later audit deletion certificate adds one
PUT/GET/wrap/unwrap. A proposed 17-call fragment protocol would instead require
34 audit PUTs, 102 total GETs, 34 wraps, 85 unwraps and 17 sets of current checks,
plus 17 later certificates. The fixed browser budget avoids that protocol,
additional reads and failure states without persistent plaintext or a new lane.

## Restore boundary

The existing recovery reader/transaction guard fences a restored database
incarnation; it does not inventory an entire object store. History reads require
both the typed available header and generic `stored_unpublished` custody state,
four current receipts, original dates and current recovery/permission/retention.
Missing, pruned or expired headers cannot authorize a read/repeat or a scope-JSON
fallback. Generic deleted attempts keep their independent no-second-refund
tombstones. A restored old header still references its original attempt/dates;
an orphan object's fixed `history/v1/` key identifies its storage purpose.

Implemented inventories cover per-attempt object/version/upload cleanup and
separate purpose-specific audit diagnostics. Global reconciliation of every
recognized prefix after backup/restore remains an existing platform gap; this
change does not claim to supply it or complete backup-horizon qualification.
No extra permanent purpose/mapping field or personal routing marker is retained
solely for a hypothetical future inventory mechanism.

Current unit/race regressions cover fresh workload Pod selection, exact explicit
Pod refusal, original filter/window/composition restoration, edited retention,
collector/compiler drift refusal, policy current-Pod selection, final authority
and expiry shortening during reads, and cursor audience/target/deadline binding.
Full installed browser/MCP capture→settings→repeat qualification remains pending.
