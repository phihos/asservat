# Saved packet query: local service proof

Seven sequential owned service campaigns are preserved with their actual outcomes.
Every campaign reports 4,194 source hashes, independently compared to its exact
Git blobs: zero mismatches, unchanged sources and `cleanupFailures=[]`.

| Campaign | Source | Go/harness exit | Go seconds | RUN/PASS |
|---|---|---:|---:|---:|
| lifecycle-ffd43fe0 | `ffd43fe0` | 1/1 | 8.618 | 4/1 |
| metadata-account-fixed | `af101995` | 1/1 | 10.041 | 2/1 |
| metadata-binding-fixed | `5722a38e` | 0/0 | 13.764 | 2/2 |
| raw-binding-fixed | `5722a38e` | 1/1 | 14.588 | 2/1 |
| raw-cleanup-fixed | `b2759438` | 0/0 | 15.639 | 2/2 |
| upgrade139 | `b2759438` | 1/1 | 5.176 | 27/26 |
| upgrade139-prepared | `360ba3f6` | 0/0 | 7.945 | 401/401 |

All names have the `saved-packet-query-` prefix. Full sources, exact selectors,
result names and payload checksums are in `manifest.json`. Complete historical
shell environments were not captured. Passing provider logs were not produced;
the four original failure PostgreSQL reports are included.

The failures remain failures: the first exposed the missing four-unit account
increment and a second-root pristine-database setup error; the next exposed the
full key-binding table's old 16 KiB bound. The first raw campaign reached all
functional assertions but failed its role DROP cleanup because the owner admin
pool closed too early. Harness resource cleanup succeeded independently of that
Go cleanup failure. The first upgrade compared against a snapshot taken before
its historical preparation changed physical column slots.

The successful metadata/raw campaigns each retain the existing two-unit summary
and add one four-unit packet query with two paid read batches. Raw batches debit
24 KiB and one operation each against the same exact parent/child pool: 48 KiB,
two operations total. Same-batch replay adds no charge; a rejected insertion
rolls back the debit; a third batch is refused. The exhausted pool also refuses
a separate native use. The narrow current-grant predicate denies after verified
revocation. Original acquisition/observation spend and capture count stay fixed.

Actual compiled hub/key roles enforce their separate permissions. Each batch
consumes manifest/data/index SQL key roles once; both native and public batch
closures persist, with no active batch or native download session. Immutable
caller-key lookup, changed-digest denial and original deadlines remain checked.

The final upgrade preserves the prepared 138 baseline exactly across the actual
139 round trip: twelve functions, full column ordinals/order/types/nullability/
defaults, constraints, indexes, trust and absence of all four new helpers at138.
Historical preparation independently preserves the entire logical schema while
reporting slots `baseline_allocation_id:23->24`, `child_id:5->7` and
`source_ordinal:6->8`. Existing summary, comparison, timing, refusal, accepted
history and syscall upgrade branches remain selected. Retained new records
refuse downgrade separately in the lifecycle campaigns.

Packets, identities/current-source observations, Job/Pod/issuer inputs and native
join proofs are controlled synthetic component inputs. These campaigns exercise
SQL key authorization, not a production remote unwrap. They do not qualify
installed MCP/React delivery, collectors, worker termination/retirement, native
CLI parity or resource containment, and make no capacity-refund claim. The
reviewed `5722a38e` to `b2759438` difference is only fixture pool cleanup; the
`360ba3f6` difference is only two upgrade-fixture files.

All 18 payloads use deterministic gzip (`mtime=0`, empty original filename),
then were decompressed and compared byte-for-byte and by SHA-256. No native
plaintext fixture or binary is included. Root independently verified preservation before removing the duplicate
uncompressed repository outputs; byte-identical originals remain in the local cache.
