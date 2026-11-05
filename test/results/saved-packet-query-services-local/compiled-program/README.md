# Packet query nonempty-program SQL regression

The installed failure identified SQLSTATE 42702 in migration139's nonempty BPF
program digest checks: PL/pgSQL loop variable `i` conflicted with the generated
SQL column. A focused real PostgreSQL test reproduced that exact error before
the fix. Both digest expressions now qualify the generated column explicitly;
validation, authority and encoding limits are unchanged.

| Campaign | Source | Go/harness exit | Go seconds | RUN/PASS |
|---|---|---:|---:|---:|
| focused RED | `329a48fc` + regression test only | 1/1 | 0.092 | 1/0 |
| focused GREEN | `8fcd4963` | 0/0 | 1.147 | 27/27 |
| metadata lifecycle | `8fcd4963` | 0/0 | 13.526 | 2/2 |
| raw lifecycle | `8fcd4963` | 0/0 | 15.325 | 2/2 |
| upgrade139 | `8fcd4963` | 0/0 | 6.492 | 401/401 |

Each campaign reports 4,194 source hashes and unchanged sources. Every GREEN
hash matches its exact `8fcd4963c04f365e7efd52ec5624945e40e6c555` Git blob.
The RED has 4,193 matching `329a48fc` blobs and the single frozen regression-test
overlay preserved as a patch and exact hash in its environment report. All five
harnesses report `cleanupFailures=[]`. The harness uses TemporaryDirectory for
scratch; it does not emit a separate `scratchRemoved` fact.

The new direct test validates both metadata/raw source shapes with a valid
nonempty typed BPF program, empty-program controls and malformed instruction,
compiler/program digest and source negatives. The single return-accept instruction
is a controlled compiled-program value: this campaign does not invoke libpcap.
It exercises both SQL digest comparisons that empty programs skipped.

Both full-role lifecycles now use that nonempty program. They retain the existing
two-unit summary and four-unit/two-batch query, caller-key and immutable grant
checks, native/public batch closure and three once-only SQL key roles per batch.
The raw path reserves each actual batch ID against its exact parent/child pool:
24 KiB and one operation per batch, 48 KiB/two operations for two batches.
Replay adds no debit; failed batch insertion rolls back; current revocation and
shared download/query pool refusals remain checked. Original acquisition,
observation spend and capture-count snapshots are unchanged.

The pristine upgrade campaign exercises valid and invalid nonempty programs
before and after the139 Down/Up cycle and preserves its exact function/schema,
constraint/index and trust checks. Retained-query downgrade denial is separately
selected in the lifecycle campaigns. No production remote unwrap, real workload
capture, installed UI/MCP delivery, native CLI parity, worker termination or
resource-containment qualification follows from these local fixtures: their
Job/Pod/issuer/join and source payload inputs remain controlled synthetic facts.

All 11 original service reports, five source verifications, two handoffs and the
RED test overlay are preserved in19 deterministic gzip payloads (`mtime=0`, empty
filename). Every payload was decompressed and compared byte-for-byte and by
SHA-256 with its original. No native plaintext fixture, binary or private provider
input is included. Original uncompressed repository reports remain for Root's
independent preservation audit and cleanup. Commands, environment, exact source
identities and limitations are retained in the handoffs and manifest.
