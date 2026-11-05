# Packet query: audited Begin replay registration

A real compiled-role PostgreSQL regression reproduced the second installed
failure boundary: caller-key lookup succeeded, but strict `PermitQuery` refused
the new acknowledged Begin because no matching `context_query_call` existed.
The fix adds one explicit replay-call registration through that existing journal.
It retains strict current permission, recovery, retention, source, grant and C-08
checks, original normalized input MAC/version and immutable query identity.

| Campaign | Source | Go/harness exit | Go seconds | RUN/PASS |
|---|---|---:|---:|---:|
| metadata RED | `9bf84fcc` + five frozen overlays | 1/1 | 8.715 | 2/1 |
| metadata GREEN | `c6b87702` | 0/0 | 14.329 | 9/9 |
| raw GREEN | `c6b87702` | 0/0 | 16.922 | 9/9 |
| upgrade139 GREEN | `c6b87702` | 0/0 | 8.065 | 401/401 |

All GREEN campaigns independently match all 4,196 reported source hashes to Git
`c6b877026e416e3a457902bfd296282d9a8c4096`; sources stayed unchanged and
`cleanupFailures=[]`. The RED has 4,189 exact `9bf84fcc` blobs and five recorded
frozen overlays: Source's three application files, Root's strict C-20 test and
the regression fixture. Its patch and exact report hashes remain preserved.
Fresh Docker readback after the upgrade found no owned custody containers.
The harness owns TemporaryDirectory scratch but emits no separate scratch flag.

The GREEN services execute actual `PacketQueryReads.Begin` with the real query
ledger, current C-03 authority, recovery reader and acknowledged C-08 invocation,
after the original caller closes. Eight unused-effect traps prove replay does
not route, compile, plan, admit/observe a worker or read. It returns the same
query's pending/replayed association under the new operation and original bounds.
The invocation fixture deliberately refuses `CheckOutcome`: this is preparation
composition, not public serialization, delivery acknowledgement or installed
MCP/React qualification.

A first registration inserts one immutable call row and increments the existing
finite control counter once. Same-call registration changes neither. Exact
snapshots retain original query, root/workload/principal query accounting,
workers, batches, grant state and uses. The normal C-08 request audit still has
its ordinary cost; replay is not an unaudited free request. Existing current
transaction/retention-topology checks execute during registration, then strict
`PermitQuery` remains mandatory.

Tests refuse changed normalized MAC, MAC version, caller key/digest, client,
expired requests, poll masquerading and cancellation. A genuinely acknowledged
wrong-input Begin is refused by both the adapter and direct compiled-role SQL.
A replay call cannot create a read batch: both adapter and SQL purpose guards
require the original Begin or an admitted paid poll. The controlled raw
reservation used to test SQL refusal rolls back atomically without spend.
Actual parent-grant revocation also refuses registration while independent
request/authority proofs remain live.

Both services retain the old summary and new four-unit/two-batch query, current
grant checks, exactly consumed manifest/data/index roles, native/public batch
closure and retained-history downgrade refusal. The raw path charges each actual
paid batch ID 24 KiB/one operation, shares the exact parent/child disclosure pool
with downloads and preserves original acquisition/observation/capture snapshots.
Job/Pod/issuer/join and payload inputs remain controlled synthetic facts; no
production remote unwrap, real collector, worker termination or containment is
qualified by these service fixtures.

The pristine upgrade retains exact139 Down/Up function, schema, constraint/index,
trust and prior-feature checks, including nonempty compiled-program validation.
Auxiliary RED/GREEN, review and gate logs keep their original handoff scopes;
precommit/overlay runs are not retroactively attributed to the signed head.
The tagged/default helper compilation logs explicitly ran no tests and supply
compile evidence only. The earlier incorrect helper tag caused an ordinary
integration compile failure during development; that overwritten console log
was not retained as a raw original and is not recast as a passing behavior test.

All nine original service reports, four verifications, RED patch, handoffs and
bounded logs use deterministic gzip (`mtime=0`, empty filename). Each payload
was decompressed and compared byte-for-byte and by SHA-256. The manifest pins
every original and compressed size/hash. No native plaintext fixture, binary or
private provider input is included. Root independently verified preservation
before removing duplicate uncompressed repository reports; byte-identical
originals remain in the local cache.
