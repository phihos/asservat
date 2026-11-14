# ADR-310: Finite approved live observation

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

> Superseded in part by ADR-328 (2026-11-13): The delivery policy is mounted
> configuration read under RBAC, not a guarded protected source; changing its
> root numeric settings needs an ordinary restart. Viewer authority, source
> bounds, minimized SQL accounting and the live delivery design remain valid.

Status: implemented; component, real-service and installed policy/manual qualification passed. Wider environment and sustained-operation qualification remains open.

## Decision

Implement REQ-LIV-001–006 through C-13 and the existing authenticated
node/regional/owner delivery channels. A view observes exact already-accepted
ongoing source epochs or an independently admitted, still-running finite manual
recording under its actual original regional/node holder. Opening, filtering, pausing, reconnecting and closing do
not acquire data, change capture filters or snaplen, pin a ring, renew source
rights or save evidence. All three approved projections remain required:
packet metadata, syscall metadata and the existing qualified HTTP-header
sanitizer on an explicitly HTTP-capable ongoing source. Finite manual HTTP
acquisition is not proof of that ongoing source capability.

Use the existing closed named `target_ref` for passive source inventory, with
current whole-pod UID resolution. The older unimplemented `target_handle`
proposal would require another public preparation operation and handle store
without adding authority. Source handles remain opaque, principal/client-bound,
at most sixty seconds, and never authorize a replacement Pod or source.

Keep at most sixteen original source references and sixteen typed display
predicates in the owning process's bounded memory for the original watch
lifetime. Clear them on joined close/expiry. No detailed scope, filters or
projected rows enter SQL, URLs, logs or audit bodies. Existing authenticated
encrypted transport carries those private details. SQL stores only minimized
control identities, fences, original expiry, aggregate accounting and a domain-separated
target-cluster digest for the exact per-cluster viewer gauge; it stores no raw
target, source, workload or principal scope. An active pre-mapping watch makes
that gauge unavailable rather than assigning it to the hub owner's cluster. Existing
persisted evidence/control references retain their encrypted-storage contracts.
Do not add same-heap-key encryption to ephemeral scope/filter memory: it does
not protect against a process that can already read both key and plaintext.
These are engineering revisions of earlier agent-authored prose under the
maintainer's security proportionality instruction, not new user decisions.

Use original kernel MONOTONIC/BOOTTIME timestamps and boot identity. Qualify
placement with the original finite authenticated exchange bracket and a remote
same-clock sample. Arrival time is not observation time. Unknown or stale clock
mapping excludes a row and reports `clockUncertain`. Expiry uses the earliest
possible observation plus thirty seconds and all earlier source/view/authority
ends. Replay adds a five-second limit. Authenticated cursors distinguish a valid
lagging position from a forged or foreign cursor; recovery starts at the current
head with a gap and cannot backfill expired rows.

## Cost and limits

The initial implementation adds one C-13 owner, five already-specified public
operations, and finite private delivery on existing channels. It adds no daemon,
broker, dependency, credential, public listener, privileged probe or per-row SQL
or object-store write. Limits remain sixteen sources, one hundred rows and
24 KiB public output, 500 rows/1 MiB browser memory, thirty-second row/idle
lifetimes, five-second/1 MiB replay, and original finite duration/output budgets.
Installation/principal/workload and node processing/subscription ceilings are
independent of source rings and incident work. Missing operator qualification
or projection capability stays unavailable.

Existing HTTP reassembly has a bounded sixteen-MiB profile; sixteen such sources
could require 256 MiB before ring and viewer reservations. An ongoing HTTP source
must reserve its original observation/reassembly work before collection, and
viewer work separately. It cannot raise snaplen or claim an unmeasured overhead
percentage. A smaller two-projection implementation is useful during construction
but does not fulfill the complete accepted live workflow.

## Verification scope

Focused domain, current source/viewer authority, bounded C-13 replay/closure,
public audit, metadata adapter and React tests are local component evidence.
Local production composition covers owner routing, source-clock placement,
SQL aggregate accounting and ongoing HTTP snapshots. Real PostgreSQL/S3/OpenBao
ledger, upgrade, manual-source and HTTP-source fixtures pass. Installed native
runs 42542873758 (policy) and 42542876337 (manual) at `beff40d2` pass packet,
syscall and HTTP projections through real C-03/SQL/owner/node delivery to MCP
and React, including separate HTTP Save/download and joined manual cancellation.
Both artifacts record unchanged sources and complete cleanup
([policy provenance](../../test/results/live-observation-policy-native-42542873758/README.md),
[manual provenance](../../test/results/live-observation-manual-native-42542876337/README.md)).
These named fixtures do not qualify wider CNI, grouped/argument/peer or
sustained-operation profiles.

The live read uses a distinct closed purpose on current authenticated channels.
Peer authentication supplies transport identity, not a viewer permit: composed
C-03 checks and the current accounted view owner/fence precede data dispatch;
regional/node consumers preserve original source/lease/processing ends, and
joined callbacks plus current final checks precede disclosure. Passive Head
reads do not activate a cohort. A data read performs one bounded source-node
request per selected source (at most sixteen, joined under the same original
request), no provider signing or Kubernetes request per row. Current source
and watch accounting checks remain per operation. Reusing the acquisition JWS
signer for each read would add provider signing plus before/after trust reads;
that additional mechanism has no demonstrated benefit over the composed permit
and existing current encrypted channel. Acquisition signing is unchanged.

Live node uploads take only spare tokens from the existing upload budget and
never join an incident's waiting queue. They leave the existing maximum whole
packet result (8 MiB) available as an incident burst; a smaller configured burst
makes live delivery unavailable rather than raising it. Encoded live body plus
4 KiB is a conservative accounting charge, not measured TCP/TLS traffic. The
source callback has independent operator event/byte/elapsed-processing credit;
viewer saturation drops metadata and does not backpressure acquisition. Regional queries group the selected sources by their original regional process.
Sixteen sources on one process use one grouped query; distinct original processes
require up to sixteen joined groups under the same deadline and unchanged
standby ceiling. This does not reserve sixteen standbys on one process.

The existing collector defaults are a 64 MiB upload burst and 32 MiB/s refill.
After the 8 MiB finite-result reserve, live can use at most 56 MiB initial spare
credit and shares the unchanged refill. Per-watch/ancestor rates and qualified
node processing limits constrain live further; this is configured token
arithmetic, not measured sustained throughput. Profiles debit streaming reader
chunks; packet/syscall finite results debit their at-most-8-MiB whole native
body. Live cannot consume the reserved whole-result burst.

Source references are stateless, domain-separated MACs bound to the installation,
current principal **and client**, exact immutable source version and original
expiry. Mint the at-most-sixty-second reference once, clipped to the original
source hard/privacy end. That passive reference lifetime is separate from the
five-second current-authority observations: decoding/replay never creates another
sixty seconds, and every Open/read/effect checks current identity, source,
audience, executor and original bounds. No reference table or lookup RPC is added.
The shared principal accounting key excludes ClientID, so console and MCP for the
same issuer/subject/kind share slot and byte ceilings; reference, watch, cursor and
idempotency ownership remain client-bound.

The existing protected delivery policy has one optional `liveRead` capability.
Missing means disabled. It has explicit projection/client/path decisions, root
aggregate watch counts and byte burst/rate, and cluster ceilings with namespace
and workload lowerings. It grants neither ordinary source rights nor native
artifact download, and does not replace an HTTP source's original reviewed
observation grant. A source ring has no selected evidence store yet; one
unambiguous installed path for the source cluster and explicit live client is
required, with the existing actual acquisition/connector/hub region pins. No
caller store or alternate placement is accepted. Root numeric settings are
fixed for the process's SQL accounting; changing them requires a restart.
Scoped lowerings are checked on each phase and can end an existing view.

There is no second startup numeric block, new ConfigMap, role or watcher. The
root byte rate/burst supplies all three ancestor buckets; separate principal and
workload slot counts and per-watch scoped rates still apply. Earlier distinct
candidate bucket defaults are not implemented runtime settings. SQL account and
control-record ceilings remain fixed internal bounds. Configuration is checked
in the first Open transaction after the original current owner proof; it cannot
require a serving certificate before runtime enrollment has started. Identical
configuration does not rewrite the row or reset debt.

Source-independent policy/recovery checks are batched per authorization phase:
at one or sixteen sources, a phase reads protected policy twice and recovery
twice. The independent final post-node phase repeats them, for four plus four
common reads total, rather than multiplying them by the number of sources.
Per-source Pod entitlement, original audience, exact accepted source/executor
and any original HTTP grant checks remain source-specific. This is request-phase
reuse of original observations, not a background cache or authority crossing
phases. Inventory avoids a second exact source SQL lookup after its protected
scan. Existing source-status batches have eight sources per private frame;
sixteen sources use two existing exchanges, with no per-source fallback retry.

Finite manual sources use the original accepted capture/attempt/action,
expectation digest, actor/audience and started execution. SQL's execution
`NotAfter` is preparation history, not the source end. The original regional
holder checks those pins and its actual node work; passive node inspection
returns only the observed capture/work/Pod/node/boot/collector tuple, original
start/hard end and any real sensitive-session reference. The regional consumer
binds these observations to its original accepted request, checks the original
accepted duration and queued/write bounds, and retains those exact times on
later reads. Metadata captures have no invented observation session; raw packet
and syscall-argument captures retain their distinct original permits. No saved
human token/group reconstruction or policy acceptance is fabricated for manual
sources. This corrects an initial agent scaffold, not a change to viewer rights.

The manual SQL consumer uses one bounded accepted-work batch and one recovery
read per phase. Holder inspection and row delivery each make one logical node
request per source (two/thirty-two for one/sixteen sources over the two checks).
These are not measured HTTP RPC counts: the existing NodeChannel poll may carry
up to sixteen queued items, while each result currently uploads separately.
Sixteen sources on one node therefore have sixteen result uploads per check;
sixteen nodes have one each. Regional grouping follows the original executor as
above. Owner forwarding separately measures eight registry observations and
seventy-two nominal query calls independent of one/sixteen sources. Availability
of their combined real-service path within the original five-second public
operation is still a qualification requirement; component timing does not prove it.

The console's dedicated `/live` entry uses the existing named-target form.
Navigation and target confirmation do not list sources or open a watch; session
shell checks remain separate. Source discovery is explicit, bounded to twenty
rows per produced page under the existing 24-KiB envelope, with opaque backend
continuation. Filter exclusions are explicit counted gaps distinct from sensor
loss. Row selection freezes only the viewer's inspection and clears with original
row expiry. A batch larger than a watch's accepted replay-memory cap is delivered
once without retaining it for replay; no row is trimmed and no debit is refunded.

## Aggregate complexity check

1. This closes a required first-release observation workflow; no incident-rate
   estimate or runtime performance benefit is claimed from synthetic fixtures.
2. The accepted workflow remains approved projections only; existing accepted
   source/privacy bounds and separate Save review are unchanged.
3. Existing ongoing and active finite recordings are typical supported paths.
4. Existing finite projections, authenticated channels and bounded SQL accounts
   are reused; no novel broker or parser is introduced.
5. Zero new collector credentials, public listeners, external services or host
   privileges; SQL adds minimized control/accounting under the existing role.
6. The existing finite state model includes unavailable, disconnected and terminal
   outcomes explicitly; missing capability cannot silently acquire a replacement.
7. One optional protected delivery capability supplies its ceilings; no duplicate
   startup numeric settings or self-tuning background mechanism.
8. Existing Kubernetes/SQL/node clock and channel behavior remain dependencies;
   unsupported or unqualified observations fail with truthful gaps/unavailability.
9. At most sixteen references/predicates, 100 rows/batch, 20-KiB private output,
   24-KiB public output, 500 rows/1 MiB browser memory; fixed/common and per-source
   call counts are recorded above. No per-row SQL/object write or provider sign.
10. Migration143 ordering follows process142 and must be rebased/reviewed before
    real-service qualification. Disablement is missing/disabled liveRead; original
    source recording, retention and historical cleanup remain independent.
11. Two projections or policy-only sources are insufficient for the accepted
    workflow. Reusing existing explicit HTTP sources and actual manual holders
    is smaller than a parallel acquisition/session system. Qualification remains
    required before runtime enablement is described as complete.
