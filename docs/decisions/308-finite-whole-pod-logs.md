# ADR-308 — Finite whole-pod logs and approved saved-log pages

Date: 2026-11-05. Status: implementation in progress; no installed qualification.
Scope: REQ-ACT-001, REQ-TGT-006, REQ-MCP-002, REQ-EVD-005/008; TASK-05/08.

## Problem and authority

Logs around an incident are an accepted product requirement. The existing log
signal detector retains counts, not a downloadable evidence artifact. The saved
`get_logs` contract promises redacted text and exact stdout/stderr attribution,
but no qualified redactor or stream-splitting capability implements those claims.

This record revises those design choices under the maintainer's standing
complexity/simplification delegation. It is an engineering decision, not a claim
that the maintainer directly selected these exact semantics. Whole-pod scope,
current permission checks, bounded sensitive disclosure and native download
remain explicit maintainer requirements.

## Decision

Implement one finite onTrigger `logs` action through the existing accepted
recipe, review, capacity, execution, custody, publication and history pipeline.
Acquire available regular, init and ephemeral container sources internally;
there is no public container selection or container permission surface. Current
and available previous sources share the same Pod/action byte and time budget.
Preserve original Pod UID, observed runtime/restart identities and the immutable
requested window, anchored to the original accepted incident/preparation time.
Before-context is bounded to24h and after-context to60s within the original
action timeout; history length is not a new wait interval. Unknown previous-instance identity stays unknown. Never adopt
a replacement Pod or describe a `previous` API request as a pinned old instance.

Collection uses the authored action's existing impact and protected approval
requirements. The builtin uses observe; raw classification alone does not add a
collection review. Sensitive authored actions or a protected RequireApproval
setting use the existing review/grant path. Raw page inspection always retains
its exact independent disclosure approval.

The portable API source combines stdout/stderr. Record `combined` provenance;
requests requiring exact stdout or stderr remain Unsupported unless separately
qualified capability establishes the split. Do not require a default-disabled
alpha feature merely to deliver useful portable logs. Kubernetes documents the
[split-stream feature and log retention limits](https://kubernetes.io/docs/concepts/cluster-administration/logging/):
split queries require the feature gate, the kubelet normally retains one previous
container, and the API exposes the latest rotated file. These limits prevent a
promise of complete pre-trigger history. The pinned PodLogOptions has no
UntilTime or Pod UID precondition; enforce the fixed end locally and recheck
original Pod/instance facts around collection. Missing, rotated, timed-out,
changed and truncated sources remain explicit gaps. If a post-read check detects
an original Pod or runtime-instance mismatch after bytes have streamed, abort
publication of that logs artifact; preserve other recipe actions. No plaintext
staging or whole-source buffer is added merely to salvage it. Matching pre/post
observations do not prove an atomic log snapshot or no intervening restart.

Keep original source bytes in a versioned streaming JSONL native file, including
invalid UTF-8, empty application lines, original timestamp prefixes and line
endings. Long lines use ordered bounded byte fragments. Missing or malformed
source timestamps stay nullable and never become invented event times. Record
requested log time separately from actual HTTP acquisition time. Bounds are
64 runtime members, at most128 current/previous origins, at most4096 decoded
bytes per fragment, at most8192 encoded bytes per record and64MiB native bytes
including framing/encoding. A successful empty response is distinct from an
empty line and an unavailable source. The decoder validates the full source,
record ordering, origin closure, counts and footer before disclosing a page.

Streaming acquisition cannot know the fetch completion instant before reading.
Use a logs-only acquisition store entry point with a joined completion callback:
the incremental checker receives the original start, then requires the actual
completion after EOF and the source identity postcheck. An ordinary close cannot
approve an unknown end. The verifier consumes the stored exact interval through
its existing mandatory native check. No future completion timestamp, full-source
buffer, second read or new durable journal is introduced. Existing fixed-end
Store/profile behavior is retained.

The query's canonical walk also binds the accepted header and every per-origin
fetch interval to the authenticated manifest. Continue these checks after page
selection stops or the cursor is invalid. This one parse retains full native
validation; it avoids an unnecessary second JSON decode of the same64MiB source.
Publication still uses its independent mandatory streaming checker.

`get_logs` returns raw saved-log pages, not purportedly sanitized extracts.
Require current evidence read/raw rights, retained audience and client checks,
and an exact independent `get_logs` grant. Reuse current parent/child issuance,
shared disclosure pool, original deadlines and keyed Begin replay. Each actual
read spends24KiB and one operation. A next-page Begin needs a fresh invocation
key; an uncertain same-key retry never repeats source work. Native download
retains its separate read/download authority and exact `download_artifact`
operation. A download grant never supplies raw page rights or vice versa.

Use typed source/version/fragment cursors, at most100 rows, a20KiB private page
and24KiB whole direct/nested public envelope. Text is untrusted; escape it in
React and never execute it. UTF-8 text and canonical base64 byte alternatives
preserve exact values. Page limits do not stop authenticated EOF validation.
Corrupt tail, changed source or cancellation yields no page. Stream64MiB via
existing authenticated frames/windows; do not raise every native type's8MiB
limit or allocate the whole artifact in memory.

The configured provisional budget is20 query units for two full source reads,
following existing64MiB profile accounting. This is a conservative configured
ceiling, not measured CPU or overhead; resource qualification must validate it.

## Complexity assessment

| Question | Answer |
| --- | --- |
| Frequency/harm | Common incident diagnostic; deployment frequency unmeasured. Current detector cannot supply retained surrounding log text. |
| Previously accepted risk | Sensitive evidence is already allowed behind bounded review. No direct maintainer requirement for arbitrary-message redaction or split-stream-only logs was located. |
| Typical deployment | Yes; uses ordinary finite Kubernetes logs rather than an alpha prerequisite or host reader. |
| Precedent | Kubernetes logs API and existing Asservat encrypted acquisition/raw-query pipelines. |
| Added privileges/exposure | Zero new credentials, RBAC resources, exec/host access or destinations. Existing pods/log reads carry raw text only to regional encrypted custody. |
| Failure states | Existing action outcomes plus typed per-origin coverage gaps; no fallback to host logs, replacement Pods or fabricated streams. |
| New machinery configuration | Zero. Existing action limits and administrator ceilings govern work. |
| External dependencies | Existing Kubernetes log availability, SQL, object storage and keys; no new component or package. |
| Aggregate cost | At most2C log GETs for C<=64 runtime members, plus bounded original-Pod checks; aggregate action bytes/time, not per-source multiplication. At most128 small origin states and one fragment buffer; at most64MiB source I/O and3 unwrap roles per paid page. HTTP and parser costs require measurement. |
| Upgrade/rollback | Extend existing native/accepted-plan/query/grant closed unions; no new ledger or role. Rollback refuses retained new-type state rather than misinterpreting it. Qualify migration and compiled-role reconciliation. |
| Smaller alternative | Download-only leaves accepted console/MCP inspection unfinished. A generic redactor or host collector adds complexity without establishing reliable guarantees. |

## Acceptance

Deliver actual finite acquisition, encrypted publication, approved MCP/React
pages, exact original native download, retained settings and fresh Repeat.
Verify whole-pod current/previous provenance, invalid bytes/empty/long lines,
fixed window, fair aggregate caps, missing/changed sources, cancellation, full
EOF/tail corruption, shared grant spend, idempotency, client/revocation refusal,
Stop and terminal cleanup. Qualify64MiB streaming and parser limits under measured
worker resources. Use real-role SQL/migration fixtures, built React and a fresh
installed workflow with same-original native parity. No component milestone
alone completes logs or the overall specification.

## Mixed recipes and current qualification limits

Reuse the existing composition-group journal for logs plus packet/syscall
children. Each child retains its actual capture ID, scope digest, action,
version and ordinal; an ephemeral independently resolved group-output association
connects it to the original reviewed parent. SQL revalidates that association
inside the existing materialization/use transaction and current key helper.
No parent/child relabeling, new persisted proof, table, role or broad key-reader
permission is introduced. A mismatching parent lookup can add one existing-row
read; ordinary standalone outputs retain their existing path and client pin.
Merged assessment rules bind the ordered actual children and preserve legacy
packet/syscall bytes. This expands contracts across existing layers rather than
adding another component. Parent-group Stop and unsupported profile/argument
mixtures retain their explicit existing limitations; they remain full-platform
work, not silently completed behavior.

The actual logs action timeout is accepted separately from the parent write
bound and applies once from the original API execution start. A retry never
renews it. Defaults and finite edits must not infer a minimum useful duration
from the Kubernetes client's five-second maximum HTTP timeout.

Local encrypted-reader experiments complete three near64MiB shapes with actual
framing/decryption, TLS ranges, full EOF and three key opens. Measured memory
peaks are118,747,136/162,729,984/174,628,864B under a256MiB declaration, without
OOM/swap. The process includes the synthetic TLS source; provider keys, accepted
authority and receipts remain synthetic. Although cpu.max declares500m, observed
CPU consumption is inconsistent with enforcement on this host (sched_ext/Lavd
is active). These results do not qualify500m runtime behavior. The optional
`make logs-resource-check` requires measured quota-consistent CPU use on a fresh
host, along with unchanged source hashes and cleanup. Final hosted qualification
and the installed user workflow remain pending.

The logs mechanism adapter belongs to existing C-23, alongside syscall/packet
adapters. C-24 analysis uses standard-library canonical base64 and bounded
in-memory JSON sizing for its closed values. The import gate explicitly permits
those pure utilities rather than introducing hand-written duplicate JSON sizing;
network, filesystem, keys, concrete adapters and third-party protocol types
remain outside domain code.

The mandatory C-21 publication check reuses the C-23 canonical logs codec. The
architecture gate permits only this package across that edge, preserving one
parser without allowing persistence to import privileged collector adapters.

Logs larger than one native frame reuse the existing multipart reservation and
process binding: reserve final and temporary obligations in the admission
transaction, then bind the original accepted API writer without refilling or
changing epochs. Small logs retain the single-frame path. Reuse the existing
large-native backing protocol (`go-profile/v1`); its name does not change the
logs parser or artifact type. The configured64MiB case requires136,740,864B and
14 objects including temporary obligations; these are conservative reservation
values, not measured stored output or overhead. A legacy record-only fixture
was insufficient despite spare general pool bytes and is corrected before
installation rather than topped up after admission.

The installed native-download authorizer admits raw logs only with both the
verified logs evidence kind and logs native type. Current ordinary rights, the
original retained audience and the existing result-access child remain required;
no share or cached response entitlement admits raw logs. This implements the
existing native JSONL requirement, without another grant or permission surface.


The native session plan uses the same registered-type download bound as the
framed response reader. The current large-window types are logs and pprof
(64 MiB maximum each) and Go traces (128 MiB). Reserve the existing 4 MiB metadata
preparation plus two complete responses: one 64 MiB window costs 76,742,656 read
bytes, independently of a shorter accepted native cap or returned range. Thus
logs and pprof reserve 157,679,616 read bytes; maximum Go traces reserve
311,164,928 read bytes. Output reserves twice the accepted native cap, with the
existing 4 KiB minimum: a 1 MiB logs capture reserves 2,097,152 output bytes;
maximum logs/pprof reserve 134,217,728 and maximum traces 268,435,456. These are
conservative charged-work reservations, not measured I/O, memory or overhead.

The six other current registered types (pod status, metadata/raw PCAPNG,
metadata/argument syscalls and HTTP headers) retain the existing 16 MiB output /
24 MiB read session ceilings. Administrator limits and separately accepted
allocation/control/key/audit backing must cover every new plan; a lower ceiling
refuses admission. Existing sessions, deadlines, spent metadata and uncertain
charges are never enlarged, reset or retried. This corrects the agent-authored
logs plan omission exposed by the installed 24 MiB session refusing its first
large-window response; it changes no permission, quota configuration or reader.
