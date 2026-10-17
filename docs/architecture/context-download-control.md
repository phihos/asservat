# Current context download control

C-14 now has a private typed `ContextDownloadCoordinator` for ordinary approved
pod-status preparation and status (REQ-DLD-002–004, S-02). It consumes request-owned
C-02 `CurrentIdentity`, the existing C-03 current download authority, C-07 accepted
transfer-plan input and the separately configured regional native-work port.
This is not a mounted browser/MCP service. Public cancellation, operation-audit
mediation, protected environment/allocation production, the actual regional
native-work channel and attachment relay remain required before public use.

## Original requests and initial startup

A preparation key is bound to the exact artifact and qualified operation. Lookup
uses original actor/client and recovery; a failed lookup is not absence. Private
artifact routing uses only the published ADR-109 locator and verified ciphertext
version. It discloses no native metadata and gives no permissions. Current whole-
pod download rights, retained audience, current retention/environment and recovery
precede the separate exact source reader. That reader checks accepted expectation,
publication/verification and the complete immutable custody copy set under the
existing transaction guards; it reads no file bytes or unwrap keys.

New sessions require a real configured regional runtime and accepted, backed
finite transfer plan. Missing runtime denies before reservation or worker effects.
There is no default capacity or fixture-backed production authority. The new key
is checked again atomically in `ReserveDownload` before locking a newly proposed
allocation. An existing request keeps its original session, allocation, limits,
deadline and spend even when today's plan differs or its proposed allocation is
absent; different scope/request under the same key conflicts.

Normal startup can outlast a five-second request-owned identity observation.
An acknowledged Preparing result permits bounded automatic **same-key prepare
POST continuation** while the initiating view and session remain active. This is
part of the original Download intent, not another confirmation click. The caller
must apply backoff, a finite retry/time ceiling and cancellation on view/session
loss; every new request obtains fresh identity and preserves the original session
and all budgets/deadlines. An uncertain response is not acknowledged startup and
needs original-key reconciliation. No retry invents a new key/session or refunds
read work. Status reads never initiate continuation. UI scheduling and the public
mapping of the internal continuation indication remain pending; no enabled flow
claims this orchestration exists yet.

`ContinueContextDownload` is an explicitly effectful private runtime port, called
only for an original session still Preparing and before its original transfer
deadline. Both source reads and continuation use a context bounded by that
deadline, rechecked after source I/O. An acknowledged continuation may
report startup pending or finish the paid preparation; an error cannot fabricate
Preparing success. Runtime implementations must serialize exact-session result
lookup/preparation and reuse actual dispatch identities. The current credential-
only worker command is not such an implementation.

## Immutable file facts versus fresh disclosure

`PreparedDownload` holds bounded immutable verified native metadata and its exact
scope/session/preparation batch identity. It is supplied only by an authenticated
regional native-work path. The intended one-result-per-original-worker/session
memory entry contains neither file bytes nor unwrap keys and has the original
worker/session/artifact lifetime. SQL stores no filename, native SHA or coverage.
The private [regional result owner](context-download-result.md) retains one
acknowledged preparation result before first delivery and checks fresh authority
when reading it. Its protected native-work channel/executable composition remains
pending; it is not an enabled production runtime.

The metadata facts do not expire when the first response's authorization lease
ends. `GetContextDownload` freshly checks current identity, rights, audience,
retention, environment and recovery, reads the existing regional result and asks
SQL for a new bounded observation. It never dispatches, prepares, unwraps, reads
S3 or changes spend. Returned read/delete dates come from the new current decision,
not the retained metadata entry. Final identity checks preserve a shorter current
deadline and deny group/scope/policy changes.

`ObserveDownload` checks current transaction guards and the exact immutable,
successful, acknowledged preparation outcome. Later content generations may use
the same verified native facts, including Streaming and Completed metadata. It
does not reopen the preparation batch, extend its old lease, authorize bytes or
mutate counters/state. The existing `PermitDownloadMetadata` remains unchanged:
it fences the initial worker response by the original preparation lease.

Ready/Streaming/Interrupted require verified metadata. Cache loss returns
explicit unavailable instead of a placeholder hash, incomplete Ready or automatic
re-decryption. Post-ready deliberate charged re-preparation is not implemented in
this step. Preparing status may omit native metadata; only the explicit prepare
operation can progress it.

Fresh authorized terminal status remains available after the transfer deadline,
without extending the worker, cache, key, artifact or session lifetime. Completed,
Cancelled, Failed, Denied and Expired return a terminal-only status without a
regional runtime/cache dependency. No native metadata is invented or re-decrypted.
Elapsed nonterminal sessions project Expired in the returned copy; SQL state,
active batches, counters and original deadlines are unchanged. Historical
Completed stays Completed. Same-key preparation replay routes these sessions to
that passive status path before runtime/source/capacity calls. Active prepared
replay likewise skips startup checks, retaining current verified-metadata checks.

Current identity, evidence rights, retention, environment, recovery and original
response freshness remain mandatory for every status response. Active response
validity is additionally bounded by the original transfer deadline. The private view retains current `AccessUntil` and `DeleteBy` independently of
optional native metadata, including terminal-only responses. A future public
projection uses current access for `managed_read_until` and may clamp displayed
`expires_at` to the earlier of that value and the original session deadline;
it must not mutate the persisted deadline or substitute a response lease for
artifact retention. Status cannot
renew any preparation/byte permit or revive Completed. The original five-second
worker response gate and all transfer-effect deadline checks remain unchanged.

## Ports, credentials and qualification

The new lookup/route/source/status methods belong to the existing SQL download
facet; no private table, migration, public schema or new dependency was needed.
The route reads the existing published locator, and source reads existing custody
receipts. The fixture grants only SELECT on `context_case_locator` and
`custody_copy` in addition to the existing download runtime privileges; the
protected production role assembly must provide these exact reads independently.
It gains no locator/copy/publication writes. The C-14 → C-02 architecture edge is
for request-owned identity as a consumer input, following the existing C-16 path.

Focused race tests cover normal same-key startup across the original observation
interval, configuration change, no reservation without runtime, lost replies,
original-key conflict, status/ready replay without another preparation, cache
loss/terminal non-revival, terminal status without runtime after transfer expiry,
source reads crossing the transfer deadline, final identity changes/cancellation
and deadline shortening. SQL adapter/domain packages also pass their fixture-free race tests.
The real SQL/S3 fixture now passes: it exercises actual publication, exact source
reads, rotated-plan and parallel replay, real encrypted native preparation, later
current observations after the old lease, active/Completed generations, wrong
receipt, expiry behind locks, terminal status after the original transfer deadline
and recovery blocking. The focused run in
`test/results/context-audit-download-focused-final.log` passed five selected tests
(download control: 20.996s), with 871 unchanged source hashes and empty cleanup.
The combined run in `test/results/context-audit-download-full-custody.log` passed
287 named entries in 139.453s, also with 871 unchanged hashes and empty cleanup.
Current identity/source/installation inputs and content-completion accounting
remain explicitly synthetic; no public transfer is claimed. These results qualify
the preceding coordinator/status implementation, not the newly staged regional
result owner or a native-work channel.
