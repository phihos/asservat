# ADR-290 — One-shot regional profile streaming

Date: 2026-11-03. Status: implementation in progress; installed qualification pending.
Requirements: REQ-PRF-001–003, REQ-EVD-005/008, REQ-CAP fair storage,
REQ-DLD-001–004; S-05 increment 3.

## Decision and authority

The maintainer requires bounded capture, conservative storage accounting, native
artifacts, original authority and deadlines, and no automatic retry of uncertain
profiling. Per-part remote SQL journaling is an implementation choice of
[ADR-166](166-bounded-streaming-custody.md), not an additional maintainer requirement.
This narrowly amends that choice for a non-resumable Go endpoint acquisition
whose existing SQL execution and local start already commit exactly one connector
process. Generic `Ledger` streaming and its durable transition journal are unchanged.

Admission atomically reserves all four final-copy ceilings plus the complete
multipart data ceiling and one upload plus every possible part slot. Migration
00123 creates an unbound `custody_stream`; it grants no write authority. The
existing checked `PrepareAPIExecution` transaction binds its plan digest and the
actual accepted connector `ProcessEpoch` once. A node collector epoch, attempt
ID, later process, or retry cannot substitute for this writer. An unbound stream
cannot consume a generic streaming claim.

Protected connector composition creates one private in-process `StreamingState`
for one prepared profile artifact. It checks the exact registration and writer,
original context and `WriteUntil`, and uses existing sequential single-attempt
multipart operations. The state is bookkeeping, never authorization. The existing
committed start and one-use prepared artifact authorize at most one store.
There is no public journal factory, restart reconstruction, replay upload,
replacement writer, or automatic retry after an uncertain result.

The SQL row retains every temporary charge, even after successful storage.
This path does not call `ReleaseStreaming`: only existing separately audited
attempt cleanup may release charges after the exact writer is quiescent and
complete backend version/object/multipart inventories prove absence. Losing an
upload ID does not prevent prefix inventory. A cancellation or missing process
alone is not proof of remote absence. Verification still rereads the ciphertext,
checks the full native artifact and requires independent audit before publication.
HTTP cancellation does not prove the application's profiler stopped; preserve the
uncertain outcome and its spent execution.

## Complexity gate

1. Required path: every acquired profile above 8 MiB needs multipart custody;
   default Go CPU output limit is 16 MiB. This is a reproducible composition gap.
2. No maintainer-approved risk is reopened; authority, precharge, one-shot start
   and inventory cleanup remain required.
3. Helps ordinary profile captures; no fleet-wide task is added.
4. Reuses existing Asservat start fencing, sequential writer and full inventory;
   no new upload manager or retry layer.
5. Added credentials, network access, Kubernetes permissions and listeners: 0.
6. Added durable state: one precharged unbound-to-bound process transition;
   no fallback or reconstruction states.
7. Added operator configuration: 0.
8. Backend dependency: the same qualified conditional completion and complete
   multipart/version inventory as ADR-166; no additional component.
9. Saves `2*N+4` journal RPCs per write: up to 38 at the 128 MiB/17-part trace
   ceiling. Local bounded transition metadata is at most 16 KiB with one mutex;
   existing framing and multipart buffers remain separately budgeted. These are
   bounds, not measured end-to-end overhead claims.
10. Generic streams remain compatible. Downgrade refuses profile rows or unbound
    reservations that the old runtime cannot represent; it never discards spend.
11. Merely raising a cap skips required temporary accounting. The one-shot local
    transition adapter plus durable reservation/process binding is sufficient
    for this path; a remote per-part protocol adds no demonstrated benefit here.

## Required verification and limits

- Approved `liveProfile` admission requires the raw grant even when the optional
  all-recordings approval setting is off; pending/revoked grants reserve nothing.
- Exact frozen endpoint, native limit, timeout, target and original timestamps
  survive preview, admission and execution reconstruction.
- SQL reserves every final/temporary byte and object atomically; repeated
  admission neither doubles nor releases charges.
- Unbound attempts cannot start; first execution binds the actual process;
  replay and a replacement process cannot reset or replace it.
- Duplicate holder enqueue and `Store`, unknown create/part/complete replies,
  cancellation and expired deadlines cannot produce another remote attempt.
- Cleanup requires joined writer cessation and complete backend inventory;
  neither terminal status nor cancellation refunds storage early.
- Migration Up/Down restores prior functions exactly on representable state.

Local tests and real SQL/S3 components are distinct from installed qualification.
The full profile workflow still requires native acquisition, cancellation/Stop,
publication, raw result-access and native download qualification. None is implied
by the migration or the transition adapter alone.

## Component verification (2026-11-03)

`python3 scripts/test-custody.py --run
'^Test(ContextAdmissionWithRealServices|CustodyUpgradeSchemaWithRealPostgres)$/^profile-approved-admission-stream-binding$'
--result-name profile-admission-sql123-3` passed with real PostgreSQL and S3:
[terminal log](../../test/results/profile-admission-sql123-3.log),
[environment and cleanup](../../test/results/profile-admission-sql123-3-environment.json).
Sources stayed unchanged and cleanup reported no failures. It covers the raw
review gate, 16 MiB profile admission, final plus temporary precharge, replay,
unbound-write refusal, encrypted capture-intent audit, actual API preparation's
process binding and replacement refusal, and exact migration Down/Up restoration.
The target, reviewer and process observations are explicit synthetic inputs.

Run 1 exposed a fixture observation-time ordering error; run 2 reached admission
and exposed the product's obsolete below-16-MiB capture-intent audit ceiling.
The intent now accepts only the derived final reservation through the supported
128 MiB profile ceiling. Neither fix changes timestamps or allocation limits in
order to make an expired real authority pass. Required installed/native tests
above remain separate.

## Qualified capacity version

Migration 00125 adds the immutable `ContextHistory.ProfileProtocol` marker
`go-profile/v1` for newly qualified roots. Missing markers retain the exact
legacy Go/SQL compiler, root digests, child limits, dates and charged spend.
The migration changes no stored row. An unknown marker is refused, and rollback
refuses retained marked qualifications or root plans rather than shrinking
obligations. Fresh installer qualifications select the marker and must fit the
administrator's existing root envelope; no new operator tuning is added.

Each qualified record funds two native responses and four content windows:
one full 128 MiB trace and one separately admitted full response. This means
four key rows, twelve content unwraps, eight window audit objects and 267
owner transitions: fifteen preparation/observation/content claim and close plus
retirement transitions, and at most 252 lease renewals. A 64 MiB window has 64
fixed 1 MiB chunks; its first lease is bound by the original claim and each
subsequent chunk can consume one renewal. Failed reads terminate without replay.
Backup and WAL accounting use those same row/transition counts. Read funding is 311,164,928 bytes: four
73.1875 MiB conservative window bounds plus 4 MiB metadata preparation. Output
funding is 256 MiB. These are prepaid ceilings, not retries after uncertain work
or promises to refill spent resources. Typed per-session admission may reserve
less; ordinary evidence does not have to reserve a maximum trace session.

The custody child preserves authored evidence funding up to the per-record
maximum trace obligation: 136,740,864 final ciphertext bytes plus 135,266,304
temporary multipart bytes, and at most 22 objects (four final objects, one upload,
seventeen parts). Both byte and object limits are capped by the authored workload
slice; the compiler never rounds insufficient funding up. Existing record and
session ceilings stay unchanged. No additional storage, network request, role
or credential is provisioned by the marker itself. The larger root metadata and
key budgets are checked before a new qualified graph can be accepted.

Required evidence includes exact Go/SQL parity for both versions, maximum and
undersized workload slices, unchanged legacy function restoration on rollback,
and a refusal to roll back a retained marked graph. These arithmetic and
migration checks do not qualify installed profile acquisition or native delivery.

The installed qualification fixture uses a 128 KiB native transition WAL bound,
three WAL copies, a 64 KiB row bound, two backup copies, eight records per workload
and sixteen workload accounts. Its native reservation is therefore 113.625 MiB
WAL and 1.25 MiB backup per record: 909 MiB WAL / 10 MiB backup per workload,
14.203125 GiB WAL / 160 MiB backup for the full root. Relative to the incomplete
fifteen-transition calculation, renewal funding adds 94.5 MiB per record,
756 MiB per workload and 11.8125 GiB per root; backup is unchanged. These are
qualified conservative accounting ceilings, not measured WAL generation. The
fixture's 1 PiB envelope is synthetic and does not qualify small-install sizing.
There is no implicit production capacity default: the installer consumes the
operator's explicit qualification and finite envelope, and refuses an envelope
that cannot fund the complete graph. The complete installed fixture graph needs
184,074,240 SQL bytes, 736,296,960 backup bytes and 77,612,187,648 WAL bytes;
a regression accepts this exact finite envelope and refuses one WAL byte less.
A smaller record/account count reduces
this cost linearly. No additional poll, renewal, rate limiter, credential or
network call is introduced: the change funds existing successful-transfer
updates rather than failing a slow download after its fifteenth owner update.
