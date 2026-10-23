# ADR-222 — Consolidate SQL credentials within the hub process

Date: 2026-10-23. Status: implemented; integrated runtime qualification pending.
Related: [ADR-177](177-hub-sql-connection-governor.md),
[ADR-215](215-hub-metadata-reader-role.md),
[ADR-217](217-api-execution-role.md).

## Problem and provenance

The installed hub opens separate SQL credentials for many adapters running in
the same process. A complete process compromise already exposes those mounted
credentials. The separation limits the privileges available through an individual
SQL injection or incorrectly composed adapter, but it also multiplies installer
claims, protected observations, receipts, projections, verification and pools.
The maintainer requested implementation with sensible simplification and rejected
speculative security benefits as a reason to stall development.

On the reviewed `17e0ff63` source, the public role producer creates 79 credentials.
Each fresh successful role performs three complete protected-current observations,
in addition to inventory opening and final checks. This is a source count, not a
measurement attributing runtime latency to those observations. ADR-219/221 changes
must be included in the final inventory before qualification.

## Decision

Use one ordinary public hub credential and one owner identity/routing credential.
Each gets the deduplicated exact union of its existing compiled grants, including
column-specific updates and full function signatures. Keep typed adapters and
their authorization, recovery, retention, processing, audit and accounting
transactions. Add no broad `ALL`, role membership, `SET ROLE`, SQL generation
from user input, administrator access or new service.

The ordinary public group includes the current hub duties except:

- Capture admission, journal, acknowledgement and intent reading: migration 52
  pins distinct role OIDs and checks `session_user`.
- Capacity profile reading: migration 54 pins its role identity, provenance and
  connection limit.
- Worker configuration reading: a download-plan transaction currently calls this
  reader while holding a connection, so its separate pool prevents self-deadlock.
- Browser settings: this is a worker duty. Remove its file from the public hub
  projection; do not include its grants in the public union.
- Browser cleanup: no runtime composition consumes this credential and no SQL
  role pin requires it. Retire it rather than provisioning a future credential.
  Keep the cleanup component and its tests; installed session cleanup remains
  pending and is not established by this removal.

The owner group combines enrollment, audit acknowledgement, activation, registry,
routing and native metadata reading. Its six-connection allowance remains
separate from ordinary public work. The separate installer/projection producers
remain: combining owner and public would save only one more credential while
requiring broader composition changes.

Publisher, federation, key service, collector and deletion credentials stay in
their existing processes. No evidence decryption key or administrator credential
enters the hub. The removed certificate-owner duty from ADR-221 must not survive
as an unused member of either union.

## Connections and lifecycle

Keep the existing 32 physical connections per hub process and existing governor:

| Pool | Maximum physical connections |
| --- | ---: |
| Owner identity/routing | 6 |
| Ordinary public work | 18 |
| Public resolution journal | 1 |
| Public resolution acknowledgement | 1 |
| Pinned capture admission, journal and acknowledgement | 3 total |
| Capture intent, capacity profile and worker configuration readers | 3 total |
| Total | 32 |

The three public pools share the same login; the existing resolution reservations
keep their audit connections available during ordinary pool saturation. Other
reads required by resolution still use the ordinary pool; this is not a guarantee
that a whole resolution request completes under saturation. Cold readers retain their
existing close-on-release behavior. Role connection limits cover the aggregate
pool maxima across retained processes plus the existing serialized verifier.
Installation budgeting counts physical connections, not the number of passwords.
No new scheduler, retry mechanism, configuration knob or pool framework is needed.

Use new permanent role ordinals and a changed compiled layout digest. Never adopt
or rewrite retained development credentials, their claims or receipts. Unsupported
retained layouts keep the existing explicit refusal. Installer unknown outcomes
remain uncertain; consolidation does not add replay or extend original deadlines.

## Accepted tradeoff and complexity assessment

An injection or adapter-composition flaw in ordinary hub work can reach the
combined ordinary privileges. The corresponding owner flaw can reach the combined
owner privileges. Current SQL is fixed and parameterized; this is an explicit
engineering tradeoff, not a claim that such flaws are impossible. Actual process
boundaries and database-enforced state transitions remain.

This affects every installation and ordinary hub request. On the reviewed source
it removes 41 credential lifecycles (79 public logins become 43, six owner
logins become one) and reduces 48 openable pools to ten, before
accounting for ADR-219/221. It adds zero services, listeners, dependencies, user
controls, lifecycle states or background work. It removes redundant credential
management while retaining the existing connection budget and recovery behavior.
Final counts, privilege checks and latency must be established on the integrated
source; no performance improvement has yet been measured.

## Qualification

Compare the final grant sets against the former exact compiled unions. Check
excluded process duties, retired role names, projection contents, aggregate role
limits and the unchanged 32-connection budget. Run real scoped SQL operations,
pool saturation/cancellation/cleanup regressions and existing transactional
refusal cases. Qualify installer provisioning and the public investigation journey
on frozen integrated sources, including ADR-219/221. The [component archive](../../test/results/resumed-c62e02ac-hub-credentials/README.md)
retains commands, exits, frozen-source hashes, preceding failures and independent
review. Focused contract, bootstrap and PostgreSQL adapter tests, integration-package
compilation and the spec, architecture and design gates pass. Kubernetes adapter
checks also pass on frozen sources (595.418 seconds). Real SQL role, pool and installed-journey qualification
remains pending on the integrated source; no native success is claimed here.
