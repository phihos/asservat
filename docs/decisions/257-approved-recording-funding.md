# ADR-257: preserve authored packet evidence funding

Status: accepted implementation; installed approved recording remains unqualified.

The installed approval-required packet journey reached independent fresh approval
and submission after the production preview expiry, then returned
`CapacityUnavailable`. Its authored context slice reserves 39,714,816 bytes and
16 objects. The existing protocol compiler retains four records, but projects
only 6,176,768 bytes into custody using the pod-status unit. One supported packet
recording requires 9,928,704 bytes. A larger authored reserve therefore could not
fund even its first recording; this is a product projection defect.

Keep the original record count `n = min(bytes / 1544192, objects / 4, 512)` and
all object, metadata, key, native-read and audit quantities. Project evidence
bytes as `min(authored bytes, n * 9928704)`. The second bound is the existing
8 MiB recorder's complete ciphertext reservation, not a new output limit. Use
checked Go multiplication and numeric SQL arithmetic before the bounded cast.
Exact pod-sized context slices and root backing remain byte-identical. A legal
residual such as one pod unit plus seven bytes retains those seven authored
bytes; the historical floor discarded them. No additional
configuration, API calls, watches, credentials, components or runtime states are
introduced.

Migration 00100 updates the arithmetic helper and existing retained children in
one transaction. It exclusively locks the retained graph, validates its exact
historical shape and pool sums, and derives each new ceiling from the persisted
original enrollment. It changes only `custody_allocation.byte_limit` and the
matching `custody_pool.allocated_bytes` delta. IDs, revisions, used and uncertain
charges, object caps, receipts and all original deadlines remain unchanged.
The new ceiling cannot exceed either authored context funding or the closed
packet bound, and the pool must still cover the exact sum of its children.

Only the named allocation producer-ownership trigger is suspended for the one
UPDATE while its table is exclusively locked. All constraints remain active;
the trigger is restored and checked before commit. No runtime credential gains
DDL privileges or a bypass. Post-validation compares every other allocation and
pool field and the complete exact retained graph. A malformed predecessor aborts
without partial changes. The existing root renewal changes deadlines only and
validates the predecessor first, so it cannot repair this projection itself.

Down performs the exact inverse under the same checks. It refuses atomically
if existing charged bytes cannot fit the historical ceiling. It never deletes
an attempt, refunds uncertainty or changes evidence. Operators must retain the
new schema while such reservations remain. This avoids permanent legacy modes
or a new per-account marker. The schema head becomes 100. The existing binary
compatibility floor remains: old Go root arithmetic receives only exact small
slices, while workload consumers call the SQL helper dynamically. No stored
scope, public transport or approval identity changes.

Validation must include a real SQL legacy-to-new transition, unchanged small
children, malformed-graph rollback, successful unspent Down/Up and refusal after
an actual packet custody reservation. Synthetic source/qualification fixtures
prove SQL compatibility, not installed collection. The guarded installed journey
must still record, publish and download real native PCAPNG before that outcome
is qualified.

Complexity gate: one observed failure in the first complete delayed approved
packet submission; harmful because the supported workflow cannot start. No
accepted risk is reopened. This benefits the ordinary supported recorder path.
The smaller alternative of raising fixture quotas does not fix the product
projection. There are zero new runtime requests, permissions, credentials,
background tasks, configuration knobs or external dependencies. The only added
failure is an explicit atomic upgrade/rollback refusal for an inconsistent or
still-charged graph. Work is one bounded migration over existing retained
accounts; ordinary admission keeps its current queries and charges.

The subsequent installed run 40546623947 on 79694a43 again completed independent
approval and the real preview wait, then refused current facts before admission.
The explicit resolution operation safely closed that unstarted intent; it did
not report accepted work. The original public refusal code was discarded by the
fixture and the private facts/current label conflated several original bounds.
The fixture now retains only the public code and resolution state, while private
closed labels identify the existing failed bound or structural predicate. No
identifier, provider text, fresh retry, new tracing service or longer deadline
is added. Pure retained-recorder tests prove refusal then closure for expired
identity, recovery, target, capability and retention, with zero admissions and
an unchanged approved blueprint. These model the failure semantics; they do not
identify which bound expired in that installed run. The aggregate dependency
path must be assessed once the concrete bound is visible; no speculative
per-step refresh or limit increase is applied.
