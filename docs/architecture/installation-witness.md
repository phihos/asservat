# Installation witness component

[ADR-097](../decisions/097-one-use-installation-witness.md) supplies a private
one-use installation record for REQ-DEP-005 and REQ-DB-005. It does not activate
the database or clear ADR-096 recovery fencing.

[First-installation activation](initial-installation.md) now supplies the separate
SQL/audit coordinator. Production provisioning and restart/restore coordination
remain unfinished; witness consumption alone still grants no activation authority.

## Ownership and interfaces

C-04 owns `InstallationWitnessReader` and `InstallationWitnessConsumer` in
`internal/application/fleet`, with immutable attempt values in
`internal/domain/fleet`. C-21 implements these ports in
`internal/adapters/kubernetes`. Wire DTOs live in `internal/contracts`; the
[closed private schema](../../specs/contracts/installation-witness.schema.json)
is mirrored into the permission-reader schema bundle.

The read port returns the exact pinned scope, optional consumed claim,
resourceVersion and original observation deadline. The consume port accepts one
finite claim and returns the independently observed persisted result. Neither
returns `RecoveryState` or offers creation, replacement, reset or SQL writes.
The installer data/admission builders are inert helpers, not startup hooks.

## State and authority

The sole `witness.json` ConfigMap data member contains installation/epoch/writer
identity and a null or exact immutable claim. Claims bind attempt UUID, PostgreSQL
start time/OID/schema version, accepted source revision and plan digest. Canonical
UTC timestamps retain microsecond precision; the attempt interval is at most five
minutes. The complete native object is bounded to 32 KiB and its record to 8 KiB.
No credentials or evidence contents belong in this record.

The state transition is `fresh -> consumed + immutable` in one native conditional
UPDATE. Native UID/resourceVersion concurrency selects at most one persisted
claim. Admission restricts writes to pinned administrators including the dedicated
writer account. The consumer must additionally prove its exact account UID and
current named UPDATE permission. Its production RBAC must omit create/delete;
ordinary readers and a separate non-administrator admission probe have distinct
purposes. Credentials available in one process are not an isolation boundary.

Read/consume use current admission proof and final exact guard/namespace checks
within the original five-second interval. Missing/replaced/deleting objects,
unavailable protection, malformed data and unexpected immutability deny use.
The consumer never trusts a PUT response as persistence proof: it rereads the
record. Exact repeat calls preserve the same result and resourceVersion; other
claims conflict. Expired claims are diagnostic history only. There is no refund
after timeout, failed downstream audit or uncertain activation.

## Composition still required

Production installation must protect and retain independent pins and the record,
use qualified Pod-bound installer credentials, and retire the narrow writer after
installation. No workload, command or Helm template currently wires this port.
The atomic pristine-SQL check, encrypted activation audit, activation writer,
recovery checkpoints and qualified restart/restore coordinator remain pending.
No synthetic claim or fixture administrator transition can fill those gaps.

Native Kubernetes tests cover consume/repeat, a four-way race, immutable reset
denial, writer create/delete denial, missing/replaced UID rejection, expiry and
missing admission protection. They use real API-issued test tokens and synthetic
database/source/plan facts. This is record qualification, not database activation,
Pod-bound installer qualification, an end-user flow or a production capacity test.
See [implementation progress](../implementation-progress.md) for exact results.
