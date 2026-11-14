# Fleet administration and trust

C-04/C-21 under REQ-FED-001, REQ-DB-005 and TASK-03. Fleet operators enroll and
revoke clusters. That responsibility grants no workload collection, evidence
reading or approval, and is separate from workload AccessBinding roles. There
is no public permission CRUD API.

## Fleet settings

[ADR-335](../decisions/335-usable-by-default.md) D14 removes the separate fleet
operator list: administrators (`identity.administrators`) enroll clusters, and
the canonical fleet-settings contract is deleted. The runtime still reads the
earlier `fleet.json`, described below
([implemented schema](../../specs/contracts/implemented/fleet-settings.schema.json),
[example](../../examples/implemented/fleet-settings.json)). The Helm chart renders it into a
ConfigMap in the Asservat namespace. It declares:

- the installation;
- administrative suspension;
- one organization issuer (HTTPS, no user info, query or fragment) and the
  allowed clients;
- approved credential-delivery profile names; no field selects a URL or
  carries a secret.

There are no enrollment ceilings: one bootstrap token belongs to one cluster
registration, the cluster rows themselves bound the cluster count, and
retained bootstrap records follow audit retention.

hub-worker reads the file through a shared informer (or the mounted file) and
rejects unknown fields and case aliases. A valid change is written to SQL
`fleet_trust`, in one transaction with a `NOTIFY` so other hub processes
reload. Unchanged content writes nothing. The stored content stays valid until
a later change replaces it; it does not expire. A watch or parse failure keeps the last valid revision and reports the
error; it does not suspend the installation.

## Recovery fence

The recovery fence is the database incarnation. The `setup` Job seeds the first
`fleet_trust` row with the incarnation of the freshly migrated database. A
supported restore changes the PostgreSQL process/database incarnation and the
restore procedure records the new incarnation before service resumes. Effects
read the stored incarnation and suspension with plain MVCC in their own
transaction and include the expected incarnation in their conditional write;
they do not lock the trust row. A configuration change by itself never clears
recovery.

## Enrollment authorization

`EnrollmentAuthorizer` authorizes a fleet operation once, using the caller's
identity handle ([current request identity](current-request-identity.md)) and
the current fleet settings. It requires membership in the administrator group
(`identity.administrators`), an allowed client and an approved delivery
profile. A subject's human/workload
class is significant: a same-named service account does not inherit a human
assignment, and a workload-maintainer group cannot enroll clusters.

The hub creates the bootstrap token and shows it once
([connector identity](connector-credentials.md)); the connector then enrolls as
described in [connector enrollment](enrollment-activation.md).
