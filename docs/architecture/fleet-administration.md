# Fleet administration and trust

C-04/C-21 under REQ-FED-001, REQ-DB-005 and TASK-03. Fleet operators enroll and
revoke clusters. That responsibility grants no workload collection, evidence
reading or approval, and is separate from workload AccessBinding roles. There
is no public permission CRUD API.

## Fleet settings

`fleet.json` follows [fleet-settings/v1](../../specs/contracts/fleet-settings.schema.json)
([example](../../examples/fleet-settings.json)). The Helm chart renders it into a
ConfigMap in the Asservat namespace. It declares:

- the installation and issuer epoch, and a monotonic revision;
- administrative suspension;
- one organization issuer (HTTPS, no user info, query or fragment) and the
  allowed clients;
- explicit human/workload operator subjects or stable operator group IDs
  (empty lists deny all new enrollment);
- approved credential-delivery profile names; no field selects a URL or
  carries a secret;
- enrollment ceilings: 1–128 active bootstrap slots, 1–65,536 retained bootstrap
  records (≥ the active ceiling) and 1–1,024 registered clusters. These are
  rejection bounds, not supported-scale claims; there are no silent defaults.

hub-worker reads the file through a shared informer (or the mounted file) and
rejects unknown fields and case aliases. A valid change is written to SQL
`fleet_trust` as a new revision, in one transaction with a `NOTIFY` so other
hub processes reload. The revision may advance but not regress, and the same
revision cannot carry different content. Unchanged content writes nothing. The
stored revision stays valid until a later change replaces it; it does not
expire. A watch or parse failure keeps the last valid revision and reports the
error; it does not suspend the installation.

## Recovery fence

The recovery fence is the database incarnation. The `setup` Job seeds the first
`fleet_trust` row with the incarnation of the freshly migrated database. A
supported restore changes the PostgreSQL process/database incarnation and the
restore procedure records the new incarnation before service resumes. Effects
read the stored incarnation and suspension with plain MVCC in their own
transaction and include the expected incarnation in their conditional write;
they do not lock the trust row. A configuration change by itself never clears
recovery or changes the issuer epoch.

## Enrollment authorization

`EnrollmentAuthorizer` authorizes a fleet operation once, using the caller's
identity handle ([current request identity](current-request-identity.md)) and
the current fleet revision. It requires an explicit operator subject or group,
an allowed client and an approved delivery profile. A subject's human/workload
class is significant: a same-named service account does not inherit a human
assignment, and a workload-maintainer group cannot enroll clusters. The decision
carries the identity and fleet revisions and the ceilings for the issuance
transaction, which enforces them with conditional counts.

The hub creates the bootstrap token and shows it once
([connector identity](connector-credentials.md)); the connector then enrolls as
described in [connector enrollment](enrollment-activation.md).
