# Fleet administration and trust

C-04/C-21 under REQ-FED-001, REQ-DB-005 and TASK-03. Clusters are registered,
changed and revoked only in the hub's Helm values
([ADR-334](../decisions/334-connector-workload-identity.md)); there is no
console or API enrollment. Fleet administration grants no workload collection, evidence
reading or approval, and is separate from workload AccessBinding roles. There
is no public permission CRUD API.

## Fleet settings

[ADR-335](../decisions/335-usable-by-default.md) D14 removes the separate fleet
operator list: administrators (`identity.administrators`) administer the fleet, and
the canonical fleet-settings contract is deleted. The runtime still reads the
earlier `fleet.json`, described below
([implemented schema](../../specs/contracts/implemented/fleet-settings.schema.json),
[example](../../examples/implemented/fleet-settings.json)). The Helm chart renders it into a
ConfigMap in the Asservat namespace. It declares:

- the installation and issuer epoch, and a monotonic revision;
- administrative suspension;
- one organization issuer (HTTPS, no user info, query or fragment) and the
  allowed clients;
- explicit human/workload operator subjects or stable operator group IDs
  (empty lists grant fleet administration to nobody);
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
