# Fleet administration and trust

C-04/C-21 under REQ-FED-001, REQ-DB-005 and TASK-03. Clusters are registered,
changed and revoked only in the hub's Helm values
([ADR-334](../decisions/334-connector-workload-identity.md)); there is no
console or API enrollment. Fleet administration grants no workload collection, evidence
reading or approval, and is separate from workload AccessBinding roles. There
is no public permission CRUD API.

## Fleet settings

[ADR-335](../decisions/335-usable-by-default.md) D14 removes the separate fleet
operator list and the fleet settings: administrators are
`identity.administrators` in the identity settings. The SQL `fleet_trust` row
holds only the generated installation ID and issuer epoch. `setup` seeds it; it
changes only when that identity changes. Nothing refreshes or suspends it
([ADR-330](../decisions/330-event-driven-system-design.md) D1/D13).

## Recovery fence

The recovery fence is the database incarnation. The `setup` Job seeds the first
`fleet_trust` row with the incarnation of the freshly migrated database. A
supported restore changes the PostgreSQL process/database incarnation and the
restore procedure records the new incarnation before service resumes. Effects
read the stored incarnation with plain MVCC in their own
transaction and include the expected incarnation in their conditional write;
they do not lock the trust row. A configuration change by itself never clears
recovery.
