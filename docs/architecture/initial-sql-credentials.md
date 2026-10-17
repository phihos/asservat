# Initial-installation SQL credential lifecycle

[ADR-100](../decisions/100-temporary-initial-sql-credentials.md) extends
[initial-installer execution](initial-installer.md). C-21's `InitialSQLRoles`
owns PostgreSQL provisioning/retirement; C-20 owns the private state DTO.
The activation coordinator and its separate preparation/audit/activation ports
remain unchanged.

The provisioner generates `NewInitialSQLCredentials` once, encodes them with
`EncodeInitialSQLCredentials`, and persists that exact payload in an immutable,
access-restricted Secret before any SQL mutation. The full startup plan digest
binds the intended database endpoint, roots, installation and workload pins.
`DecodeInitialSQLCredentials` requires that exact installation and digest,
closed fields, canonical independent secrets and the original finite interval.
It accepts expired state only so cleanup remains possible. Do not regenerate
missing state, adopt a same-named Secret or change pins after an uncertain result.
The codec alone proves neither persistence nor object identity. C-21's
`InitialCredentialStateStore` now supplies the narrow Kubernetes producer/reader;
the supervisor must retain its returned Secret UID and original plan across
restarts. The adapter cannot create/adopt a namespace, guard, account or Pod.

Before Secret creation, authenticate the configured administrator online, prove
the independent probe account and exact native namespace guard, compare the
immutable configuration UID and full plan digest, then read the live writer
account and original gated Pod specification. The Pod must remain unscheduled
with exactly the installation gate. Submit one create-only Secret request with
no POST replay. An uncertain response or name collision permits only lookup of
the same caller-retained bytes in the same protected scope. Different contents
are a conflict, never an update or adoption. Recheck protection afterward within
the original at-most-five-second interval. Failed final checks leave the result
uncertain; they do not delete a potentially important installation record.

Reads require the previously retained Secret UID, exact immutable one-field
payload, current administrator/guard and unchanged startup inputs. They remain
available after the installer Pod terminates so credential retirement can use
the same state. Missing protection blocks disclosure; already-retained exact
credentials can still be retired through the independent SQL facet. Both read
and create reject substituted object identity, and neither supplies SQL effects
or activation authority. Semantic credential validation through the SQL codec
remains mandatory before those effects. The Secret is not logged or audited as
content. Cluster administrators must protect Secret storage and API audit policy
as for other installation credentials.

The maintenance adapter requires verified TLS 1.3 with no fallback/tracer,
at most four pool connections, a primary server and a non-superuser role with
`CREATEROLE` but no database creation, replication or RLS bypass. Provider-side
grant options must be delegated separately; the activation Pod never receives
this credential. This is a trusted administrative capability, not ordinary
evidence permission or a requirement placed on developers.

The private executable independently derives each expected username from the
installation UUID and preparation/audit/activation purpose before opening SQL.
Three distinct but unrelated accounts are insufficient. It requires server
SCRAM-SHA-256 authentication too: trust, MD5 or cleartext-password negotiation
cannot bypass the password's original validity. These checks do not replace the
provisioner's exact-grant validation or its retirement responsibility.

For schema 32, preparation/activation get `SELECT, MAINTAIN` on the exact 51
tables required by pristine-state locking. `MAINTAIN` permits the locks without
general update/delete/truncate rights. Preparation inserts the attempt and
initial blocked root, and can update only the conflict-handling singleton field.
Audit can read its attempt/schema and acknowledge only the encrypted audit
receipt. Activation reads the current-trust view and updates only activation
and bounded fleet state columns. All roles get schema usage; none can create
objects, own application objects, inherit another role, or grant onward access.

Each bounded transaction preserves the original deadline and checks database
time after lock waits. All roles are created in one transaction. A retry checks
exact attributes and direct/ambient privilege paths before a fresh TLS/SCRAM
authentication of all supplied credentials. It does not rewrite an existing
verifier or validity date. Error messages remain opaque; state/logins have
redacted formatting. Go string lifetime does not provide guaranteed heap erasure.

Retirement uses the same table locks to exclude overlapping activation effects,
sets `NOLOGIN PASSWORD NULL`, revokes each schema/table/column grant and verifies
the retired state. An existing session can remain connected but loses these
effect rights. Password expiry alone does not close sessions or revoke grants.
Cleanup of provider tokens, Secrets and actual Pod/processes is independent.
Unknown or permission-drifted cleanup must remain visible as incomplete.

[Implementation progress](../implementation-progress.md) distinguishes provider
tests, native Pod composition and pending production orchestration. The updated
native fixture invokes the product persistence adapter but still establishes
the clean namespace, guards, startup inputs and maintenance/provider authority.
It is not a shipped installer or an enabled Helm runtime.
