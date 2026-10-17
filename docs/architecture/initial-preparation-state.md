# Retained installation state and historical result

ADR-118 continues ADR-117's declaration checkpoint. C-20 owns the private
[material schema](../../specs/contracts/initial-sql-material.schema.json); C-21
reads protected Kubernetes inputs and supplies SQL codecs/read facets; C-04 owns
the purpose-specific historical observation contract.

`InitialSQLMaterialReader` reads one independently pinned immutable Secret in the
stable bootstrap namespace after proving current administrator, original guard
and retained root identity. It requires exact installation/request values and
three distinct canonical 32-byte random password values. It performs no CREATE,
UPDATE, secret adoption or fallback. Failure returns no material. The original
five-second bound remains binding through the final native checks. The reader
currently consumes the original staging guard, so post-handover reads require the
separately planned explicit guard-transition composition.

`NewInitialSQLMaterial` reuses the existing crypto/rand password generator for
trusted first-bootstrap creation only. It persists no time or role and grants no
SQL access. `BindInitialSQLMaterial` reconstructs the existing exact ADR-100 state
using the accepted original interval; it does not generate replacement passwords
or verify that interval's durable acceptance. The producer-owned public binding
and automatic first-bootstrap private persistence are still required before this
can be a complete issuing path. Native provider-generated credentials cannot be
recreated from these bytes.

The private material must be retained independently from the supervisor process.
Helm stores its pending release, including rendered manifests, before it creates
ordinary chart resources. Chart lookup by itself cannot recover a crash before
the private Secret was created. The supported installer must retain and recover
the exact original release bytes or pinned Secret, never rerender random values
while uncertain work remains. Helm rejects another pending operation, so the
actual supported resume flow still needs qualification. Release records containing
private manifests are also secret storage. After positive external retirement,
Secret and release-history cleanup must follow the configured bootstrap policy;
removing them prematurely can destroy the only original reconciliation material.
These are source-based design findings, not a passing Helm recovery test.
[Helm install source](https://github.com/helm/helm/blob/main/pkg/action/install.go),
[Helm upgrade source](https://github.com/helm/helm/blob/main/pkg/action/upgrade.go).

`InitialInstallationReadProtection` reuses the current administrator and exact
native workload guard checks used for cleanup reads, plus the original immutable
startup ConfigMap UID/hash and complete witness/cluster/account scope. It does not
read a credential Secret, mint a token, require the old Pod to be running, or
consume a witness. The distinct `InitialInstallationReader` receives SELECT-only
credentials for the schema version and `fleet_initial_activation`; no migration
or activation write permission is added.

The SQL reader performs one scoped MVCC SELECT after current protection succeeds.
It validates the stored claim ID, exact startup digest and witness scope, closed
record/receipt shapes and acknowledgement consistency. An activation timestamp
must fall inside the original claim interval. Old schema-version/database claim
provenance is preserved and never promoted to the current database incarnation.
Final current protection cannot extend the original deadline, even if it blocks.
There is no inference from a missing record to no effect, or from a historical
success to current recovery readiness. The reader can report historical activation
while the current root remains blocked. A separately protected role producer and
supervisor composition remain required; fixture role creation is not production
provisioning. This facet reuses the setup probe account. After that account's
permission or credential retirement, a failed probe cannot be treated as native
policy enforcement. A separately qualified handover/status composition is needed
for observation after setup retirement; current code does not claim that path.

## Verification

The focused overlay race/compile passed for Kubernetes (9.610s), PostgreSQL
(1.035s), application/contract compilation and integration compilation (1.059s).
The external integration selection skipped without its owned fixture; it is not
a real-service result. The private JSON Schema and UUID/canonical-base64url
negative cases passed using the repository validation environment with format
checks. Integrated Go vet/race, SQL generation and specification/architecture
gates now pass. The fresh-installation SQL/S3/OpenBao suite passes sixteen named
entries, including the historical reader's role, deadline and recovery isolation
checks; its current Kubernetes administrator proof remains synthetic. The
combined native Kubernetes selection also passes, including historical read
under actual current input/guard protection after the product installer Pod
exits. Bootstrap/provider/role provisioning remains fixture-supplied. Exact terminal logs, unchanged
source hashes and cleanup are recorded in [implementation progress](../implementation-progress.md).

Regression sources cover exact expired-state reconstruction and redacted formatting,
private Secret UID/content/guard changes, final-deadline expiry, historical scope
and audit mismatches, and reading after the old Pod terminates. The SQL fixture
uses a separate SELECT-only role, tests each disposition, verifies mutation denial,
observes an actual blocked SQL read before deadline expiry, and checks that a
later recovery block remains unchanged. Its Kubernetes operator proof is explicitly
synthetic; native current-input checks require their own qualification.

## Required continuation

Retain original private bootstrap state, durably bind the credential interval,
produce the gated Pod and final immutable inputs, record the exact staging-to-final
guard handover, compose existing credential/provider effects and activation, then
join/fence original writers and positively retire their rights. Historical success
alone cannot prove the latter. Failed or terminal Pod status cannot distinguish a
pre-witness no-effect attempt from claimed/uncertain activation. A protected
cancellation/reconciliation protocol remains necessary before a fresh attempt;
changing the original five-minute claim or fifteen-minute credential deadline is
not that protocol. Full installer and public investigation runtime remain disabled.
