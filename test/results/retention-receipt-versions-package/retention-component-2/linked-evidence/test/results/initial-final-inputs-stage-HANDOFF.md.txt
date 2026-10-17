# ADR123 public final-input checkpoint

Frozen typed public producer, outside live. It extends the actual private
initial-prepare command after the ADR120 gated Pod, using the original root,
namespace/account/Pod receipts and installation-owned public service inputs.
It does not launch, activate, provision provider credentials or enable runtime.
No SQL migration, dependency or role changes. Parent owns application and native
qualification. Preserve this package when continuing private inputs/handover.

The additional inventory is fixed at nine: witness, fleet source, three compiled
policy/binding pairs and immutable final startup ConfigMap. Original source intent
and each typed CREATE are durably bound before one POST. Pending effects permit
only exact lookup. Policy compilation must be acknowledged before the binding;
normal compilation delay is observed automatically by the private command, within
its original run budget. UID/operation/spec and original binding RV cannot change.
Services are public, limited to24KiB, within the48KiB startup/root bounds. No secret
or secret-payload digest enters the public journal. Independent final native
source/witness enforcement, private/provider readiness and handover remain later.

`test/integration/initial_preparer_test.go` has one narrowly extended variadic
fixture hook plus invocation before RBAC retirement; keep all existing parent
fixes when merging. The isolated new native test calls the real producer against
owned Kubernetes, checks actual defaults/UIDs/guard compilation and exact replay,
then verifies the original Pod remains gated. Only unused external provider
endpoints are synthetic. Fixture teardown uses its explicitly trusted
administrator and exact owned resource UIDs; it is not product retirement.

Actual checks:

- `TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -race -p 2 -overlay=.../overlay.json ./internal/adapters/kubernetes ./internal/bootstrap ./test/integration -run 'TestInitialPreparationFinalInputs|TestInitialPreparationPublicInput|TestInitialPreparationPendingPolicy' -count=1`: terminal0; Kubernetes14.261s, bootstrap1.050s(no matching tests), integration1.057s(native skipped). qualification-fourth.log.
- Same three packages, `go vet -p 2 -overlay=.../overlay.json`: terminal0, vet.log.
- spec-venv Python check-schemas.py: terminal0; two positive envelopes, nine negatives. Actual Draft202012+format checking and offline references, schema-check.log. The scratch script initially tried a non-schema JSON without$id and a positive root without its required Pod; those fixture errors were corrected, no production schema weakened.
- Earlier failing valid input isolated client-go's generated `?timeout=5s` in API Request.URL; comparison now validates the caller HTTPS origin/root then compares that origin, not generated request parameters. qualification-diagnostic-stable.log preserves the diagnosis. Earlier worker-type compile failure was a transient parent merge, not this implementation.

Native selection for parent: `^TestInitialPreparationPublicInputsWithRealKubernetes$`.
No external fixture has been run for this checkpoint. Existing fixture120s parent
budget plus30s policy-readiness limit remain finite. Readiness observation issues
no duplicate pending POST. Planned provider operations do not yet exist here.

Required next work continues immediately in a separate stage: original private
probe/provider response persistence and one-use issuance; immutable target provider
Secret and original SQL-role provisioning; exact staged→final guard handover and
one-use original-Pod ungating; real activation disposition and positive credential/
process retirement. Unknown TokenRequest/provider replies are not retried. Unknown
public CREATE currently remains explicit lookup-only reconciliation work, and
unknown Pod requests preserve the occupied key. No claims of historical namespace
cleanliness, HA admission propagation, completed Helm or restart recovery.
