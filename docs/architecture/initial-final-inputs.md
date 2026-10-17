# Initial installation public input producer

C-21's `InitialPreparer.PrepareFinalInputs` continues the actual private
`initial-prepare` command when protected service inputs are present. C-20 owns the
closed desired document and bounded root fields. It creates exactly witness and
fleet ConfigMaps, final workload/witness/fleet policy-binding pairs, and immutable
startup inputs. It accepts no arbitrary object body, activation flag or private
credential.

The source digest is frozen before effects. Namespace/account UIDs come from the
nine original declarations; Pod UID and actual specification digest come from the
gated producer. Policy generations must be exactly the first generation with
matching observedGeneration and no type-checking warnings. The original binding
UID and resource version remain exact on replay. Startup data includes the actual
source, witness, guard and workload identities plus public provider configuration.
Runtime provider constructors still independently validate connection profiles.

Every first effect has an acknowledged root CAS before its one POST. Existing
pending intents get only exact name/ownership/operation/specification lookup.
Lost successful replies can therefore recover their original object; an absent
unknown effect cannot be reset. The administrator, original staging/continuity
protection and gated Pod remain current within the earliest original five-second
operation deadline. These observations are not evidence of historical cleanliness
or HA admission propagation.

The private command automatically waits only for the exact pending policy to
finish type checking, within its original finite process-run budget. A warning or
changed policy is refused; waiting does not repeat CREATE or extend any effect
lease. Other uncertain operations return the fixed resume/reconciliation remedy.

Focused staged unit/race tests pass for all nine objects, original startup identity
propagation, lost responses, absent unknown effects without repeated CREATE, source
intent changes, pending policy compilation, missing/replaced UIDs and changed
binding resource versions. The selected native Kubernetes case passes in
57.63 seconds, including sixteen inherited guard/retirement subtests and the
actual nine-resource producer/replay checks. The enclosing combined run fails
in the separate v2 worker startup case; see [implementation progress](../implementation-progress.md).
Public provider endpoints remain synthetic, all actual public Kubernetes resources
use the production producer, and the Pod remains gated.
The public-input producer does not issue a probe token or provider credential,
remove staging, ungate a Pod, activate SQL or authorize retirement. Those components
remain the next required continuation under ADR-123.
