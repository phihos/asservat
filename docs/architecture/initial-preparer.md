# Resumable initial declaration

ADR-117 adds the private `initial-prepare` command and a fixed protected projection
at `/run/asservat/initial-preparer`. It consumes `deployment.json`, a current
`administrator-token`, and a separately authenticated `probe-token`; provider
credentials and arbitrary object bodies are not accepted. File reads reuse the
confined regular-file loader. Core dumping is disabled before credentials are
read. Cancellation and unavailable input produce nonzero exit.

The immutable desired plan lives in a stable bootstrap namespace, separate from
the new target namespace. The independently probed continuity policy is pinned by
UID/generation and binding UID/resourceVersion. The separate staging policy is a
pinned trusted bootstrap input. Policies/bindings cannot themselves be protected
by ValidatingAdmissionPolicy; replacing them requires installation requalification.
Their exact pins must remain stable across routine Helm upgrades.

The supervisor alone creates and CAS-updates its public root ConfigMap. The root
contains the plan digest, original installation/request IDs, its own observed UID,
ordered create intents/receipts and a monotonic phase. The shape reuses ADR-102's
bounded entry format (64 entries, 48 KiB); the actual producer accepts exactly nine
ordered resource identities. No credential or secret-payload digest enters it.
Helm must not own this mutable document or reset it during upgrade/rollback.
A current missing externally pinned root UID cannot create a replacement. Initial
root creation under the original continuous guard may be retried at the same name;
no API deletion/reuse of that key is permitted. Out-of-band control-plane restore
is outside this installation continuity proof.

`Open` proves current administration/guard enforcement and initializes or resumes
the original root. `EnsureNext` appends at most one pending intent by exact
UID/resourceVersion CAS. A lost CAS reply returns unavailable before any resource
CREATE. A later run reads that same intent, then GETs or repeats its exact named
CREATE under the unchanged guard. Full typed verification precedes the immutable
receipt. Namespaces accept only their expected restricted label and native
metadata-name/finalizer/status defaults. No credential, Secret, Pod, provider
operation, witness consumption or activation is retried by this path.

`Declare` handles only the finite declarative inventory, and `VerifyDeclared`
rereads every known UID/shape before reporting the declaration checkpoint. Each
step preserves its original five-second current-authority deadline through all
blocking reads/writes. A one-minute process-run budget is separate from the public
root: restarting resumes that same root and never renews an issued credential.
There is no root age limit that forces an otherwise safe installation to start over.

`RetireSetupAuthority` changes phase monotonically and empties only the compiled
setup rules/subjects in place. It verifies the observed empty objects before
reporting `retired`; uncertain updates remain unresolved. Original receipt UIDs
and resourceVersions remain historical and unchanged. The continuity policy
rejects named and collection deletion, refill, RoleRef changes, aggregationRule
injection and metadata ownership changes. A delayed original CREATE cannot revive authority because the
same key and UID remain occupied. This operation neither claims activation success
nor replaces the later credential/session retirement checks.

The first-installation inventory fits the original bound. Nine producer objects
plus the root precede the activation-specific Pod, six final guard objects, public
witness/fleet/startup configuration and purpose-separated credential objects.
The trusted bootstrap namespace, two policy/binding pairs, probe anchor/account/
RBAC/token lifetime anchor remain a separately owned finite set. Later runtime
credentials/configuration are a separate bounded provisioning phase, not arbitrary
resources appended forever to this initial journal.

## Verification scope

The focused Go race suite and vet passed against the staged source on
2026-10-11; integrated full Go vet/race and repository gates now pass.
Local TLS tests cover lost replies before/after resource creation, lost/expired
intent acknowledgement, unchanged replay, UID replacement/deletion, unavailable
administrator/guard and repeatable in-place retirement. Unit-only fake client QPS
limiting avoids testing delays; native fixtures retain the real bounded clients.
The initial test run found an off-by-one completion branch after all nine receipts
committed; its regression requires the same invocation to return the declared
checkpoint. The branch was corrected without extending authority deadlines.

The isolated native test `TestInitialPreparationSupervisorWithRealKubernetes`
uses the real producer/API and a fixture-owned delayed POST. It checks resumed
same-name creation, deletion denial, exact retirement reductions, and an original
POST arriving after retirement returning AlreadyExists. The fixture explicitly
supplies trusted bootstrap inputs and tears down only its owned resources after
retained requests join. The combined native selection now passes the enclosing
test, all fourteen functional subtests and cleanup. Earlier runs exposed an
incorrect request.namespace assumption for Namespace deletion and a fixture
cleanup classifier that missed structured 422 policy rejection. Both corrections
retain the exact guarded names/UIDs and original deadlines. The actual logs,
unchanged source and owned-lab cleanup are in
[implementation progress](../implementation-progress.md). These are component
results with fixture-owned bootstrap, not an automatically provisioned installer.

## Next composition

This is a declaration checkpoint within the assigned preparation supervisor,
not a complete runnable installation. Typed continuation must create/retain the
initial target journal/probe inputs, immutable SQL state, guarded inert Pod,
provider credentials and final input/guard projections; persist exact staging
handover; launch the existing `initial-install`; then retire credentials and
bootstrap authority with observed denial. A changed/disabled staging binding
cannot be silently adopted by this checkpoint's original pins. Unknown Secret,
TokenRequest, provider, activation and ungating outcomes still use their existing
one-use protocols. Helm packaging, automatic protected bootstrap provisioning,
initial local-key audit composition, restart/restore and public-runtime enablement
remain separate required work. Users must never be asked to hand-edit root/UIDs
or regenerate a plan merely to retry an ordinary interrupted declaration.
