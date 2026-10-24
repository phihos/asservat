# Official Helm initial bootstrap

ADR-137 packages the existing ADR-131/133 commands. C-20 owns the closed public
input/runner DTOs; the provider configuration adapter normalizes PEM and the
non-authorizing audience hint; Kubernetes owns fixed runner/terminal observation;
bootstrap owns local CLI/command composition. Helm supplies static trusted setup
RBAC and nonsecret desired inputs. Runtime continuation remains an explicit
option; the default chart installs configuration foundations only.

## Original identity and phase boundaries

The administrator selects an already trusted Restricted bootstrap namespace,
distinct target namespace, stable name, exact release image digest, public
provider/fleet settings and existing Secret references. The product establishes
all dynamic UIDs, SQL OIDs, guards, journals and immutable private projections.
The namespace is an explicit trust entry, not proof of historical cleanliness.

The hook runs `initial-bootstrap`, `initial-bootstrap-schema`,
`initial-bootstrap-prepare`, then `initial-bootstrap-retire` in one fixed Pod.
With `bootstrap.continuation.enabled`, `installer-continue` is the final
container of that same Pod. This replaces two Pods, six process starts, two
scratch volumes and two projection producers with one Pod, five process starts,
one scratch volume and one producer. The first four commands retain their exact
credential mounts. Retirement refreshes the common/public/history projection
and removes the maintenance credential before continuation receives the read-only
preparer subdirectory. Continuation receives its own rotating projected API
token and only the SQL administrator file from the producer Secret; it does not
mount producer material, DDL credentials or registry credentials.

The 30-minute orchestration ceiling does not extend a five-second observation,
original SQL/provider effect, fifteen-minute copy-cleanup claim or any retained
history. The existing manager retirement, history grant transfer, current schema
incarnation checks and positive v3 setup-copy deletion are unchanged.
There is no fresh lifetime for the last container. Helm's client wait timeout
also does not extend the Pod or any phase. The bootstrap-only four-command
profile remains available when continuation is disabled.

The public compiler accepts ordinary PEM roots and sorts qualified DER roots.
An omitted API CA comes from the native public projection. An omitted audience
may use exactly one unexpired audience in the current projected token as a hint;
ambiguity requires an explicit setting. This parsing authenticates nobody.
Actual administrator/API/probe identity and independent denial precede private
effects. Unsupported private input cannot fall back to an ambient credential.

Each runner pins a full digest and revision name for its two immutable public
JSON objects. With continuation enabled, `runner.json` also contains the full
SHA-256 of the exact immutable public `continuation.json`. Its existing
ConfigMap name uses the first 32 hexadecimal characters; the complete digest
remains bound by the runner's original input digest. The optional
field leaves original bootstrap-only input bytes and layout unchanged.
Resume reads the original bootstrap/runner snapshot, not current values. A
corrected first-attempt typo may create another snapshot; known product state
continues to require its original scope. Missing or contradictory inputs cannot
recreate the installation. Snapshots are currently retained pending qualified
positive-unreferenced cleanup. Helm never deletes seed/history/tombstones.

## Terminal-only orchestration resume

`installer-resume` resolves the normal local kubeconfig/context/namespace and
reports them with the installation name. It never uses in-cluster fallback or
opens setup credentials. A bounded read checks the original fixed template,
public input digest and every actually started process. Live, unknown, node-lost,
restarted, replaced or contradictory Pods are unavailable. Positive terminal
receipts permit one exact UID/RV DELETE and require observed absence. An unknown
DELETE is not a replacement grant; a later invocation repeats exact observation.
No background retry, Helm shell call, seed read or recovery activation occurs.

A missing hook means only that orchestration may be invoked. The fixed commands
still classify protected existing progress independently. Failed hooks are
retained; only successful hooks are deleted automatically. Application/schema
rollback is outside this initial-install protocol.

For the combined runner, the same terminal proof covers continuation and its
projected input name is part of the exact Pod spec comparison. Terminal-only
cleanup does not read the downstream continuation ConfigMap: its absence or
outage cannot keep a proven terminated runner alive. No journal, operation
identity, provider attempt or uncertain spend is reset. A chart upgrade also
uses Helm's existing administrative connection for one render-time lookup of
the legacy `<name>-continuation` Pod. Missing or completed (`Succeeded`/`Failed`)
legacy Pods permit rendering; nonterminal, node-lost or deleting Pods refuse it.
Helm never deletes or adopts that Pod. This check does not replace terminal
process proof or fence concurrent administrative changes. Offline `helm
template` has no live lookup and cannot qualify an upgrade's overlap check.

## Explicit private registry input

The operator's separately supplied pull Secret supports the runner and remains
an ongoing distribution dependency. Its `.dockerconfigjson` is at most 4 KiB,
contains exactly the pinned image registry, and normalizes only username/password
or equivalent Basic `auth`. Reject helpers, external-command configuration,
identity tokens, headers, extra keys/registries and conflicting credential forms
without including credential content in errors. No workstation/node auth lookup
occurs. The existing aggregate 8 KiB material/32 KiB seed bounds remain unchanged.

The typed capability makes the original activation provider Secret
`kubernetes.io/dockerconfigjson`, with exactly eight keys. Only the original
seven keys are projected into the activation Pod; `.dockerconfigjson` is consumed
by kubelet via the exact same Secret name/UID. The native guard binds that Pod
spec and original private projection. No runtime Secret reader is added.
Managed copy deletion/sanitization uses the original positive v3 lifecycle and
does not revoke operator originals or erase node caches, etcd or backups.
Absent capability retains the prior Opaque Secret and exact serialized fields.

Kubernetes permits additional keys in this Secret type but requires a valid
Docker config key and applies its aggregate 1 MiB data limit; the product's
smaller bounds remain mandatory. Its kubelet pull keyring reads the Docker key
from the named pull Secret. Primary sources: [API validation](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/apis/core/validation/validation.go),
[kubelet credential extraction](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/credentialprovider/secrets/secrets.go),
[image pull Secrets](https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod).

## Qualification and remaining installed prerequisites

The single five-command layout and expanded resume path are a packaging
refactor awaiting their own runtime qualification. Earlier four-command and
separate-continuation evidence below does not qualify removal of the second
producer. The new owned Helm lookup cases use deliberately unscheduled Pods
with fixture-written status; they test real render-time API lookup and refusal,
not kubelet process termination. The installed product chain must separately
exercise the combined commands, their credential boundaries and retained replay.

The new owned `scripts/test-context-storage.py --helm-bootstrap` selection
packages the actual chart, builds the actual product, starts empty PostgreSQL
and actual OpenBao/S3, and pushes only that test image to an owned authenticated
TLS Distribution registry. Two owned Kind nodes have no exact image/manifest;
only its public CA is installed into their containerd trust. The unchanged
runner pulls on node A; fixture-only node availability then sends the unchanged
activation Pod to node B. Require anonymous denial and successful authenticated
manifest GETs from both nodes without recording headers/credentials. Shared
layer caches are not cold exact-image evidence. The pinned registry image is
fixture provenance, not a measured pull result.

The [packaged native run](../../test/results/helm137-native-hook-diagnostic-check.log)
passes original manager/schema/audit/activation and v3 positive closure,
setup-free fresh Helm replay, failed-hook original-revision CLI resume and
uninstall preservation. Its [environment report](../../test/results/helm137-native-hook-diagnostic-environment.json)
confirms anonymous denial, authenticated exact-manifest pulls from both owned
nodes without preloading that image, 1,458 unchanged source hashes and complete
owned cleanup. This is component qualification with fixture-owned upstream
administration. A preceding hook failure remains unexplained: the passing run
uses the same product binary, with added failure diagnostics only. Do not claim
a startup-availability fix or independently qualified production bootstrap
environments. Unit/API metadata tracing and compiled setup-free replay qualify
separate scopes; no production tracing is added.

Subsequent installed continuation and end-user evidence are tracked in
[implementation status](../implementation-status.md). They require protected
identity/session, permission, retention, capacity, processing and provider
inputs; a successful bootstrap-only hook supplies none of those runtime
guarantees. Independently qualified restart/restore activation, internal
identity/static-key services and bundled database/store profiles remain
separate accepted work. Consolidating the runner does not implement those
capabilities or turn Helm rollback into application recovery.
