# Official Helm initial bootstrap

ADR-137 packages the existing ADR-131/133 commands. C-20 owns the closed public
input/runner DTOs; the provider configuration adapter normalizes PEM and the
non-authorizing audience hint; Kubernetes owns fixed runner/terminal observation;
bootstrap owns local CLI/command composition. Helm supplies static trusted setup
RBAC and nonsecret desired inputs. No public runtime is enabled.

## Original identity and phase boundaries

The administrator selects an already trusted Restricted bootstrap namespace,
distinct target namespace, stable name, exact release image digest, public
provider/fleet settings and existing Secret references. The product establishes
all dynamic UIDs, SQL OIDs, guards, journals and immutable private projections.
The namespace is an explicit trust entry, not proof of historical cleanliness.

The hook runs `initial-bootstrap`, `initial-bootstrap-schema`,
`initial-bootstrap-prepare`, then `initial-bootstrap-retire` in one fixed Pod.
The 30-minute orchestration ceiling does not extend a five-second observation,
original SQL/provider effect, fifteen-minute copy-cleanup claim or any retained
history. The existing manager retirement, history grant transfer, current schema
incarnation checks and positive v3 setup-copy deletion are unchanged.

The public compiler accepts ordinary PEM roots and sorts qualified DER roots.
An omitted API CA comes from the native public projection. An omitted audience
may use exactly one unexpired audience in the current projected token as a hint;
ambiguity requires an explicit setting. This parsing authenticates nobody.
Actual administrator/API/probe identity and independent denial precede private
effects. Unsupported private input cannot fall back to an ambient credential.

Each runner pins a full digest and revision name for its two immutable public
JSON objects. Resume reads that original snapshot, not current values. A
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

A missing hook means only that orchestration may be invoked. The four commands
still classify protected existing progress independently. Failed hooks are
retained; only successful hooks are deleted automatically. Application/schema
rollback is outside this initial-install protocol.

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

Installed end-user operation still requires protected identity/session sources,
permission/deny/capability acceptance, retention topology/history/catch-up,
qualified storage/backup/WAL and finite workload/audit/capture/Stop backing,
processing initialization/release reserve and complete client/native paths,
worker/owner/connector trust and credential provisioning, actual public HTTPS
browser/MCP/content composition, joined ongoing supervisors, and independently
qualified restart/restore activation. Existing components are not substitutes
for those installed accepted inputs. Internal identity/static-key services and
bundled database/store profiles remain separate accepted work. Hook success
starts no hub, console, MCP endpoint or collector.
