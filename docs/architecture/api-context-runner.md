# Regional API context execution

The private `APIContextRunner` composes the ADR-104 Kubernetes API collector with
current accepted context, the existing start CAS and encrypted artifact producer.
It captures only the fixed 4096-byte Pod status projection. It does not execute a
command or require Node, exec, Secret, log or observed-container access.

`APIContextWork` is read using the original actor/client and current recovery and
ordinary permissions. It contains the audited accepted expectation, original
Pod/owner selection and immutable intent digest; stored groups and expired
preview observations are never authority. Current target, capability, retained
scope, identity and protected process observations are compiled again. The
result must equal the reviewed scope, exact Pod pin and collector image.

The preparation SQL role inserts one `context_execution` row. Eight competing
requests can receive only one first-create acknowledgement. An unknown commit
or create result may recover the exact name and content, but cannot repeat
CREATE. The separate capacity account verifies current protected namespace and
start guards, creates the exact object and later marks it Ready after SQL stores
its original UID. The execution account can only consume Ready, with native
admission additionally requiring the bound executor Pod and account. Original
request cancellation and the earliest five-second deadline cover every start
check, key preparation, local write and SQL wait.

Only acknowledged local CAS plus SQL start recording permits collection. Key
preparation occurs before CAS. Capture uses the original target pin and remaining
start interval. Native bytes remain bounded memory and are cleared on return;
only the existing wrap-only producer writes encrypted evidence. Failed/unknown
acquisition remains spent. A later process or a replay cannot capture again.
Stored output is a candidate awaiting independent verification.

The execution result freezes the exact four ciphertext receipts and acquisition
times. `APIContextPublicationGate` reads completed history and current retained
policy/recovery/permission fences; it has no live target or process reader. The
existing `ContextPublisher` fully verifies the artifact and writes its separately
credentialed encrypted verification audit before catalog publication. The audit's
optional API outcome includes exact executor/start/process provenance and the
completed execution digest. SQL rejects another process, receipt set, expectation
or start. Historical node records retain their original bytes and validators.

The process guard is installation-owned configuration. It reads a digest-pinned,
Restricted standalone executor Pod, uses a real Pod-bound credential, checks live
account identity despite authentication caches, and proves independent native
namespace denial. A Pod status resourceVersion race permits at most three exact
object-conflict retries, each re-reading the same UID/spec within the original
five-second interval; another denial never triggers a retry. Parent-context
cancellation also rejects a consumer passing a
background context. This current proof is not historical integrity or a deployed
installer. The initial standalone Pod profile is finite composition work, not a
claim that Kubernetes proves process uniqueness.

Foreground deletion permits the exact Kubernetes garbage-collector identity
(or shared controller-manager identity) to remove only `foregroundDeletion`
from the exact already-deleting executor Pod. Spec, labels, annotations, owner
references and other finalizers remain unchanged. This does not authorize a
new deletion or live workload mutation. A real native failure reproduced the
missing finalizer allowance; no policy disable or forced deletion was used.

Validation is staged separately from live repository qualification. Focused race
checks cover concurrent effect exclusion, identity/target/process changes after
key preparation, unknown replies, exact UID recovery, expiration after blocking
work, and API audit/progress corruption. TLS tests use synthetic API responses.
Prepared native fixtures cover separate SQL roles, encrypted result verification
and exact native read; their process/start facts are explicitly synthetic. The
native CRD/admission cases cover API Pod/account matching and two independent
start namespaces, with impersonation explicitly limited to fixture validation.
The joined native API runner now passes against owned Kubernetes/PostgreSQL/S3:
actual Pod-bound identity and native policy checks, one start, encrypted storage,
normal target/executor deletion, independent publication and exact 362-byte
native retrieval. The [result](../../test/results/context-api-runner-native.log)
and [environment](../../test/results/context-api-runner-native-environment.json)
record terminal 0, 802 unchanged sources and no cleanup failures. Identity,
initial authority/retention and wrapping-key fixtures remain synthetic, and the
runner executes in the test process with the actual Pod-bound token. This does
not establish an in-Pod regional executable or public workflow. The independent
two-start-namespace case and full combined suite remain to be qualified.

The next composition is authenticated connector-to-regional dispatch with the
existing request lifetime, protected role provisioning, and the existing
publication/download flow. No public endpoint, Helm runtime flag, synthetic
production authority or automatic recovery activation is introduced here.
