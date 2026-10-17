# ADR123 private probe checkpoint

Frozen nineteen-path checkpoint, outside live; no SQL/module/dependency changes.
It adds one pinned bootstrap private-state Secret and one bounded original probe
TokenRequest to the actual initial-prepare command, while retaining public setup
and the gated Pod. It does not provision SQL/provider credentials, ungate/activate,
retire credentials or enable any public runtime. Continue the accepted SQL and
provider composition in the separate initial-sql-provisioning-20261012 stage.

The immutable desired plan pins the original private Secret UID and explicit API
audience before guard/root creation. Mutable private progress is producer-owned,
not Helm-owned. The closed 16KiB document records original root binding, anchor
intent/receipt and one <=5s issuance claim/positive response. Acknowledged first CAS
alone permits TokenRequest. Concurrent losers, unknown replies and replays cannot
issue again. Live producer recovery can persist only its retained authenticated
original response; a new process needs that response already in the pinned Secret.
Actual expiry/Secret/account/audience checks remain current. No credential or
secret-payload digest enters the public root. Historical plans without the new
fields retain byte-identical compiled guards, proven with old-source digests.

Private continuity permits only the canonical irreversible inert terminal shape,
but there is no product clearing method before positive credential retirement and
joined writers. Native terminal-shape testing is explicitly a fixture-admin guard
check, not a product retirement claim. The method has separately current five-second
phases; no aggregate five-second invocation limit is claimed without a parent bound.

Shared pure provider validation rejects bad HTTPS origins/ports, CA representation/
validity, SQL settings and key names before one-use preparation effects. It is also
used by existing hub-worker/initial-installer validation. No network/trial mutation
is used for syntax checks. Existing fixture roots now use correct DER bytes.

Integration detail: parent-owned catalog.yaml needs exactly
`internal/adapters/providerconfig` in C-21 package_roots. No shared index/catalog/
progress files are in this package. The shared native fixture change merely adds
an optional trusted plan-setup callback after cleanup registration and before
original guard creation; keep current other agent/parent hooks when merging.

Actual checks:

- qualification-final.log: TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2
  go test -vet=off -race -p2 -overlay=.../overlay.json ./internal/adapters/kubernetes
  ./internal/bootstrap ./internal/contracts ./test/integration -run
  'TestInitialPrivate|TestInitialPreparationRejectsStatic|TestInitialPreparationFinalInputs|TestInitialPreparerClosed|TestHubWorkerProjectionPins'
  -count=1. Terminal0: Kubernetes32.224s, bootstrap1.085s, contracts1.025s,
  integration1.060s(no native fixture selected/executed).
- bootstrap-contracts.log: full bootstrap/contracts -race -p2 -vet=off with the
  same overlay, terminal0 (4.389s/1.308s).
- validation-before.log: meaningful before regression, original checkedServices
  overlaid into the same stage. All13 invalid public-provider cases failed as
  expected because preparation accepted them; the fixed final run passes.
- policy-baseline*.log: diagnostic runs against the unchanged original policy
  implementation measured the two stable hashes. Their expected placeholder
  failures are not test passes. The final golden tests pass for both historical
  profiles without the private capability.
- check-schemas.py via existing spec-venv Python, terminal0: two positive private
  documents/eight negatives, Draft202012 with actual format checking and offline
  references. schema-check.log. Runtime enforces timing/state relationships.
- vet.log/qualification-first.log retain the Go overlay limitation: vet cannot
  chdir into a new package directory absent in live. This is not a claimed vet
  pass. Parent will run real integrated vet; a small external vet-work source view
  was prepared but no vet/build ran from it. No workaround touched live/module files.

Native selection for parent:
`^TestInitialPreparationPrivateProbeWithRealKubernetes$`
(and rerun public input producer if desired for the corrected DER fixture).
It uses real original producer/TokenRequest/TokenReview/API guards, while trusted
bootstrap creates the pinned private Secret and explicitly determines the owned
lab API audience. It tests original replay without a second TokenRequest, protected
Secret deletion/mutation, joined producer closure and irreversible native inert
shape. Existing fixture120s budget remains; no external run has occurred here.
The owned API fixture credentials are never production authority evidence.

Required next work: SQL binder and one-use exact target-state Secret persistence;
actual InitialSQLRoles provisioning with maintenance credentials outside Pod;
scoped OpenBao issuance/revocation and explicit S3 capability; exact immutable target
provider projection; independent final guard proof/handover and one-use original-Pod
ungating; historical activation resolution and positively joined retirement. Lost
or expired original private credentials still require qualified recovery. Do not
reset root/UIDs, renew original dates or infer quiescence from GET/409/expiry/history.
