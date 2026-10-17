# ADR117 declaration checkpoint

Status: frozen outside live. This checkpoint implements the first phase of the assigned preparation supervisor; credential, activation and guarded handover continuation is still required and remains active.

## Scope

Twelve changed paths: eleven new files and the guarded `cmd/asservat/main.go` hunk. No SQL, module, chart, shared catalog/index, AGENTS or public workflow changes. The copied `initial_preparation_resources.go` is byte-identical to its base and excluded.

`initial-prepare` loads only the fixed protected projection and current administrator/probe token files. Its concrete supervisor creates/resumes one producer-owned root and nine typed declarative objects, preserving the original identities and one pending CAS intent. Root continuity is long-lived; every effect/current proof keeps its original five-second deadline, and the command has a one-minute run budget. The private schemas describe the new desired/root documents, not activation authority.

The trusted Helm bootstrap owns immutable desired inputs and pinned continuity/staging policies; the mutable root is deliberately not Helm-managed. Kubernetes excludes VAP/binding resources from VAP protection, so those are trusted inputs, never retryable producer objects. Exact pins cannot silently change on chart upgrade. Nine permanently occupied producer keys prevent late CREATE revival; the six RBAC objects retire only to empty rules/subjects with the same UID. DELETECOLLECTION is matched through oldObject.metadata.name because native static admission attributes may omit request.name.

No credential, TokenRequest, executable Pod, provider, witness, ungating or activation operation inherits declarative CREATE replay. Normal errors provide fixed, secret-free resume/remedy copy. The UI is not asked to hand-edit journals or UIDs.

## Verification actually run

- Focused race: terminal 0, `qualified-race.log`; Kubernetes 12.539s, bootstrap 1.049s, contracts compiled, command compiled, integration 1.054s. Native test skipped without owned fixture environment.
- Narrow vet: terminal 0, `qualified-vet.log` (empty on success).
- Private schema validator: terminal 0, `private-schemas.log`; both schemas and references validated, one valid root accepted and three malformed roots rejected.
- No real Kubernetes test, full repository gate, Helm install or external fixture was run by this agent.

Commands, from live working directory with this sparse overlay:

```sh
TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go test -race -p 2 -overlay=/home/phil/.cache/asservat-build/planning/initial-preparer-20261011/overlay.json ./internal/adapters/kubernetes ./internal/bootstrap ./internal/contracts ./cmd/asservat ./test/integration -run 'TestInitialPreparer|TestInitialPreparationSupervisorWithRealKubernetes' -count=1
TMPDIR=/home/phil/.cache/asservat-build/tmp GOMAXPROCS=2 go vet -p 2 -overlay=/home/phil/.cache/asservat-build/planning/initial-preparer-20261011/overlay.json ./internal/adapters/kubernetes ./internal/bootstrap ./internal/contracts ./cmd/asservat ./test/integration
/home/phil/.cache/asservat-build/spec-venv/bin/python /home/phil/.cache/asservat-build/planning/initial-preparer-20261011/check-private-schemas.py
```

Parent native selection: `TestInitialPreparationSupervisorWithRealKubernetes`. The test is discoverable as a new file; no shared fixture hook is required. It has a 120-second overall context and 30-second cleanup context, no intentional long sleep. It uses actual API/native policies and fixture-owned administrator bootstrap. A test transport retains the first named Role CREATE before transmission, allows a second identical request, and releases the first after retirement: actual API must return AlreadyExists without refilling authority. This is network-delayed request qualification, not proof that the API server already processed a timed-out request. It separately checks named/collection deletion, namespace/default normalization, all four RBAC refill denials and mismatched root UID. Trusted cleanup occurs only after retained requests join and is not product retirement.

## Merge

`manifest.json` contains each exact base/new SHA-256. New paths must be absent; changed main base must match. `initial-preparer.patch` contains only those twelve paths. Parent owns shared architecture/decision indexes, implementation progress, AGENTS and any integration of the two private schemas into broad checks. The stage source is immutable after this handoff.

## Remaining assigned work and limits

The nine entries plus root use ten objects. The trusted bootstrap namespace, two policy/binding pairs and five probe/token/RBAC anchors are a separate fixed ten-object set. Later activation-specific Pod, six final guard objects, three public witness/fleet/startup inputs, three private/probe credential inputs and target preparation journal bring the currently envisaged installation to about 34 fixed objects; the later exact compiled inventory must be recounted before implementation. The root's 64-entry/48-KiB bound is not increased. Runtime purpose-separated provisioning remains a distinct bounded phase.

Next typed continuation must retain original private credential bytes in independently protected stable bootstrap state, compose existing immutable SQL state and role provisioning, create the inert Pod and final inputs, record explicit original-to-final staging handover, run existing `initial-install`, and retire credentials with observed denial. Neither a root nor a successful declaration grants activation/recovery authority.

A finite Never Pod and original five-minute claim create a real recovery boundary: pre-witness positively no-effect failure may support a separately qualified new attempt; claimed/uncertain activation must reconcile the exact original attempt, not mint new credentials/witnesses or silently renew the claim. A changed staging guard likewise needs explicit recorded handover, not current-pin adoption. This checkpoint makes no claim to have solved those remaining parts or enabled a runnable Helm investigation service.
