# First-profile capability and live submission connection

This is a disabled composition checkpoint for REQ-EXE-002 and S-02. It reuses
the API execution class and runner from ADR-104/106. It does not mount public
collection or create a new regional transport.

`ContextCapabilitySource` implements the existing preview and execution reader
ports. It reads only `context-capability.json` in one immutable ConfigMap with
independently installed namespace/name/UID, exact administrator policy/binding
pins and a distinct non-administrator denial probe. Its closed content must
equal the installed first-profile tuple: root, installation, cluster, recovery
epoch, revision, enabled flag, collector version/image and compiled projection
digest. Unknown, duplicate, aliased, omitted, null or extra JSON fields are
rejected; whitespace does not change the canonical revision digest. There is no
default qualified image or caller-selected source.

Each observation checks current recovery and actual guard enforcement, reads
the exact immutable source, checks enforcement again and rereads the source.
The original five-second caller/source/guard/recovery minimum survives all
blocking work. A final recovery check can only shorten that deadline. A source
observation is not permission, a permit, a rollout acceptance or proof that a
collector is running. The runner independently verifies its exact protected
process image and current acquisition authority. Installed provisioning of this
qualification remains required.

The exact capture-intent reader selects one root/capture pair rather than the
old global two-row pending page. `ExactCaptureIntentPublication` remains the
historical acknowledged-only reader. New admissions use the purpose-separated
[ADR-132 protocol](capture-intent-lifecycle.md), whose
`CaptureOperationPublication` preserves the original first-write and bounded
reconciliation cutoffs. Its distinct completed reader reuses independently
acknowledged provenance without writer, journal, KMS or storage I/O, including
after the audit write interval. An unresolved original intent cannot obtain
another first-write permit from a later continuation. Historical acknowledged
receipts alone never authorize a start.

`ContextSubmission` delegates existing preview/check/resolve behavior and joins
new admission, exact intent acknowledgement and `StartContext` in the original
current caller's request. Bootstrap's `APIContextStart` invokes the actual
`APIContextRunner`; it accepts only its existing AlreadyStarted or
StoredPendingVerification outcomes, neither of which means publication succeeded.
This adapter belongs in an authorized regional composition. It does not justify
giving public hub processes collector SQL credentials, wrap keys or acquisition
access, and no deployed command currently constructs it.

Downstream failure preserves the accepted value internally with an error; it
does not undo admission or claim no effect. Metadata still expires at its
original response bound. Accepted replay stays passive, including after target
or preview disappearance. Explicit acquisition continuation after a lost or late
admission now uses the explicit `continue_acquisition: true` request branch in
[ADR-134](../decisions/134-explicit-capture-continuation.md). It never admits a
missing key, replaces the accepted target or renews its original interval. Only
the acknowledged first execution-preparation winner may generate keys; an
existing prepared row is uncertain and cannot retry that effect. Started/stored
replay remains passive. Continuation is never hidden in polling or resolution.
The existing durable
deadline observer/progress service must be composed so pending work is not
presented as indefinitely progressing. No background identity queue is added.

## Qualification scope

The [native capability case](../../test/integration/context_capability_native_test.go)
now passes with actual Kubernetes admission and separate read/probe RBAC. It
checks exact image/cluster/epoch binding, source/binding replacement, missing
protection and unchanged resource versions across positive and negative dry-runs.
The fixture supplies accepted recovery and image qualification; it does not
establish them. Actual source hashes and cleanup are recorded in
[implementation progress](../implementation-progress.md).

Focused tests exercise the actual TLS capability source/protection adapters
against synthetic API responses, exact SQL row decoding, receipt reuse and the
request-owned submission service. They cover source/guard/recovery changes,
original-bound expiry after blocking reads, pending audit, cancelled/denied
callers, wrong original intent, uncertain start, passive replay and preserved
admission identity. Synthetic recovery/proof replies are not production authority.

The staged `TestContextAdmissionWithRealServices/native-api-runner` case enters
the existing regional fixture through real C09 preview/request, separate current
ADR-132 SQL credentials, encrypted intent acknowledgement and its read-only
completion port. It injects an unavailable start before execution preparation,
then checks that a fresh explicit continuation reaches the actual API runner
without another admission or key preparation. Ordinary replay remains passive.
The first native runs failed inside reviewed admission, before regional start.
After correcting audit cutoff precision and the fixture lifecycle budget, the
native case passes with one original execution/local CAS and 362 exact bytes
verified, published and read after target/executor deletion. See
[implementation progress](../implementation-progress.md) for actual terminal
results and the preserved failures. Its capability,
human and protected installation facts remain synthetic; composing the actual
capability ConfigMap/guard and installed regional transport is still required.
Parent owns the external run and terminal source/cleanup qualification.

The protected capability installer, qualified intent writer lifecycle, regional
start connection, public loader, download runtime bridge and authenticated
native content route remain prerequisites. No public collection switch changes.
