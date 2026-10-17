# Initial pod-status assessment

C-06 `planning.AssessContext` implements the assessment for the exact
`builtin-pod-status-v1` diagnostic under REQ-ASM-001–005. It consumes a currently
valid compiled plan without I/O, trial collection or an additional approval.
Caller eligibility remains mandatory before exposing the result. The report is
not a collection permit, benchmark or safety certification.

The report binds the plan, reviewed rule and capability digests and retains the
plan's original observation deadline. It reports one incident pod, no ongoing
observation and an `onTrigger` Kubernetes snapshot. The 4096-byte native output
ceiling is a configured limit; it excludes the API response, encryption/object
overhead and total collector memory. Current resource pressure, coexistence and
overhead are unmeasured, so the impact is explicitly unknown. The explanation
identifies API collection, encryption and upload; it does not invent a CPU or
latency percentage or an application pause.

The retained native projection contains status counters and Kubernetes identifiers.
The encrypted manifest also retains namespace, assignment and identity provenance,
including issuer URL addresses/paths. Retained exposure therefore includes those
categories as well as potentially personal identifiers. Reading the underlying Pod
response can transiently encounter workload configuration, literal environment
values and annotations. Excluding those fields from the saved representation
does not conceal their transient exposure or assert anonymity. No secret or
workload-specific discovered value is included in the assessment text.

For this exact pod-status workflow, retention uses relative ages from the first
submission preparation, as specified by [ADR-103](../decisions/103-durable-context-previews.md).
Time waiting for collection consumes that lifetime; acquisition does not restart
the clock. The first admitted registration fixes the anchor and effective dates,
and accepted retries retain them. Access age and deletion due age come from the
effective resolved deadlines; a short requested lifetime is
not replaced by the administrator's larger maximum. Duplicate policy definition
digests are consolidated for the public schema, while the compiled scope retains
all separate source identities. The report promises no absolute evidence expiry
from preview time. Preservation is described as possible until a current scoped
policy projection establishes more. Automatic deletion applies to managed copies;
the required handling codes state that external copies cannot be recalled.

The shared browser/MCP wire explicitly uses `anchorRule: submissionPreparation`
for this preset. Canonical and runtime output validation reject its former
acquisition anchor, while generic assessments retain that anchor for other
mechanisms. Assessment rule v2 includes the anchor semantics and changes both
execution-class digests, so old unsubmitted drafts require a fresh review.
Existing accepted-operation lookup still precedes draft/rule validation and
retains the original evidence registration; historical encrypted bytes are not
rewritten. The console validates the typed anchor before showing its fixed
pod-status explanation.

C-20 `transport/presentation` provides the same typed assessment and lifecycle
projections for browser and MCP. Canonical offline JSON Schema tests check their
wire shapes, while planning tests cover scope/freshness, independent ownership,
clamped retention and the distinction between deletion due age and maximum age.
The maximum 64-policy response is checked against the 24 KiB output ceiling.

`TMPDIR=/home/phil/.cache/asservat-build/tmp go test -race
./internal/application/planning ./internal/transport/presentation` passed in
[the component report](../../test/results/context-assessment-unit.log). This is
component verification; public preview integration and measured collector impact
remain separate work. Other capture mechanisms require their own qualified rules.
