# Pod-status assessment

C-06 `planning.AssessContext` produces the assessment for the
`builtin-pod-status-v1` diagnostic under REQ-ASM-001–005. It consumes a
compiled plan without I/O, trial collection or an extra approval. Caller
eligibility is checked before the result is shown. The report is not a
collection permit, benchmark or safety certification.

The report binds the plan, reviewed rule and capability digests. It reports
one incident pod, no ongoing observation and an `onTrigger` Kubernetes
snapshot. The 4096-byte native output ceiling is a configured limit; it
excludes the API response, encryption/object overhead and collector memory.
Resource pressure, coexistence and overhead are unmeasured, so impact is
reported as unknown. The explanation names API collection, encryption and
upload and invents no CPU or latency percentage or application pause.

The saved native projection holds status counters and Kubernetes identifiers.
The encrypted manifest also holds namespace, assignment and identity
provenance, including issuer URL addresses/paths, so retained exposure
includes those categories and potentially personal identifiers. Reading the
Pod response can transiently encounter workload configuration, literal
environment values and annotations; excluding them from the saved
representation does not hide that exposure or claim anonymity. The assessment
text contains no secret or workload-specific discovered value.

Retention uses relative ages from submission preparation. Waiting for
collection consumes that lifetime; acquisition does not restart the clock.
Admission stores the effective access and deletion deadlines on the artifact
row (ADR-330 D12), and accepted retries keep them. A short requested lifetime
is not replaced by the administrator's larger maximum. Duplicate policy
definition digests are consolidated in the public schema while the compiled
scope keeps every source identity. The report promises no absolute expiry
before submission. Automatic deletion applies to managed copies; the handling
codes state that external copies cannot be recalled.

The browser/MCP wire uses `anchorRule: submissionPreparation` for this preset;
other mechanisms keep the acquisition anchor. Assessment rule v2 encodes the
anchor in both execution-class digests. Because previews are stateless
(ADR-330 D9), a changed rule changes the plan digest and submission reports
the change.

C-20 `transport/presentation` gives browser and MCP the same typed assessment
and lifecycle projections. The maximum 64-policy response fits the 24 KiB
output ceiling.
