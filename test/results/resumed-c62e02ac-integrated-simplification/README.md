# Integrated simplification qualification and corrections

Candidate before corrections: `bc94a1885ddcfe16825dbf8571934d288a050f44`.
The compile and first design receipts precede it at `9da475cd`; their commands
exit 0 but wrappers exit 1 because the architecture report changed from 1321 to
1314 positive checks. That generated report is retained. Design repeat 02 exits 0
in 13.187154 seconds with 3,837 non-result sources unchanged.

Full `make sql-check go-check` exits 2 after 399.683 seconds with 3,837 sources unchanged.
SQL generation and the preparatory gates pass; non-Kubernetes tests expose:

- a retired physical role still used by a logical-facet privilege test;
- installed owner validation still multiplying six former pools;
- a diagnostic test requiring pointer-identical derived contexts.

The command does not reach Kubernetes groups. Corrections keep the physical
budget and logical grants, and explicitly verify original caller cancellation.
The focused PostgreSQL/diagnostic race tests exit 0 in 39.845625 seconds, with 3,837 sources
unchanged. Independent preflight finds the installed fixture's four retired
bootstrap logins and shared query/native capacity sequencing. Focused owner and
projection tests exit 0 in 25.120 seconds; six owned file hashes are unchanged during that
run. The subsequent three-line post-read cancellation check is recorded in the
final source map and awaits the next parent gate.

Query 01 exits 1 after 52.1217 seconds before lifecycle setup because its invocation omitted
`--fleet`, leaving KMS unavailable. Query 02 adds the required fixture provider
and exits 1 after 27.706955 seconds after four setup subcases pass: migration 71's unparenthesized
JSON extraction/subtraction produces PostgreSQL's ambiguous-operator error.
The exact one-line correction is in the next candidate. Neither run qualifies
the lifecycle. Both source snapshots remain unchanged, harness cleanup completes,
and independent container/network read-back confirms absence.

The installed fixture now uses the shared hub credential. It observes the exact
query worker's original lifetime and natural termination, then requires actual
product cleanup to persist termination and retirement before the distinct Stop
case. It never mutates deadlines, quotas or cleanup state. Current full Go, real
SQL lifecycle and installed qualification remain pending. Native57 remains the
latest installed result; the implementation task continues.

Logs are preserved verbatim. manifest.json hashes every archived file other than
itself. The local three-job CI-partition rerun, when performed, will be recorded
separately from the failed serial command.
