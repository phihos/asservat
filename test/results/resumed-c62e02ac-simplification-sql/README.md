# SQL qualification for the structural simplification

This archive preserves the failed role matrix, its diagnostic reproduction, the
fixture correction and both passing SQL qualifications. No production deadline,
role grant or SQL check was weakened to obtain the passing results.

| Run | Frozen commit | Actual exit | Go package / harness seconds | Result |
| --- | --- | --- | --- | --- |
| [Initial five role cases](roles/result.json) | `c6be50ca` | 1 | 19.506 / 33.875 | Matrix fails at final inventory verification; four other scenarios pass. |
| [Diagnostic matrix](roles-diagnostic/result.json) | `abb48c73` | 1 | 6.426 / 44.241 | All 81 claims and receipts exist; the fixture fleet observation has expired. |
| [Corrected five role cases](roles-current-observer/result.json) | `114dd899` | 0 | 46.527 / 131.646 | Matrix, unknown claim, lost completion, held lock and recovery after lock pass. |
| [Full capacity fixture](readers/result.json) | `114dd899` | 0 | 79.525 / 90.857 | All seven shared-pool readers and the existing capacity scenarios pass. |

The diagnostic records 5,376 milliseconds of provisioning against an original
five-second fixture fleet observation. Its immediate SQL read confirms expiry,
with suspension and recovery blocking both false. The positive fixture calls
now use the existing independent fleet observer, with unchanged five-second
observations and joined shutdown before later assertions. Deliberate privilege,
unknown-result, lock and recovery failures retain their controlled setup.

The new shared-reader subtest passes in 1.77 seconds. It uses the actual compiled
metadata login, verifies its manifest/grants, and exercises all seven typed
adapters concurrently on one cold pool with `MaxConns=7`, configured under the
unchanged 32-connection governor. It checks excluded SQL operations, current
identity scope, the eighth acquisition's deadline, capacity reuse, and caller
expiry, identity expiry and cancellation after a real permission-row wait.
It does not saturate the entire process governor or measure installed latency.

Every fixture has 2,750 recorded source hashes matching its stated commit before
and after execution, and an empty cleanup-failure list. Exact owned container
IDs and owned network absence are independently checked. The first wrapper
incorrectly classified Docker's lowercase `no such object` response: its raw
result remains unchanged, and [fresh cleanup readback](roles/cleanup-readback.json)
records the corrected absence verdict. This does not alter the failed test exit.

The separate [SQL-generation check](sql-generation/result.json) exits 0 in
0.378 seconds: all 54 generated files match sqlc v1.31.1. This checks generated
source consistency, not runtime SQL behavior.

Each run retains its command, environment, full harness/test logs, source hashes,
provider failure logs when emitted, and cleanup readback. Copies are byte-identical
to the cache evidence; [copy and sanitization checks](archive-copy-verification.json)
record their hashes. No live fixture descriptors, passwords, bearer tokens or
private keys are included; the credential-pattern scan found no matches and no
log redactions were needed. `manifest.json` covers the complete archive.

SQL/TLS/SCRAM, encrypted custody/publication, PostgreSQL, S3 and OpenBao are real.
Protected Kubernetes/root and human inputs remain synthetic. The complete Go
gate and execution of the combined five-command installer with the full installed
investigation remain pending. Helm lifecycle evidence is archived separately.
