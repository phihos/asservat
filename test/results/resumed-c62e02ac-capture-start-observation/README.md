# Request-owned capture start observation

Baseline: `840f27fc338f0c170a4f6069bc95db4c109bbfaf`. ADR-216 candidate; no external fixture was run for this record.

The runner RED actually failed its repeated-call assertion (Go exit 1, 0.003s): target, eligibility, capability and retention were each read three times; process was read four times including completion. It first completed the actual runner with synthetic effect ports, so this was not a setup rejection.

The composed RED actually reached the first `PrepareAPIExecution` and failed its duplicate-prelude assertion (Go exit 1, 0.040s): two accepted-work reads and 36 observer + 12 probe HTTP requests. It composes real `RegionalAPIContextStart`, router, `HubOperations`, runner, evaluator and concrete protected capability adapter over loopback TLS. SQL, identity, retention, signing and regional peer replies are synthetic. Preparation deliberately refuses after recording its valid input, so no SQL row or key effect is claimed.

The same composed assertion passes after the handoff: one accepted-work read and 18 observer + 6 probe HTTP requests. Clients use the installed opening limiter, 50 QPS / burst 100. One capability read includes two complete protection checks and two source snapshots, each of which also brackets its ConfigMap GET with namespace reads. The earlier manual estimate of 14 observer requests omitted those four namespace reads and was corrected to the measured 18.

The successful direct runner now performs one target/eligibility/capability/retention observation and two process reads including the retained final completion proof. The complete composed successful path's capability reduction from four reads to one (96 to 24 HTTP requests) follows from these measured components and the source graph; this fixture stops before a successful SQL preparation. It is not an installed successful-capture measurement or proof that every native54 refusal had the same cause. RED timings without race and GREEN timings with race are not a speedup comparison.

## Verification

- Focused race: exit 0; execution 1.215s, bootstrap 1.162s.
- Full affected race: exit 0; execution 1.259s, bootstrap 32.260s, contextstart 2.784s, mtls 35.042s. This includes the existing unknown-preparation/concurrent-replay coverage.
- Existing collector pin/projection regressions under race: exit 0; Kubernetes 1.192s. Actual adapter tests retain Pod/namespace/controller replacement refusals and no native disclosure on failure.
- Scoped diff check: exit 0.
- Independent read-only review by ci_change_detection: no remaining blockers; source hashes checked against focused GREEN.

Tests cover original caller/target/capability/retention/recovery/process/parent expiry and cancellation after wrapping and readiness, exact local handoff identity/client/capture/target/pin/incarnation, actual evaluator scope refusal, unchanged checked values across SQL calls, SQL refusal propagation, returned-process conflict, next-operation identity changes, conservative lost replies and closed keys. The local fake SQL refusal is not the pending real SQL lock-wait qualification.

Every JSON run record contains the exact command, environment, actual Go exit, elapsed command time and before/after source hashes. Python wrappers preserve the Go exit in that record; they themselves completed successfully after recording expected RED exits. `tool-observations.json` identifies the terminal tool outputs. Final byte snapshots use `.go.txt`, and `source-sha256.json` matches the full affected race inputs. The tracked patch excludes the new test files, whose full final snapshots are included.

`prior-attempts/` is not product-failure qualification: the first composed setup omitted namespace resourceVersion and failed before preparation. The next run reached preparation while the expected observer count still used the incomplete manual estimate. The final `composed-red` uses the corrected expected count and independently fails the duplicate accepted-read and capability-read assertions against unchanged baseline runtime.

External current-SQL fence and complete installed lifecycle qualification remain pending. No deadline, retry allowance, QPS, burst, schema, privilege or wire format was changed.
