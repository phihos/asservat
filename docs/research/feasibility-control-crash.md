# PostgreSQL authority and native crash-path feasibility

Executed 2026-10-09 after the maintainer authorized the next two spikes. [Executable sources, failures, hashes and results](../../experiments/control-crash/README.md) are retained. These are partial EXP-01/05/11/19 and SC-INV-002 results, not completed release gates or production implementation.

## Findings that refine the design

1. **Keep PostgreSQL and short explicit transactions.** The real database reproduced oversubscription with an unlocked aggregate check and prevented it with the proposed locked parent/counter approach. Grant, capacity and work admission remained atomic under the tested contention and backend termination.
2. **Specify current time after all blocking authority/accounting locks.** `now()` is transaction-start time. A grant could expire during a lock wait while that predicate still passed. Even `clock_timestamp()` is insufficient if evaluated before a later blocking artifact lock: the initial publication code reproduced exactly that defect. Reordering the check fixed the regression. Dispatch and delivery still need their own current checks.
3. **Keep the small Rust local helper.** A static prototype transferred real kernel cores, including a fault in nested PID 1, into local encryption; the exact generated executable opened both complete native cores in GDB. The tested helper has no remote dependency and only `libc` beyond its standard library.
4. **Bound every IPC phase with one absolute deadline.** Missing receivers and full listen queues refused quickly; handshake/read stalls released the crashing processes around two seconds in this VM. A per-read timeout renewed for every chunk would not establish the same total bound. Synchronous remote refill remains excluded.
5. **Distinguish admission from final evidence completion.** EOF after a limit, timeout or lost receiver cannot certify a complete core. The prototype uses an explicit clean-end frame; final reports are atomic and separate from initial admission. An oversized stream was encrypted as an incomplete artifact, with no claim it could be analyzed.
6. **Keep spent/uncertain state across retries and receiver loss.** A dropped SQL COMMIT acknowledgement resolved through the original operation key without spending again. A locally consumed crash entry remained unavailable after receiver restart. These are separate tests, not proof of a distributed exactly-once transaction.

The clock semantics are documented by [PostgreSQL's time functions](https://www.postgresql.org/docs/18/functions-datetime.html#FUNCTIONS-DATETIME-CURRENT); its [isolation documentation](https://www.postgresql.org/docs/18/transaction-iso.html) explains why ordinary aggregate reads need additional serialization. The failure and success claims above come from actual retained tests, not documentation alone.

## SQL experiment

PostgreSQL **18.6**, official image pinned by digest, ran non-root on a private Docker internal network with no published service, two CPUs, 768 MiB RAM and a disposable data volume. The client used pgx **v5.11.0**, a maximum of 32 pooled connections, five-second statement and one-second lock timeouts. Fsync and synchronous_commit were on. [Exact fixture/version](../../experiments/control-crash/results/postgres-fixture.json), [server settings](../../experiments/control-crash/results/postgres-version.txt).

| Test | Actual result | Scope limit |
| --- | --- | --- |
| Unlocked aggregate admission | Two concurrent transactions admitted 16 units against an 8-unit ceiling | Deliberately unsafe baseline; confirms a row CHECK alone cannot enforce the aggregate |
| Last grant / last capacity | Of 64 contenders, exactly one acquired the final grant start; exactly one acquired an 8-unit non-context allowance. Losers leaked no starts | One primary and simplified known rows; not hierarchy-scale throughput |
| Protected/context/object capacity | Heavy A/C use did not consume B's protected allocation. A retained context capacity at its hard ceiling. Object count was independently constrained | Logical integral counters; no S3 physical-capacity boundary or fair I/O scheduler tested |
| Idempotency | 32 equivalent submissions created one operation/reservation/work item; changed digest was rejected | Compact synthetic identity model, not full source/principal/client canonicalization |
| Expiry during locks | Reproduced stale `now()`; post-lock current-time admission rejected without spend. Publication regression failed before the fix and passed afterwards | Clock-skew/backward-jump policy and remote authority freshness remain untested |
| Revocation versus admission | A committed revocation defeated an admission waiting on the same grant row | No IdP, Kubernetes SAR or disconnected node permit involved |
| Combined result allowance | Two artifacts/four client children shared one 64-unit pool; only eight of 64 concurrent 8-unit spends succeeded. Collection-start exhaustion did not revoke result access | Committed-artifact, client/capture, count and parent checks only; full action/digest/audit/retained-audience model remains separate |
| Unknown charge / deletion acknowledgement | An indeterminate reservation remained charged. Repeated trusted deletion acknowledgements released capacity once, without refunding the consumed action | The acknowledgement is injected; actual backend deletion/version inventory is not tested |
| Lost COMMIT reply | Fault wrapper read and discarded a real server COMMIT acknowledgement; replay of the original key returned the existing operation without a second spend | Single connection fault, not network partition/failover coverage |
| Backend death inside admission | Killing the transaction backend before COMMIT left no partial grant/capacity/work records | No remote side effect was started |
| Serializable predicate | An unprotected write-skew conflict aborted with SQLSTATE 40001; a fresh complete retry saw exhausted capacity | Bounded retry/backoff under sustained contention remains to be qualified |
| Work leases | Audit-pending work was not claimable; 24 workers claimed 12 distinct items; a reclaimed lease rejected the prior completion fence | A Boolean models audit acknowledgement. No object audit or remote execution, and SKIP LOCKED does not prove fairness |
| Abrupt database restart | SIGKILL/restart with the same volume preserved an acknowledged denial and uncertain-charge marker | Single-primary crash recovery only; no standby promotion, old-primary fencing, PITR or restore gate |

The final ordinary suite has **14 passing tests under the Go race detector**, with the post-restart test skipped there and passed separately. [Final log](../../experiments/control-crash/results/sql-test.log), [restart](../../experiments/control-crash/results/sql-restart.log), [publication failure before correction](../../experiments/control-crash/results/publication-expiry-before-fix.log). The first suite found a race in the test's connection-fault wrapper when pgx opened an asynchronous cancellation connection; atomic first-connection selection corrected that harness without disabling the race detector.

The lab uses a compact test schema, string IDs, synthetic credentials and generic counter units. It is not a production migration. Database TLS, least-privilege roles, the full configuration/grant/retention hierarchy, parent publication audits, row lifecycle, workload scheduling and OIDC are not qualified. No SQL state stores real evidence.

## Kernel core experiment

The VM was new Ubuntu 24.04, Linux **6.8.0-142-generic**, amd64, two vCPUs and 2 GiB RAM. No host mounts or existing cluster were shared. The generated C fixture ran as UID 65534 with RLIMIT_CORE=0 and deliberately accessed invalid memory. The kernel invoked the helper with `%P %s %u`; the receiver validated the initial-namespace PID and process start time against prepared test entries. A separate test put the fixture at PID 1 in nested PID/mount namespaces.

The helper used a 16 MiB input bound, 64 KiB buffer, two-second monotonic deadline, three-second alarm and nonblocking Unix/stdin I/O. It entered a dedicated cgroup with 64 MiB/eight-task limits and a 20% CPU quota; the receiver had 96 MiB/32 tasks and one CPU. `core_pipe_limit=2` bounded concurrent kernel handoffs. The receiver and debugger each ran without external network interfaces. These settings and numeric results are experimental, not production defaults or latency promises.

| Final case | Maximum observed time until process reaping |
| --- | --- |
| Complete native core | 115.6 ms |
| Complete core from nested PID 1 | 114.4 ms |
| Absent receiver / full listen queue | 15.7 / 15.6 ms |
| Missing permit / expired permit / wrong start identity | 7.5 / 15.6 / 7.5 ms |
| SIGKILL, no core expected | 1.4 ms; no artifact |
| Stalled handshake / stalled reader | 2,019.3 / 2,017.3 ms |
| Oversized 40 MiB fixture allocation | 114.7 ms; incomplete encrypted output |
| Receiver killed after acceptance | 22.2 ms; spent entry retained |
| Retry after receiver restart with spent entry | 7.5 ms; rejected |
| 16-process crash burst | 2,019.7 ms; two helper connections, excess cores skipped |

These are one final run per case, measured by the VM harness including its scheduling/wait overhead. They are not percentile estimates or a hard real-time guarantee under arbitrary node pressure. [Full results and GDB backtraces](../../experiments/control-crash/results/crash-results.json), [kernel observations](../../experiments/control-crash/results/vm-kernel-tail.txt).

Both complete artifacts contained **4,640,768 native bytes**, were encrypted with prepared Tink Go primitives, decrypted with matching SHA-256, and opened in GDB with `crash_here` and `main` frames using the exact generated executable. Plaintext existed only in pipes/memory and bounded `/run` tmpfs for that local-tool test; the test removed native files afterwards. Persistent evidence files were ciphertext. The oversized case retained **16,732,160 native bytes** and was explicitly incomplete/unverified, rather than calling a truncated ELF prefix a valid core.

Peak charge in the named helper cgroup was **602,112 bytes**, with peak two tasks. Receiver charge peaked at **91,475,968 bytes**, including its charged cache across repeated lab runs. These are cgroup accounting observations, not whole-system overhead or per-process RSS. No OOM was recorded. The configured CPU quotas did not actually throttle during these short runs, so sustained CPU-pressure behavior remains untested.

The initial PID-1 fixture used `raise(SIGSEGV)` and exited without a core; replacing it with a real memory fault made the intended test meaningful. This is consistent with namespace-init signal restrictions described in [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html). [core(5)](https://man7.org/linux/man-pages/man5/core.5.html) documents initial-namespace pipe handling, `%P`, RLIMIT_CORE being ignored for pipe delivery, and the special/unbounded behavior of `core_pipe_limit=0`. The experiment does not claim these rules make every runtime or managed node compatible.

The static-pie helper was built with Rust **1.96.1**, `libc` **0.2.190**, and the host GNU toolchain; its ELF ABI note names Linux **6.1**. It worked on the tested 6.8 kernel. A static binary is not proof of the proposed 5.15 floor or arm64 support: qualify a pinned compatible build environment and both architectures before release.

## What remains unproven

- **Durable crash evidence:** keys in this receiver are prepared but memory-only, not prewrapped by KMS. Receiver/key loss makes the remaining ciphertext unrecoverable in this lab. Production must implement the already-specified durable wrapped envelopes, audit/prepaid permits, copy inventory and recovery protocol before declaring readiness.
- **Kubernetes process attribution:** this spike tests Linux PID namespaces directly, not K3s/containerd/CRI-O attribution, pod ownership, target replacement, LSM/user-namespace behavior, helper deployment/upgrade or two managed providers.
- **Helper/receiver protocol:** root peer credentials and an allowlist are a narrow prototype. Production still needs the complete I-03 identity/version/epoch binding, negative peer tests, explicit timeout/cap/rejection reasons, bounded loss reporting, receiver cgroup/termination qualification and safe packaging/uninstall under node failure.
- **Resource guarantees:** kernel dumping work and the crashing process are outside the helper's cgroup. A node-wide pipe ceiling does not establish per-workload fairness; memory/storage pressure, filesystem stalls, slow-key preparation, collector epoch recovery and storm scheduling remain gates.
- **Production authorization/durability:** the SQL and crash experiments are independent. No full distributed grant, local CAS, audit, KMS/object-store, OIDC, multicluster or restore workflow was exercised.

The VM's original crash handler and pipe limit were restored, a simulated foreign writer was preserved by the ownership check, and the disposable resources were removed. [Cleanup verification](../../experiments/control-crash/results/cleanup.json) includes unchanged workstation crash settings.

## Recommended next implementation work

Proceed to S-01 and S-02: the authority/storage foundation and the first complete low-impact context investigation across UI, MCP and native download, including expiry and verified deletion. First finish the versioned artifact-frame/index/key/commit contract using the prior storage spike; do not freeze its experimental format or enable privileged mechanisms merely because these samples passed. Preserve the remaining mechanism/operational gates as explicit enabling conditions, rather than expanding this isolated lab into an unreviewed product implementation.
