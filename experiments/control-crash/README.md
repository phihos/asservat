# SQL authority and native crash-path experiments

Executed 2026-10-09 after maintainer authorization. This is an isolated concurrency model and VM mechanism lab, not the product schema, controller, security boundary or production core helper. See [findings and limits](../../docs/research/feasibility-control-crash.md).

All identities, counter units and process contents are synthetic. The SQL suite uses actual PostgreSQL 18.6/pgx v5.11.0; no SQLite/mock substitutes. A separate Ubuntu/KVM VM runs the static Rust helper, Tink-encrypting local Go receiver and generated crashing C program. The workstation's crash handler is untouched. No existing cluster, public service, paid resource or real user evidence is used.

## Results

- [SQL suite](results/sql-test.log): 14 tests passed with the Go race detector; the post-restart test is explicitly skipped here and [run separately](results/sql-restart.log) after killing/restarting only the owned fixture. Tests include deliberately unsafe baselines; their PASS means the hazard was reproduced, not that the unsafe method is acceptable.
- [Crash matrix](results/crash-results.json): 14 cases passed, including real nested-PID-1 memory fault, matching executable/GDB opening, refusal, stalls, byte cap, receiver loss, spent-entry restart and a 16-process burst.
- [Failed publication regression](results/publication-expiry-before-fix.log): the experiment originally published a child after grant expiry during an artifact lock wait. The final code validates current time after that lock.
- [Initial test-harness race](results/sql-initial-race.log): pgx's asynchronous cancellation opened another connection through the injected dialer and overwrote the captured connection pointer. Atomic first-connection selection fixed the harness; the race detector remains enabled.
- [Initial PID-1 fixture failure](results/crash-initial-pid1.log): explicitly sending SIGSEGV did not kill the namespace init process. The final fixture causes an actual invalid-memory access. Earlier receiver admission reports also lacked finality; final reporting now uses atomic replacement and the harness waits for completed outcomes, including partial cores.

[Execution manifest](results/execution.json), [VM input record](results/crash-execution.json), [SQL input record](results/sql-test.json) and [cleanup](results/cleanup.json) preserve source hashes, actual command exits and tested boundaries. No whole EXP gate or product TASK is complete.

## Reproduce SQL tests

Prerequisites: Go 1.27, Python and Docker. Run from the workspace root:

```sh
python3 experiments/control-crash/postgres.py up
python3 experiments/control-crash/run-sql.py test
python3 experiments/control-crash/run-sql.py restart
python3 experiments/control-crash/postgres.py down
```

The image is digest pinned. The fixture uses a Docker internal network, no published port, non-root PostgreSQL process, read-only root filesystem, dropped capabilities, 768 MiB/two-CPU limits and a disposable anonymous data volume. Scripts verify ownership labels before mutation. They never accept an arbitrary production database URL. The runner supplies explicit synthetic credentials and uses the fixture's private bridge address; TLS/production database roles are not qualified by this lab.

`restart` intentionally SIGKILLs that fixture and starts it with the same volume. It verifies an acknowledged denial/uncertain-charge marker survived single-primary crash recovery with fsync/synchronous_commit enabled. It does not test standby promotion, split-brain fencing, synchronous replication, PITR or recovery from an old backup. The SQL model uses compact string identities and generic integral units to isolate transaction behavior; it is not a proposed replacement for the normative UUID/domain schema or a physical-storage benchmark.

## Reproduce the crash lab

Use [VM preparation and commands](vm/README.md). The lab creates a new user-owned QEMU/KVM VM with no host mounts or shared kernel. It pins the Ubuntu image checksum and pins SSH trust from cloud-init's local serial output. Host binaries are built unprivileged and copied to that VM; only the VM installs the core pattern and experiment cgroups.

The helper has a two-second monotonic handoff deadline, a three-second alarm, a 16 MiB byte ceiling, nonblocking local I/O and a fixed-size buffer. The tested build is a 1,314,704-byte static-pie Rust/glibc executable using only `libc` beyond the standard library. Static linking does not prove compatibility with all proposed node kernels; its ELF ABI note names Linux 6.1 and only Linux 6.8 amd64 was tested.

The receiver runs in a fresh network namespace without external interfaces, uses prepared in-memory Tink keys and fsynced spent markers, and writes ciphertext to its lab disk directory. Successful native decryption goes to the VM's `/run` tmpfs solely for bounded offline GDB verification; these plaintext files are then removed. Key wrapping, recoverable durable keys, real audited permits, Kubernetes/CRI ownership, scope/revision checks, spool admission and deletion ledgers are **not implemented**. Receiver/key loss makes remaining ciphertext unusable in this experiment; that is not the production recovery design.

The restart case first consumes an entry through an injected local helper invocation while the target is alive, then restarts the receiver and causes a real crash. The persisted spent marker prevents reusing that entry. The crash-burst limit is node-wide, not evidence of workload fairness. The receiver's root peer check is a narrow test, not complete local-service identity qualification.

The owned VM, private SSH keys/cache, PostgreSQL container/volume/network and lab artifacts were removed after recording results. Shared compiler/package/image caches were retained. Cleanup is filesystem/resource removal, not a physical-media erasure claim.
