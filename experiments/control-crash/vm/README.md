# Disposable crash VM

Do not install this helper or run the VM driver on the workstation. The [experiment boundaries](../README.md) apply. The driver and both binaries require `/root/ASSERVAT_DISPOSABLE_VM`; the helper has fixed lab socket/cgroup paths. This guard is an accidental-use barrier, not a security sandbox.

From the workspace root, `python3 experiments/control-crash/vm/lab.py up` creates a new two-vCPU/2 GiB Ubuntu 24.04 VM and a 10 GiB sparse disk. Then run `pin` after cloud-init emits the VM public host key in the local serial console. Existing disk/key/run state is refused; set `ASSERVAT_LAB_STATE` to a fresh directory for another lab. The default state path is `/home/phil/.cache/asservat-control-crash-20261009` on the recorded workstation. The VM has user-mode networking and a loopback-only SSH forward.

Inside this VM only, install `gcc gdb make python3`, create `/opt/asservat-lab`, and create the guard file. No Kubernetes cluster is required for this specific kernel-path experiment. Nested PID/mount namespaces are tested directly; Kubernetes attribution remains a separate gate.

Build on the host with caches on a disk-backed path, keeping the nearly full workstation `/tmp` untouched:

```sh
CARGO_TARGET_DIR=/path/to/lab-cache/helper-target RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --locked --manifest-path experiments/control-crash/helper/Cargo.toml
CGO_ENABLED=0 GOTELEMETRY=off TMPDIR=/path/to/lab-cache/go-tmp go -C experiments/control-crash/go build -o /path/to/lab-cache/receiver ./cmd/receiver
```

Copy the helper, receiver, [fixture.c](fixture.c) and [run.py](run.py) over the lab's recorded SSH connection to `/opt/asservat-lab/{helper,receiver,fixture.c,run.py}`. The Python lab module's `sshargs()` supplies the pinned connection; pipe each file to `cat` at its fixed destination. Make the two executables mode 0755 and run `gcc -g -O0 -o /opt/asservat-lab/fixture /opt/asservat-lab/fixture.c` in the VM. Retain binary/source hashes before testing.

Run inside the VM:

```sh
ASSERVAT_RUN_ID=run-1 python3 /opt/asservat-lab/run.py
cat /run/asservat-crash/results.json
```

Select a fresh run ID for each repeated invocation. The driver saves/restores the original VM core pattern and pipe limit in a `finally` block, uses `core_pipe_limit=2`, and creates dedicated helper/receiver cgroups. The synthetic crashing process runs as UID 65534 with RLIMIT_CORE=0. The final memory-fault fixture is also tested as PID 1 in a nested namespace. The receiver and GDB each run in a fresh network namespace. GDB uses the exact fixture binary with startup scripts/auto-load/debuginfod disabled.

The helper's cgroup has 64 MiB/eight-task limits and a 20% CPU quota; the receiver has 96 MiB/32 tasks and one CPU. These are experiment settings, not selected production defaults or a bound on work in the crashing process/kernel. Raw core bytes are encrypted before disk staging. Test-only native files are on `/run` tmpfs and are removed after verification. The normal run restores the original hook, including after a simulated competing-writer/uninstall check. A whole-VM failure is handled by disposing of the VM; no host setting depends on guest cleanup.

Copy the final result, kernel tail, tool versions and hashes back before shutdown. `python3 experiments/control-crash/vm/lab.py down` checks its QEMU PID/name and shuts down only that VM. Verify exit before removing that lab's private cache. Do not use `docker prune`, remove unrelated directories or invoke host sysctl/BPF tools.
