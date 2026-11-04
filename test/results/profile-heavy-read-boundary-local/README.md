# Local heavy read-boundary evidence

These local components investigate the failed installed heavy comparison at source
`b5d42f9557897b40ca5d6506ffc3c9bd4946f373`. They do not fix or qualify that workflow.
The production earliest authority cutoff remains unmeasured. No production code,
VM, retry policy, permission, resource limit or operation deadline changed.

## Actual native reader discriminator

The retained temporary test uses the exact two previously downloaded 10s CPU
profiles (SHA-256 `853f5ed2f0a6afa8c64dcef9d0715e49b9435966406cde3b108f599a63084a9d`
and `efd5dac937c228106a344b5bbd9b7340035f761a979bbca010b8fa6a676fae6f`).
The payloads are retained once in the adjacent installed-failure archive, not
copied here. It re-encrypts them using existing product framing/manifest helpers
and runs actual NativeContextReader.ReadApprovedProfileComparison, ComparePprof,
pinned TLS range reads and two remote key-child protocol adapters. Authority,
receipts and key admission are synthetic. No SQL, deployed worker, actual KMS,
acquisition or cgroup is part of this test.

The report preserves the actual command and exit0 (package56.764s). Both normal
clients pass in1.293/1.329s. The actual S3 constructor makes the supplied HTTP
client timeout30s, including the worker-shaped client originally supplied5s.
Six-second body pauses on each input pass in13.351/13.334s. An artificial6s parser
pause passes in7.347s. Deliberate body work beyond the original20s context fails
at20.002s without valid output, despite all six key roles being consumed. This
rules out the proposed five-second S3 total-body cap locally; consumed roles
alone do not prove payload completion.

Both actual initial setup failures are preserved: nonexistent temporary constant
(exit1, compilation only) and a temporary custom transport rejected by the
constructor (exit1, reader never ran). The final source SHA is recorded in its
report. The transient `go test` binary hash was not retained and is unknown.
Two existing focused contract runs also exited0: both-source original authority
bounds and paid poll result ownership. They use synthetic/injected-clock facts
and do not measure installed authority time remaining after worker startup.

## Six-second real TLS conversation

The retained temporary test extends the existing production
HubWorkerAdmission/router/registration/two-frame-gate/TLS-h2/RunWorkerConversation
seam with a6s approved reader. It preserves original source/scope/operation
bindings, operation20s, the stricter original fixture parent8s, initial peer5s
observation, and current peer/serving observations each bounded to5s. The current
serving fake rereads now+5s as production does; it does not retain the existing
fast fixture's fixed expired timestamp.

Actual exit0, whole process6.023859s; approved read6.001058s, ctxErr=nil;
AcknowledgeProjection and NativeJoined assertions pass, one completion and one
reader call,14 operation observations. The initial observation expired at
13:35:13.965390Z; the reader returned after13:35:14.970Z. Original stricter command
cutoff13:35:16.965305Z and operation cutoff13:35:28.965390Z were not renewed. This
rules out a surviving five-second projection transport timer in this local
composition. It does not exercise heavy objectstore reads or deployed authority.

The report contains exact invocation, UTC start, source/test and binary digests.
The compilation command was:

```
env TMPDIR=/home/phil/.cache/asservat-build/tmp GOTMPDIR=/home/phil/.cache/asservat-build/tmp GOFLAGS='-buildvcs=false -p=2' go test -c -o /home/phil/.cache/asservat-build/profile-heavy-lease-repro/native.test ./internal/transport/native
```

The initial compile exit1 (unused imports, no test ran) and successful final
compile exit0 logs are retained. Temporary source was removed and its isolated
worktree was clean after the actual test. The binary is not archived.

## Preservation and verification

`archive-manifest.json` identifies every exact cache source, source/stored sizes
and SHA-256 digests. All logs, reports and temporary source are deterministic
gzip (level9, mtime0). Readback verifies stored hashes, inflation against original
cache bytes, deterministic recompression and both report source digests. No
native payload, test binary or private fixture file is added here. No enclosing
installed qualification is claimed. No source changes or tests were run while
building this archive.
