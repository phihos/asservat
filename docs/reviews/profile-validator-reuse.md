# Shared immutable manifest validation

The profile writer preparation path compiled the embedded schema graph for each
prepared artifact. A local 64-holder composition exhausted its 256 MiB cgroup
while writing a profile. Compile the immutable graph once per process instead;
validation still creates independent request state. No target, evidence,
authority, or verification result is cached. Public contracts and validation
rules are unchanged.

The production change adds one `sync.OnceValues` initializer. It adds no workers,
requests, permissions, configuration, scheduler, or codec changes. Deterministic
embedded-schema compilation failures are retained for the process lifetime.

## Existing measurement

The disposable, unprivileged local Docker probe used the actual
`ConnectorRecordings`, prepared artifact writer, 8 MiB codec, and TLS S3 client
with synthetic authority and a server that acknowledged and discarded ciphertext.
It prepared 64 holders, overlapped the listed number of 262,008-byte PCAPNG
uploads, and wrote a 128 MiB synthetic trace-shaped input in 17 multipart parts.
The trace was deliberately not semantically valid. No publication was attempted.
The memory and memory-plus-swap limits were both 256 MiB.

| Variant | Packet uploads | HeapAlloc after 64 holders | Sampled cgroup high-water mark | Result |
| --- | ---: | ---: | ---: | --- |
| Per-preparation compilation | 2 | 107.3 MiB | 238.7 MiB before OOM | Exit 137, OOMKilled |
| Shared compilation | 2 | 15.1 MiB | 192.0 MiB | Exit 0 |
| Shared compilation | 4 | 14.1 MiB | 197.9 MiB | Exit 0 |
| Shared compilation | 8 | 19.4 MiB | 196.8 MiB | Exit 0 |

These are sampled HeapAlloc values without forced GC, not retained-live-byte
measurements. The two-upload comparison reduces that sample by 92.3 MiB. The
baseline's final OOM peak was not sampled. Every run recorded unchanged sources
and no cleanup failures. The probe included its test binary and local S3 server,
but excluded installed Kubernetes/control clients and node HTTP input buffers.
It therefore establishes neither full connector RSS/headroom nor workload
fairness. The configured 500m CPU limit showed no throttling in these short runs;
these are not throughput qualifications.

Provenance: base `7c869f8daf80a3e57526b6faf70383f12a276ad7`; original probe source
SHA-256 `9a4ab13ef6f3489d1ca683ca80b828e74674aded8a1b659fc4baceb9b3acd933`,
shared-compilation probe source
`d05300cc64782c215dcdc4c1f758745689867c326ca7999d21619742e3a89cae`.
Raw `writer-memory-current-2` and `writer-memory-shared-schema-current-{2,4,8}`
reports remain in the separate cooperative-upload-writer lab worktree; the lab
and unrelated scheduling experiments are not included in this production change.

## Focused verification

Both commands used `TMPDIR=/home/phil/.cache/asservat-build/tmp`:

- `go test -race ./internal/adapters/objectstore/manifest -count=1`: passed, 2.993s.
- `go test -race ./internal/adapters/objectstore -count=1`: passed, 7.815s.

The new concurrency regression uses 32 goroutines, each validating 16 valid and
mutated profile manifests through the same validator, and requires every
mutation to fail. Integrated repository gates and installed qualification remain
the responsibility of the combined profile candidate.
