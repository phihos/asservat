# Local heavy-profile resource evidence

These are terminal component results, not installed worker qualification. The
Docker runs used clean source `1d3f6b4feac941ec74e2c73ebb8ac958ec348c9d`.
Archive preparation used rebased source `042f3c218ff1aeea906c0bfeea055e5f06f0b25a`.
The 200 files listed in `source-reuse.json.gz` match between those heads; this
supports reuse analysis and does not retroactively qualify the rebased commit.

The unchanged `TestProfileComparisonEncryptedProcess` produced its inputs in a
separate process, then ran the real framed/encrypted comparison and pinned
loopback TLS reads in two fresh Docker cgroups. Providers, receipts and authority
were synthetic. There was no real SQL/KMS/S3, collector or deployed worker. The
cached BusyBox image was reused without pulls or new images; networking was
disabled except for the test's existing container-local loopback exchange.

| Run | Consumer exit | Charged cgroup memory peak / limit | Result | Cleanup |
| --- | --- | --- | --- | --- |
| Complete | 0 | 272,306,176 / 402,653,184 bytes (259.7 / 384 MiB) | Valid 20-row comparison, six synthetic unwraps, both sources closed | Exit 0, no container retained |
| Cancel second source | 0 | 212,529,152 / 402,653,184 bytes (202.7 / 384 MiB) | Cancellation joined in 138,050 ns, no result, six synthetic unwraps, both sources closed | Exit 0, no container retained |

Both runs recorded zero OOM events and zero swap usage, with `memory.swap.max=0`.
The shell and finite probes count toward the container measurements. The
snapshot does not include its later output/exit tail. Bind-mounted prebuilt
inputs may have host-cached file pages; this is not a cold-cache qualification.

The configured CPU quota was `50000/100000` (`NanoCpus=500000000`), but both
runs recorded no throttling. Complete container CPU usage was 1.475124 seconds
over 1.616293 seconds of Docker invocation wall time. This does **not** establish
effective 500m execution. The host had kernel `7.2.9-2-cachyos` and active
`sched_ext`/LAVD; a causal explanation was not established and the host was not
tuned. CPU enforcement and the installed workload remain unqualified.

The measured inputs each used a **one-second** CPU duration, 100,000 functions,
locations and samples, 1,048,576 frame visits, 16 values per sample, 32,768 numeric
labels, and a 16 MiB-minus-56-byte protobuf. Their native hashes differ from the
**ten-second** prepared installed inputs. The latter manifest is retained only
under `prepared-inputs/`; those bytes were not run in these Docker consumers.
Neither shape covers every parser maximum or the 64 MiB native-input ceiling.

Producer RSS is a per-run observation outside the worker cgroup: the encrypted
one-second producer recorded 416,012 KiB / 1.616 seconds; the separately retained
terminal ten-second harness producer recorded 434,968 KiB / 2.505 seconds.
Neither value is a universal producer requirement or worker memory measurement.

`manifest.json` records original commands and source heads where retained,
artifact sizes, original-byte SHA-256 and gzip SHA-256. Raw source logs keep their
original names; a later filename/rebase does not change their measured source.
The legacy embedded component report calls itself "uncontained" because its
source was deliberately unchanged; the outer Docker inspection and cgroup
records establish the containment actually used for these two component runs.
The standalone final affected-race, harness component/selftest and probe
selftest logs retain terminal success contents, but their exact enclosing
commands, source heads and numeric exits were not retained. They are not
reassigned to either measured or rebased head.

All gzip files use level 9, zero mtime and no filename header. Their decompressed
bytes were read back against the cache originals. No binary, native payload,
private fixture, allowed-signers file or credential is included. No new runtime
checks or external qualification were run while preparing this archive.

The final local `make pre-push profile-preflight` also passed at clean
`02bbbaecad50d81c8c64a9b87b07c9bcfc0056b7`, after rebasing the two resource
changes onto the heap readiness repair `80593f93`:441 console tests,4.694s
capture races and4.469s integration fixture races. Its original log and exact
invocation/exit are retained in the manifest. This adds local integration
evidence; installed resource qualification remains unrun.
