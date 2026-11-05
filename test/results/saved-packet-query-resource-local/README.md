# Final local saved packet query resource evidence

Measured source: `b27594380f0229ef75e688f775fe0a8e40f5e056`. Candidate reuse: `360ba3f60d71c500dff6e5c6512ce38a71421f0d`. All **1812** tracked repository Go/embed/module/fixed-probe inputs matched each commit in one 3624-blob Git readback and still matched current files. The candidate changes only two integration upgrade test files, outside this compiled dependency set. This is relevant-input equivalence, not a whole-repository runtime qualification.

Fresh static CGO-disabled test binary SHA256 `fbf01d25464e1268ec18fc8b5f0158271e8fd25bcaeaa8e96b9ff0aa93ec6e5d`; fixed probe `7ec2674deffe5f75908c851bb1dc9e22d491a3a6e3dfc8e80475f840edbfcfcb`; cached image `sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e`. Actual build commands, overrides and exits are retained. The separate producer exited 0 in 1.010099s, with peak RSS 140676 KiB; generation/encryption happened outside all consumer cgroups.

| Shape/mode | Whole-cgroup peak MiB | Consumer/container/probe/cleanup exits | Result |
| --- | ---: | --- | --- |
| payload-output/complete | 90.44531250 | 0/0/0/0 | valid 60-row page |
| tiny-prefix-wire-cache/complete | 128.44921875 | 0/0/0/0 | valid 100-row page |
| payload-output/cancel | 26.28125000 | 0/0/0/0 | no result; read error and receiver joined |
| payload-output/source-error | 27.73828125 | 0/0/0/0 | no result; read error and receiver joined |

Both exact 8 MiB native inputs, all prepared file hashes and the final source/binary/probe hashes were read back after execution. Native PCAPNG block/count/captured-byte/wire-length values were also independently parsed:

- payload-output: 8388608 native bytes, 5475 saved records, 8212500 captured bytes, 5376 distinct original wire lengths; SHA256 `e9b45d95b6930aa87ea88303c45e6b41071119a9774faf911db0e3e59c8db274`.
- tiny-prefix-wire-cache: 8388608 native bytes, 233011 saved records, 233011 captured bytes, 232912 distinct original wire lengths; SHA256 `2390b57c20f33aeb4632270f225ec908f57c9914d762d3ebe6c061b147301d4e`.

Each consumer used a fresh 256 MiB cgroup, `memory.swap.max=0`/current 0, configured `cpu.max=50000/100000`, nonroot `1000:1000`, cap-drop ALL, no network and a read-only root with immutable input binds. Before/after probes and original Docker inspect records agree; all max/OOM counters were zero. Both complete cases consumed three synthetic TLS unwrap bindings and returned valid bounded pages; cancellation and source-transport failure returned no page, consumed three bindings in these runs, and joined. Cancellation joined in 176851 ns. Replay made no additional key request. All four actual consumer, container, probe and cleanup exits were 0; the final owned-container lookup was empty.

**CPU 500m is configuration only.** The tiny-prefix case recorded 1.232044 CPU seconds during a 0.851350s whole-cgroup observation, with two additional CPU periods and zero throttled periods. These short intervals do not demonstrate effective or sustained 500m enforcement, throughput or maximum-load qualification. Cgroup peaks and process MaxRSS are retained as separate observations; these are not universal memory maxima.

The measured component includes the actual approved receiver, outer NativeContextReader, 256-instruction Go VM, all 16 selected fields/64-byte saved-frame prefixes, canonical/full framed EOF authentication, and local TLS range/key providers in the consumer process. Current source/key authority is synthetic. It excludes hub libpcap compilation, SQL/current human/grant authority, real KMS, native owner/public transport, worker bootstrap/enrollment and an installed maximum-input claim. The original production 20-second conversation bound is retained. No source edits, image pulls, host tuning, forced GC, GOMEMLIMIT override or consumer reruns were used.

The historical `10e324ab` preparation initially failed when building an ignored probe package; an explicit `main.go` build succeeded before its producer/consumers. Three small original setup records retain that failure. This final `b2759438` refresh used the explicit-file build from the start: all setup commands, the fresh producer and all four fresh consumers passed. The historical measurement is not relabelled as this run.

Original metadata, commands, logs, source inventory, counter/probe/inspect records and fixture hashes are deterministic gzip members (`mtime=0`, empty filename). `manifest.json` records original and compressed sizes/SHA256. Every stored member was decompressed and compared byte-for-byte with its source. Binaries, native payloads, ciphertext and private fixture DTOs are excluded; their hashes remain in the reports. No runtime or qualification was rerun for archival.
