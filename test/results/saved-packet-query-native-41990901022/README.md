# Second installed saved packet query attempt: failed

[Native41990901022](https://github.com/phihos/asservat/actions/runs/41990901022)
tested `9bf84fcc6b8d0b8651c51dfc3e6a9f277581c98c`. Go and harness exited 1;
Go took 713.646 seconds. CI41990784851 separately passed all 15 jobs. This
installed campaign remains failed.

Both fixed summaries passed. The first raw `pcap_query` returned Pending,
establishing admission through the corrected nonempty-filter SQL branch. The
immediate same-key Begin retry then returned HTTP503. No query page, query/native
parity or completed native download is qualified by this attempt.

The retry has a new audited operation ID. The application called strict
`PermitQuery` without registering that invocation in the existing query-call
journal. The real adapter requires its exact call row; earlier unit fakes
returned success without it. A stricter audited-path regression and a fresh
compiled-role PostgreSQL regression reproduce the missing-row refusal. The
correction registers only an exact keyed Begin repeat, retaining current
authority, original query/grant/deadlines and the existing journal's bounds.
Corrected qualification is separate and pending at this checkpoint.

All 4,255 reported source hashes match the exact Git commit. Sources remained
unchanged, cleanup failures were empty and build scratch was removed. ZIP
249,864 bytes matches server SHA-256
`f48f7cc9324b332b71794f53514d79a8ff0d39a1e08d949385363b261cfac76c`;
all extracted members match their originals. The 15 deterministic gzip members
in `archive-manifest.json` retain original logs, terminal API records, source
and ZIP readbacks. Each was decompressed and checked byte-for-byte. No failed
assertion is promoted to a pass by source or cleanup checks.
