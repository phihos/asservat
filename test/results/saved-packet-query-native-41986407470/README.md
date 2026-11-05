# First installed saved packet query attempt: failed

Native run [41986407470](https://github.com/phihos/asservat/actions/runs/41986407470)
tested PR169 source `329a48fc14f173668dea717c07874a8046da4a84` with
`continuation-manual-raw`. Go and harness both exited 1; Go took 697.503 seconds.
This is a failed campaign. Required PR CI41986382075 separately passed all 15
jobs on that source; green CI does not replace the installed failure.

The approved recording was published, and both the read-only MCP fixed summary
and actual installed React summary passed their current source/account/key
checks. The first raw `pcap_query` request then returned HTTP 503. No query page,
query/native parity or completed native-download outcome is qualified by this
run.

The retained PostgreSQL report identifies SQLSTATE `42702` in
`context_packet_query_window_valid`: its PL/pgSQL loop variable `i` conflicts
with the unqualified digest-byte column in the nonempty-program digest checks.
Earlier managed-service fixtures used an empty program and bypassed this branch.
Both compiler- and program-digest queries require qualified column references;
the local regression and correction have separate evidence. No timeout or
authorization change is justified by this failure.

All 4,255 reported source hashes independently match the exact Git commit.
Sources remained unchanged, cleanup failures were empty and build scratch was
removed. These cleanup facts do not turn failed functional assertions into a
pass. The original artifact ZIP is 251,719 bytes; its downloaded SHA-256 matches
the server digest
`17d6b7b1b4fcde7a3249281c87a7576a230a5d9ee164d802bee4fbe65d405773`.
Every ZIP member matches its extracted original.

`archive-manifest.json` preserves 17 deterministic gzip members, including the
original six artifact files, terminal run/job records, source audit, verification
script, review records and failure log. Each was decompressed and compared with
the original bytes and SHA-256. The ZIP is represented by its verified digest.
PR169 remains open pending the corrected local and installed qualification.
