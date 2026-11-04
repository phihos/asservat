# Shared trace and heap browser preparation

One test-only candidate combines the prepared trace native workflow and heap
browser workflow, so they can share a full CI matrix. Each installed workflow
still needs its own fresh environment and terminal result. No production code,
permission, resource limit, budget or deadline changes.

All five preparation patches match their original stable patch IDs. A sixth
commit corrects an existing Python assertion that still expected the earlier MCP
heap sequence: its RED exit1 becomes GREEN exit0 while preserving summary SQL
verification before browser native preparation. All34 regional, three trace and
two heap selector tests pass; affected integration races exit0 in4.334s.
Independent final review found no blockers.

The provenance lists fourteen unchanged source scopes against the earlier local
built React/browser qualification. That synthetic local evidence is reused with
its original source attribution; this does not claim an installed browser or
trace result. An initial log-redirect setup failure ran no test and is recorded.
All seven cache originals were deterministically compressed and read back.
