# Exact shared-principal query accounting

The installed browser assertion assumed every human account had only one query.
The existing product intentionally excludes ClientID from that account key:
browser and MCP queries share the human's quota while retaining distinct actors.
Only the test readback is corrected. It now compares the allocation with the
positive sum of query units for exactly that root/account; original per-query,
root/workload, key, worker-resource and closure checks remain.

The real-service regression runs two complete query lifecycles with different
clients against the same published metadata PCAPNG using compiled hub/key roles.
Both consume independent three-role key sets and close native/public batches.
Independent SQL proves two clients, one account, two queries and four allocated
units. The old assertion fails on that correct state (Go/harness1,10.404s); the
corrected assertion passes (Go/harness0,11.264s). Each run matched all4,140 source
hashes to base `e280290e` plus the three recorded test-only overrides, kept sources
unchanged and completed cleanup. Job/Pod/issuer/identity inputs remain synthetic;
this is not installed workflow proof.

Affected installed-driver races and final integrated `make pre-push` exited0.
The latter includes481 console tests. Existing product, browser-driver and SQL
schema sources are unchanged from the preceding qualified local/service/CI
snapshots. Fresh exact-candidate CI and installed native PCAPNG parity remain
required. Numeric accounting diagnostics now distinguish the actual counters.

All14 archived gzip originals passed complete decompression/length/SHA256
readback. The manifest retains original locations and exact hashes. Five owned
uncompressed service outputs were moved to the cache only after verification;
their mapping is retained. No user files or private fixture inputs were moved.
