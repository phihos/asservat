# native99 — S-02 exit checks in one workload cluster PASSED; second cluster join refused (1d1e0966)

`TestInitialBootstrapChainWithRealServices` exit 1 after 1846.7 s. Every check of the first
regional workload cluster passed (see milestones.txt): browser submission, MCP capture, exact
duplicate replay and idempotency Conflict with one admission row, collection/verification/
publication, approved inspection, read-only scope refusal, native download, Range plus If-Range
resume, catalog minimization, browser/MCP preview, case and extract parity, browser native download
(SHA-256 equal to MCP), unrelated-user refusal identical to absent objects, Stop after Deny, Deny
revocation, failed cleanup retaining charges, verified deletion and expiry refusal.

The second workload cluster enrolled, then `installer-cluster-join` refused with
`permission source identity changed`: the join always wrote slot 1, and the installed profile
allows one catalog slot (`OwnerClusterCatalogSlots = 1`). Both are being fixed.
