# ADR-319 — Privacy evidence discovery

Date: 2026-11-11. Status: implemented and qualified for SC-PRV-011.
Requirements: REQ-PRV-006, REQ-AUT-005, SC-PRV-011.

Privacy operators need to locate evidence before deciding how to handle a rights
request. Ordinary case reads cannot serve this purpose because a restriction
blocks them, and operator membership does not grant ordinary evidence access.

The Processing console searches published evidence by exact case ID or by exact
cluster, namespace and workload IDs within a half-open acquisition interval.
The case ID is the existing system-issued incident reference. An optional
purpose matches the original accepted purpose exactly. The workload search uses
the retained acquisition anchor. Ring evidence can cover time before its anchor,
so operators can widen the interval when reviewing a request.

Each response contains up to 12 candidates, including the original case, capture
and artifact IDs, native type, data class, effective access and deletion dates,
custody state and recorded direct parent IDs. Retained copies pending deletion
can still appear after ordinary access expires. The original control retirement
date bounds their visibility and any continuation that identifies them. Deleted
artifacts are outside the search. Current publication records capture roots with
empty parent lists. The console reports the lineage recorded by that producer.
Complete derivative, cache, early-erasure and exception coverage remain work
under REQ-PRV-006.

Search reuses the existing processing transaction and compiled hub SQL role.
The case and workload selectors use their existing index ranges. The query
materializes a finite candidate page before reading purpose and type metadata.
The continuation records the last scanned row, so a page with zero purpose
matches can still continue. Every page uses fresh operator authority, original
caller and SQL bounds, and verified publication and custody facts. The result
can select an artifact for the existing explicit restriction action.

`search_processing_evidence` uses the existing browser operation, session,
CSRF, and normal audit lane. The application checks the protected privacy
operator list independently of ordinary evidence scopes. The shared audit gate
acknowledges intent before catalog access and acknowledges the outcome before
delivery. Audit stores keyed input/output digests and returned candidate IDs.
The page limit fits the existing 24 KiB response budget even with 16 direct
parents and escaped Unicode in each candidate. The operation is browser-only.

Migration 150 expands the existing normal-lane operation and input-format lists
and leaves the floor at 149. Down restores the prior functions after checking
for retained search audit rows. An old-image smoke must verify the installed
prior operations with new audit rows present before claiming image rollback.

## Complexity review

1. Privacy requests require discovery even while ordinary access is blocked.
2. The accepted operator authority and evidence lifetime rules apply.
3. Exact selectors cover installations with retained published evidence.
4. The case locator, processing index, audit gate and restriction form already
   implement the underlying patterns.
5. Added SQL grants, credentials and network services: zero.
6. Added fallback modes: zero. Existing audited refusal handles unavailable facts.
7. Added settings: zero.
8. Added dependencies: zero.
9. One bounded metadata query and one existing audit pair per requested page.
   Candidate hydration covers at most 13 rows, including lookahead. There is no
   global index, poll, watch or per-workload job.
10. The SQL expansion preserves earlier operation names. Upgrade, Down and
    prior-image behavior are separate qualification checks.
11. An ordinary case lookup cannot discover evidence while restricted. Exact
    retained selectors provide this workflow with the existing tables.
