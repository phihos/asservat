ADR222 independent source-only review by /root/recover_decisions
Worktree: /home/phil/Projekte/asservat-hub-credentials-c62e02ac
No edits, Go builds, tests or external operations performed.

No extra-grant or pool-envelope blocker found. Both existing public and owner
compiled grant bodies remain byte-identical after their extraction into duty
helpers. The new ordinary union contains exactly the 35 former hub duties after
nine explicit exclusions from the old 44-member list. Owner union uses the same
six former duty bodies. Sort/dedup preserves exact column-level privileges and
function signatures. New permanent ordinals and changed layout digest reject old
retained identities without adoption. Browser settings and cleanup stay outside
the hub projection. Pool maxima: owner6 + ordinary18 + resolution1+1 + pinned
capture3 + separately acquired cold readers3 =32. Aggregate role limits81 and25
cover four retained processes plus the serialized verifier. The download-plan
nested worker-configuration reader remains in a separate pool. Owner routing's
configuration transaction occurs between independent pool queries, not under an
outer held transaction.

Integration blockers identified and sent parent:
1. public_downloads.go:54 still opens worker-owner and :237 constructs it, while
publicPoolPlan rejects this removed duty. ADR221 removal must be integrated before
qualifying public startup; no compatibility credential framework is needed.
2. Real SQL fixtures remain on previous physical layouts. public_runtime_roles_test.go:
241 selects retired identity-read; 408-417 derives aggregate20 as physicalMaxConns
although the installed verifier correctly accepts18 or1; 426 deletes retired
names from a new manifest, leaving it unchanged for a negative test. Also update
api_execution_pool_test.go's retired role/cold3/13limit, hub_metadata_readers_test.go's
retired role/cold7, installed_download_preparation_test.go's three retired roles,
capacity fixture role maps, installed_permission_observer_test.go and continuation
projection-file readbacks. Preserve existing effects/current-authority negatives
and adapt physical layout expectations without weakening runtime verifiers.

Source hashes record the reviewed core; parent's wider fixture adaptation was
ongoing. Review is not a frozen integrated-source or runtime qualification verdict.
