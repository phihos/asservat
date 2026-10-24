# API execution credential consolidation: local evidence

ADR-217 replaces three credentials and pools in the same hub process with one
`api-execution` login and one cold pool of three. The exact former 46-grant union
is retained; ordinal 94 replaces retired ordinals 21–23. Public inventory is
79 and hub public projection is 44. Typed ports, current SQL effect checks,
original deadlines and the process-wide 32-connection governor are unchanged.

The new inventory and exact-union regressions failed against unchanged baseline
production code: actual exit 1 (21.204 s including compilation). Both RED test
snapshots match the RED before/after hashes. Distinct snapshots were reconstructed
from those unchanged files and verified by `red-snapshot-verification.json`; the
initial cache snapshot used a colliding basename. Original logs remain unchanged.

All four GREEN commands exited 0: full contracts/PostgreSQL race (38.209 s),
selected bootstrap/Kubernetes race (581.862 s), race-instrumented integration
compilation (24.325 s, no tests run), and design gates (12.103 s). These are command
wall times; package times and exact commands/environments are in their raw logs
and receipts. The wrapper terminal was session 43847, chunk 4de0f2. All 3,782
tracked/untracked non-result source hashes were unchanged before/after each
command. Byte-identical manifests are stored once with their explicit mapping.

Independent source review found no blockers: exact grant union, role identity
pins, no nested selected-pool acquisition, contract counts, and excluded mutation
checks were inspected. Existing real-service tests now use one compiled role and
pool for read/prepare/record, including concurrency, original expiry and lock-wait
revocation; their presence and compilation are not an execution result.

No external SQL, Kubernetes or provider fixture ran for this archive. Fresh role
provisioning, actual SQL lifecycle/current-check qualification and the installed
journey remain required on the combined candidate. No runtime performance saving
is claimed. A facet-specific injection now reaches sibling execution privileges;
a full hub-process compromise already had all three credentials.
