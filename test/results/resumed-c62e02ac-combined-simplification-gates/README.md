# Combined simplification gates

Candidate: `98f7e181bca3d075c3b42adefc604a993f22e1ac`. This combines the
API execution credential consolidation (ADR-217), consumed download preflight
observations (ADR-218), the focused SQL download discriminator and corrected
fixture-only guarded cleanup. Installed native56 is separate and pending.

| Gate | Actual exit | Wrapper duration | Scope |
| --- | --- | --- | --- |
| Specification, architecture, design, Go dependencies | 0 | 12.461 s | Canonical contracts and dependencies |
| Selected real PostgreSQL/S3 execution and download cases | 0 | 74.734 s | Shared compiled execution role/pool, preparation boundaries, permission revocation during a lock wait, historical publication and original-authority download dispatch to first Job port |
| Five fresh-install public-role cases | 0 | 41.147 s | Grant matrix, unknown claim, lost completion, held lock and recovery after lock |
| Cleanup fixture race compilation | 0 | 43.658 s | Compilation only, before the ADR-217 cherry-pick; no tests executed |

The SQL selection passes all twelve recorded case/subcase names, including both
compiled verifier/publisher paths. The shared pool holds three connections,
refuses a fourth under deadline/cancellation, releases/reacquires, and denies
excluded writes. The dispatcher test deliberately stops at the Job-create port;
it cannot establish native bytes or explain native55's exact failure.

Both real-service harnesses record 2,759 source hashes matching the candidate,
unchanged during execution, actual test exit 0 and no cleanup failures.
Independent Docker read-back confirms their owned containers/networks absent.
The design/SQL wrappers also compare all 3,785 tracked non-result sources.
Fixture human/protected-source roots remain synthetic; these are scoped
integration results, not installed-workflow or broad first-release completion.

`cleanup-compile` records hashes for the two changed integration helpers. It
addresses native55's separate refusal of raw fixture administrator deletion by
using the original accepted installer actor under the unchanged guard. A
fixture-only exact-name DELETE grant exists only during final cleanup and is
removed by UID. Retained failures are left intact. Native behavior remains to be
qualified by the installed run.

Raw commands, outputs, exits, source checks and cleanup read-back are retained
under the named subdirectories. No gate was skipped, weakened or inferred from
partial output. The full Go gate on this candidate remains pending.
