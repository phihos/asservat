# ADR-186 — Operation-scoped public role proof

Date: 2026-10-15. Status: accepted; implemented. Native qualification passed
([continuation run 18](../../test/results/adr183-continuation-native-18/result.json)):
all 66 public roles and the projection.
Requirements: REQ-DEP-005, REQ-DB-005, S-02; TASK-11.
Builds on [ADR-173](173-work-scoped-process-observation.md) and
[ADR-184](184-promoted-owner-first-launch.md).

## Context

The public runtime role root proves its full current state on every read:
- the accepted owner configuration;
- the owner workload guard with its probes;
- a self-subject review;
- the owner Deployment;
- the worker binding.

Each read runs that proof twice, before and after fetching the journal. One
role needs three root steps (claim, the SQL step's root read, completion),
which comes to about six full proofs.

The unit fixture measures 53 API requests for a claim, 35 for a read and 53
for a completion: about 141 per role. That fixture has no configuration
probes and a minimal worker binding. At the fixed 20 QPS with a burst of 20,
that is roughly six seconds, more than the original five-second claim
window.

Native continuation runs 12 and 13 stopped while provisioning the second of
66 public roles. Retries cannot fix this, and raising the client limit is
not allowed. The configuration role source already scopes one proof to one
role operation, and ADR-173 reuses one work-scoped observation for the same
reason.

## Decision

1. **One proof per role operation.** The root exposes an operation that:
   - runs one full, bracketed current proof at its start;
   - keeps that proof's original deadline, at most five seconds and never
     renewed.

   The SQL producer runs each role's claim, role step and completion inside
   one operation.
2. **Inner reads reuse it.** A root read inside the operation fetches and
   checks the journal under the operation's deadline, without repeating the
   proof. Outside an operation, reads keep the full bracketed proof.
3. **A fresh proof after blocking work.** The completing write runs one
   fresh current proof first, because the role step's SQL locks and network
   I/O intervene. The claim write follows the opening proof with no blocking
   work in between and needs none.
4. **Write brackets.** Outside an operation every journal write is followed
   by a proof, as before. Inside one:
   - the claim write is preceded by the opening proof;
   - the completion's fresh proof follows the claim write;
   - the completing write is followed by its own proof.

   A claim grants nothing by itself, and role creation keeps its SQL trust
   and root checks.
5. **Unchanged invariants.** No proof extends an original deadline. Unknown
   writes stay lookup-only. Expired claims are never replaced, and the
   journal's own state validation is unchanged.

## Consequences

A role costs three full proofs plus four journal requests, about 56 requests
or under three seconds at 20 QPS, instead of 141. The 66 public roles fit inside the 30-minute window. The SQL producer uses
the operation through an optional interface, so synthetic test roots without
it keep their previous behavior.

## Implementation

1. `PublicRuntimeRoleRoot.WithPublicRoleOperation` and operation-aware
   `read`; a fresh proof in `CompletePublicRuntimeRole`.
2. The postgres producer wraps each role in the operation.
3. Unit request-count regressions; native qualification through the
   continuation.
4. Verification and publication run inside one role operation. The
   projection starts from the opening proof, and its later boundaries still
   prove against it.
