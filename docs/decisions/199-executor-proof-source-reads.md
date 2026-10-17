# ADR-199 — One source read at each end of the executor proof

Date: 2026-10-16. Status: accepted; implemented and natively qualified
([ADR-196 continuation run 8](../../test/results/adr196-continuation-native-8/environment.json): the installed executor's first cold proof
fits its five seconds).
Requirements: REQ-EXE-002, S-02 regional context start; TASK-03 / TASK-11.
Refines [ADR-173](173-work-scoped-process-observation.md). Found by
[ADR-196](196-regional-cluster-join.md)'s native runs.

## Context

The installed regional executor never finished its cold process proof
within the proof's original five seconds.
[Continuation run 6](../../test/results/adr196-continuation-native-6/environment.json)
measured each attempt:

- The shared observer client made 100–120 API calls before the bound.
- Their transport time totalled 80–150 ms.
- So the elapsed time was limiter wait. Kubernetes clients stay at
  20 QPS/burst 20, so about 120 calls need five seconds.

ADR-173 measured the cold proof at 71 calls. That fixture used a synthetic
connector source with no API reads. The installed proof reads the guarded
connector source six times, at about 15 calls each:

- twice in the opening process-credentials observation;
- twice in the attestation;
- twice in the closing observation.

That makes about 145 calls, which needs at least 6.25 s of limiter time.
ADR-173 rejected raising limits and dropping checks. Neither is done here.

## Decision

The cold executor proof reads the connector source once when it opens and
once when it closes, and every component checks against those two reads.

1. **Open.** The opening read checks the process-credentials observation:
   binding, current client leaf chain against the source's roots, and hub
   registration. It also checks the attestation: binding, workload guard,
   Pod token and live chain. Neither component reads the source again.
2. **Close.** The closing read happens after every other check. It must be
   the same source with the same roles, and the closing process observation
   is checked against it.
3. **Freshness.** The proof's freshness is bounded by both reads, as
   before. Every other check and its order are unchanged, including the
   workload and settings guards, the settings snapshots, the
   Deployment/ReplicaSet/Pod chain, the inputs, the execution account and
   the token reviews.
4. **Other callers are unchanged.** The new `…At` variants take one source
   observation the caller read within the same original interval. They are
   used only by the executor proof. Enrollment, renewal and the cheaper
   recheck keep their own reads.

5. **The close is local.** *Added after run 7.* The process observation
   asks the hub for the leaf's registration. That is a full lifecycle
   conversation, during which the hub has this cluster run its own
   boundary proofs. [Continuation run 7](../../test/results/adr196-continuation-native-7/environment.json)
   reached the closing source read at 4.45–5 s with 109–120 observer calls,
   so that second conversation does not fit.
   - The closing check (`ConfirmConnectorProcessAt`) is now local. It
     requires the same active process, request and installed client leaf as
     the opening observation, and the leaf chain must still verify under the
     closing source's roots.
   - The opening registration's original FreshUntil keeps bounding the
     proof and is never renewed. A hub-side revocation during the proof is
     seen by the next proof, as ADR-173 already accepts for one work's
     observation.
   - A failed proof's diagnostic lists each completed check with its elapsed
     time.

The source is still observed at the start and at the end of the proof, which
are the same bracket points as before. Only the reads in between, which
re-observed the same object within the same interval, are gone.

## Consequences

Without the hub conversation at the close, a cold proof should fit within the
unchanged five seconds. The native run records the actual profile. A source change between the two reads is
still detected at the close. As before (ADR-173), no instantaneous
revocation is claimed.
