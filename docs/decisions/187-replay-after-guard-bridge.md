# ADR-187 — Replay after the guard bridge

Date: 2026-10-15. Status: accepted; implemented. Native qualification passed
([continuation run 23](../../test/results/adr183-continuation-native-23/result.json)):
the bootstrap hook replay and a second continuation after the bridge, with the
guard generation and the journal unchanged.
Requirements: REQ-DEP-001/005, S-02; TASK-11.
Resolves the open item of [ADR-183](183-installer-runtime-continuation.md).

## Context

The guard bridge advances the workload guard by two generations. Every
handover reader pins the original generation and then reports a change.
These all stop after the bridge:

- the passive bootstrap hook: the history protection, the schema check and
  the completed-installation check;
- a rerun of `installer-continue`, at the history read and at the resource
  producer's constructor and current checks.

A `helm upgrade` replays the bootstrap hook and would therefore fail.

`currentHandoverWithFinal` already accepts the bridge's retained guard
(at most two generations later, exact spec, original UID, binding and
administrators). But a fresh process has no bridge object to supply it. The
bridge history reader needs runtime probe tokens and the activation record,
so the hook cannot use it.

## Decision

1. **Compute the retained guard; never adopt stored bytes.** The retained
   policy depends only on:
   - the original plan;
   - the owner Deployment and the two account UIDs;
   - the layout.

   All of these come from the resource journal's receipts. A fresh reader
   reads the journal with a plain GET (the runner may read Secrets), builds
   the bridge administration and guards with the same code as the bridge,
   and selects the phase by the live policy generation. The existing proof
   then requires exact spec equality. A wrong candidate fails as a change,
   and journal bytes only select which candidate is checked.
2. **Bridge-aware reads only.** The read-only handover callers (`ReadHandover`,
   the history protection and its read check, the historical schema check)
   accept the retained phase-two guard. Every effect path keeps the original
   guard:
   - cleanup, launch and staging retirement;
   - schema claims;
   - bridge creation.
3. **The resource producer may reopen after the bridge.** Its constructor
   and current checks accept the bridge phase (probe or retained), so a rerun
   can read the journal and inventory. Creating the journal or writing a new
   claim is refused once the bridge has started. A complete journal advances
   without writes.
4. **The prepare step skips completed cleanup.** It retires the handover only
   while cleanup is incomplete, which is the same condition the retirement
   itself checks.
5. **Continuation rerun.**
   - Existing filled audit Secrets are reopened by name and UID. The journal
     binding pins those UIDs.
   - Once the owner launch receipt exists, the continuation deletes any
     leftover phase-3 inbox (it holds a credential), reports that it is
     already complete, and exits successfully.
   - Partial reruns past the worker launch remain out of scope.

## Consequences

`helm upgrade` replays the bootstrap hook after the continuation. The copy
closure becomes reachable after the bridge; it only deletes bootstrap
copies, which was its pending duty anyway. The bridge-aware reader adds one
journal GET and one policy GET to passive reads after the bridge.

## Implementation

1. Extract the bridge administration builder from the inventory, and the
   guard builder from the bridge constructor. Behavior is unchanged and
   pinned by equivalence tests.
2. `bridgedFinal` and `passiveHandover` in the preparer; switch the
   read-only callers.
3. A bridge-aware resource producer with write refusal.
4. The prepare step's cleanup condition.
5. Continuation rerun: audit Secret reopen and completed no-op.
6. Unit tests per caller and phase. Native: after the continuation, rerun
   the bootstrap hook and a second continuation, with unchanged policy
   generation and journal.
