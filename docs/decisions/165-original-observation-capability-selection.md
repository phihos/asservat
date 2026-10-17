# ADR-165 — Original observation capability selection

Date: 2026-10-14. Status: accepted; component qualification passes; no runtime
selection. Requirements: REQ-FED-001/003 and REQ-DEP-003; existing scenarios and
TASK-03 / TASK-11 retain traceability ownership.

## Problem

[ADR-150](150-operation-owned-native-observation-proof.md) requires the installed
owner, hub worker and regional connector to agree on the observation protocol
(`owner-observation/v2`) from the original installation onward. Before this
change, the installed resource journal, the owner bootstrap plan/claim/selection
and the owner deployment input could only express `owner-observation/v1`.
Observing a newer file later must not upgrade an existing installation, and an
older file must not downgrade a v2 one.

## Decision

- `InitialRuntimeResourceState`, `OwnerBootstrapPlan`, `OwnerBootstrapSelectionClaim`
  and `OwnerBootstrapSelection` carry an optional `observationFormat`. Omission
  keeps the original v1 bytes exactly. The only explicit value is
  `owner-observation/v2`, and it requires both provider-installed layouts.
- `NewObservationProviderInstalledRuntimeResources` selects v2 **before** the
  first resource claim. The value is part of the root's binding digest, so a v1
  and a v2 root built from identical inputs have different bindings. Every
  validator (resource state, bootstrap state/plan/body, deployment binding and
  owner projection input) requires the root's original format. Mixed or unknown
  values are rejected, never adopted.
- `OwnerBootstrapSelectionProducer.ReadObservationParticipants` is available only
  to a v2 root. It derives the original owner observation pin and the HWORK
  caller pin from the same two genuine native brackets as `ReadWorkerCaller`. It
  makes no further API or SQL call and selects no replacement Pod. Owner and HWORK
  must differ in Deployment and account.

The result is ephemeral provenance. It publishes no backend projection, grants no
runtime authority and does not change `RunHubAPI`. Existing v1 installations and
their readers are unchanged.

## Verification

- [component-1](../../test/results/installed-observation-selection-component-1/result.json)
  failed in one never-before-run staged test. That test built a second resource
  root inside an operation fixture whose API state had already advanced past the
  root's source-guard pins. The test now builds both roots from the same fresh
  preparer. Its final `Read` assertion was removed: without a v1 journal it could
  not prove non-adoption, which the mixed-state test checks through the same
  `valid()` predicate.
- [component-2](../../test/results/installed-observation-selection-component-2/result.json)
  passed every race group but failed its canonical step, because the runner
  invoked the system Python without the required spec extras.
- [component-3](../../test/results/installed-observation-selection-component-3/result.json)
  passes compile, six race groups (64 parents), vet, and the spec, architecture
  and Go-architecture checks, with unchanged sources and removed scratch.

## Remaining

The backend projection and receipt, owner promotion, regional process (now under
[ADR-168](168-rotating-cluster-enrollment-credential.md)'s credential model),
HWORK direct-holder selection, and installed two-cluster qualification remain
pending.
