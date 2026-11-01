# Capture profile catalogs: implementation plan (2026-11-01)

S-04 increment 11 (docs/reviews/s04-plan-2026-10-27.md), specs/capture-profiles.md
REQ-CPR-001/002/004/005. Gap audit against main d8ba286b: only the
one-builtin composition path exists (`internal/application/planning/recorder.go`
`resolveBuiltin`, `compositionShape`), with two embedded builtins.

## Slicing (complexity gate)

Multi-component compositions that mix evidence types (packets + syscalls)
need one capture to produce several artifacts. Today a capture carries one
`ContextExpectation` with one native type, so that is an execution change,
not a compiler change. It also needs the snapshot action kinds that arrive
with S-05. It is therefore slice B, after slice A:

- **Slice A (this branch): catalogs.** Organization and namespace
  `CaptureProfile` resources, builtin availability, resolution into the
  existing one-component composition, `list_capture_profiles` /
  `get_capture_profile`, and provenance with source UIDs.
- **Slice B: composition.** 1–8 components, deterministic IDs/aliases,
  identical-snapshot dedup, duplicate-expensive conflicts, aggregate budgets,
  per-evidence-type retention and multi-artifact captures.
- **Slice C: console.** Catalog list, profile cards, plan diff, Save as
  profile (derived namespace profile with ≤8 origins).

## Slice A steps

1. CRD `captureprofiles.asservat.io` generated from
   `specs/contracts/capture-profile.schema.json` (new `scripts/profile-crd.py`
   modelled on `policy-crd.py`); chart RBAC read-only for the hub.
2. Builtin availability: protected installation setting listing disabled /
   deprecated builtin versions; checked at preview, start and history repeat.
3. Resolver port in planning (`ProfileSource`): `builtin` stays embedded;
   `organization` reads the hub namespace, `namespace` reads the target
   workload's namespace only. One bounded LIST per preview, one GET per start;
   the definition digest and source cluster/namespace/object UID are bound
   into `wireResolved` and the `captureProfile` history dependency. Disabled
   versions refuse new previews/starts; deprecated ones warn.
4. Tools: runtime schemas via `scripts/investigation-schemas.py`, use case,
   presentation and MCP registration; browser/MCP parity.
5. Tests: unit (resolver confinement, no shadowing, availability), real
   Kubernetes CRD test (immutability by version, namespace confinement,
   builtin-name impersonation refused, disabled version blocks starts).

## Deferred to slices B/C

Everything listed under slices B and C above, plus the three unshipped builtins
(process-context, go-cpu, http-headers), which are listed as unavailable
entries until their increments land.
