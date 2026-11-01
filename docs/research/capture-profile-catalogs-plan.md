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
2. ~~Builtin availability setting.~~ Dropped under the complexity gate:
   REQ-CPR-001 gives builtins no availability field and routes prohibition
   through collection ceilings or engine/pack disablement, so a separate
   setting would be agent-added machinery with no requirement behind it.
3. Resolver port in planning (`ProfileSource`): `builtin` stays embedded;
   `organization` reads the hub namespace, `namespace` reads the target
   workload's namespace only. One bounded LIST per preview, one GET per start;
   the definition digest and source cluster/namespace/object UID are bound
   into `wireResolved` and the `captureProfile` history dependency. Disabled
   versions refuse new previews/starts; deprecated ones warn.
4. Tools: runtime schemas via `scripts/investigation-schemas.py`, use case,
   presentation and MCP registration; browser/MCP parity. Both tools take
   `target_ref` (like `list_diagnostics`; no target-handle store) and return
   one page of at most 100 rows narrowed by `catalog`.
5. Tests: unit (resolver confinement, no shadowing, availability), real
   Kubernetes CRD test (immutability by version, namespace confinement,
   builtin-name impersonation refused, disabled version blocks starts).

## Deferred to slices B/C

Everything listed under slices B and C above, plus the three unshipped builtins
(process-context, go-cpu, http-headers), which are listed as unavailable
entries until their increments land.

## Slice B plan (2026-11-01, from a code map of main 8c3ab742)

One capture is strictly one attempt, one artifact and one expectation
(`context_capture.attempt_id` UNIQUE, `custody_attempt.artifact_id` UNIQUE,
`context_catalog.capture_id` UNIQUE, verification keyed by capture). Giving a
capture N artifacts would break all of these and every `ContextExpectation`
consumer. The ADR-266 recording save group already provides N child captures
under one shared scope digest and case, with mixed kinds allowed. Slice B
therefore maps an N-component composition onto **one shared review and scope
with one child capture per recorder action**, not one capture with N
artifacts. That satisfies REQ-CPR-003's "one recipe and one current execution
scope contain every action and budget".

1. **B1 compile.** `expand` loops over components with one global alias and
   generated-ID map (`a` + 24 hex of sha256(componentID NUL localID); reject
   collisions), at most 16 actions, aggregate `maxTotalBytes`/`maxDuration`.
   Identical expensive actions (packet/syscall) are a duplicate conflict; two
   non-identical packet or two syscall sources on one Pod have no qualified
   coexistence profile and are refused with a remedy. Packet + syscall is the
   one mixed pair. Retention is resolved per evidence type.
2. **B2 policies.** `PolicyRecorderConfiguration` carries one entry per
   action; one policy arms one source per action on each Pod (sources are
   already independent per `SourceID` on the node and per action in SQL).
   Saves become one group child per (Pod, action). Gate: a native test runs a
   packet and a syscall source on the same Pod at the same time.
3. **B3 manual.** A manual syscall `Recording` (processing trigger accepts
   `syscallRecords` on the recording branch, new migration) and a manual
   group preview kind, so a manual N-component capture becomes a group.
