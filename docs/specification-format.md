# Specification format

Plain Git-tracked Markdown organized by capability, with stable requirement IDs, Given/When/Then scenarios, JSON Schema contracts, YAML examples, decision records and a task-to-requirement map. The pattern follows GitHub Spec Kit and OpenSpec (separate intent, design and tasks) without either tool.

There is one canonical specification in `specs/`. Each rule lives in one owning spec; others link to it. `docs/` holds rationale, research and operations. Consequential changes get a decision record in `docs/decisions/` and are applied directly to the canonical specs; there is no separate change directory.

## Normative rules

- `MUST`, `MUST NOT`, `SHOULD` and `MAY` have RFC 2119/8174 meanings.
- Each requirement has a permanent `REQ-...` ID, each scenario `SC-...`, each work package `TASK-...`. Removed IDs are not reused.
- One observable obligation per requirement, with concrete units, limits, failure behavior and actors. Every limit states its reason.
- A schema defines shape; behavior specs define authorization and semantics. A schema-valid request can still be unauthorized.
- JSON Schema files validate portable examples and are not installable CRDs. Go API types generate the Kubernetes structural schemas.
- APIs start at `asservat.io/v1alpha1`; manifests, event types and MCP outputs are versioned independently.
- Facts cite primary sources and date. Unknowns name an experiment, its success condition and the consequence of failure.
- An unchecked task or pending experiment stays unchecked until evidence exists.

## Agent task packet

```text
Task: TASK-04 / log and metric trigger evaluator
Read: AGENTS.md, specs/triggers.md, specs/contracts/trigger.schema.json
Requirements: REQ-TRG-001, REQ-TRG-002 (explicit list)
Interfaces: occurrence/v1, policy digest
Must preserve: no payload in Kubernetes Events; no duplicate intrusive action
Acceptance: SC-TRG-001, SC-TRG-002; exact tests to run
Non-goals: unrelated recipes and UI work
Evidence: commands, exits, versions, open limitations
```

Traceability uses explicit lists, not ranges. Reviews cover negative paths, restart recovery, revocation and unauthorized access, not only happy paths.

## Validation

`make spec-check` uses Python 3 with PyYAML and jsonschema from `requirements-spec.txt` in a development virtual environment. It checks local links, schemas, registered examples, requirement/scenario/task references, contract bounds and selected cross-field invariants offline. Text validation does not prove the distributed design; the [validation plan](validation.md) supplies runtime gates.
