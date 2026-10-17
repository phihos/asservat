# Specification format for agent-led implementation

Research date: 2026-10-09. This is a format choice, not evidence that one framework produces universally better code.

## What current approaches provide

| Approach | Primary evidence | Fit for Asservat |
| --- | --- | --- |
| GitHub Spec Kit | [Repository](https://github.com/github/spec-kit), [agentic workflow](https://github.github.com/spec-kit/reference/agentic-sdd.html) | Separates constitution, specification, planning and tasks. Good greenfield discipline; generated workflow machinery is unnecessary for this design-only phase. |
| OpenSpec | [Repository and example artifacts](https://github.com/Fission-AI/OpenSpec) | Keeps capability requirements/scenarios and change proposals beside code. Useful for incremental changes; avoid maintaining two canonical copies of requirements. |
| Kiro specs | [Official documentation](https://kiro.dev/docs/specs/) | Requirements, design and tasks with structured acceptance criteria. The document pattern is portable; an editor-specific workflow is not required. |
| Machine-readable contracts | [JSON Schema 2020-12](https://json-schema.org/draft/2020-12), [Kubernetes structural schemas](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/) | Validate examples and generate contract tests; they cannot express every authorization, temporal or failure invariant. |
| Small agent entrypoint | [AGENTS.md](https://agents.md/) | Gives repository instructions and a reading map without burying behavior in tool-specific prompts. |

The useful common pattern is **versioned text plus executable contracts and verification**, with small context bundles. Framework documentation describes workflows; it is not a comparative benchmark. No universal "best format for LLMs" was established by the primary sources reviewed.

## Decision

Use plain Git-tracked Markdown organized by capability, stable requirement IDs, explicit Given/When/Then scenarios, JSON Schema contracts, YAML examples, architecture decision records, and a task-to-requirement map. Use Spec Kit's separation of intent/design/tasks and OpenSpec's capability/change model, without requiring either CLI or claiming exact native compatibility.

There is **one canonical specification** in `specs/`. `docs/` explains rationale, research and operations. `specs/changes/<change>/` contains a proposal, affected IDs, design delta and tasks for future changes; after acceptance, update canonical specs and retain the change record. Never make a second full specification inside a change directory.

## Normative rules

- `MUST`, `MUST NOT`, `SHOULD` and `MAY` have RFC 2119/8174 meanings. Requirements are normative design intent, not implementation claims.
- Each requirement has a permanent `REQ-...` ID. Each acceptance scenario has `SC-...`; each implementation work package has `TASK-...`.
- Prefer one observable obligation per requirement. Use concrete units, limits, failure behavior and actors. Avoid "secure", "fast", "flexible" or "supports X" without a testable meaning.
- A schema defines shape. Behavior specs define authorization and semantics. They must agree; a schema-valid request can still be unauthorized or infeasible.
- JSON Schema 2020-12 files validate portable examples. They are **not installable CRDs**. Future Go API types generate Kubernetes structural OpenAPI/CEL schemas; conversion tests must preserve these contracts.
- Proposed APIs start at `asservat.io/v1alpha1`. Explicit versioning applies independently to manifests, event types and MCP outputs.
- Facts cite primary sources and inspection date. Unknowns have an experiment ID, success condition and consequence of failure.
- An unchecked implementation task or pending experiment stays unchecked until evidence exists.

## Agent task packet

Every implementation task should contain:

```text
Task: TASK-04 / log and metric trigger evaluator
Read: AGENTS.md, specs/triggers.md, specs/contracts/trigger.schema.json
Requirements: REQ-TRG-001..005 (enumerate actual IDs in the task)
Interfaces: occurrence/v1, policy digest, container identity tuple
Must preserve: no payload in Kubernetes Events; bounded memory; no duplicate intrusive action
Acceptance: SC-TRG-001..005; exact tests/fixtures to run
Non-goals: unrelated runtime recipes and UI work
Evidence: commands, exits, versions, unresolved limitations
```

The traceability file uses explicit lists rather than range notation. Reviews check negative paths, restart recovery, revocation and unauthorized workload access and external identity rejection, not only happy paths.

## Validation and tool policy

`make spec-check` uses Python 3 plus PyYAML and jsonschema from `requirements-spec.txt`. It performs offline local-link checks, schema/meta-schema checks, validates every registered example, checks requirement/scenario/task references, and enforces selected cross-field invariants. Install these **development-only** dependencies in a virtual environment. No spec CLI, telemetry, remote schema resolution or runtime agent service is needed.

Text validation does not prove the distributed design correct. The [validation plan](validation.md) supplies the runtime and adversarial gates. The implementation must not silently redefine a requirement to fit a passing test.
