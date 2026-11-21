# Working on Asservat

## Goal and scope (maintainer, 2026-11-21)

Asservat is a multi-cluster Kubernetes platform for recording and analyzing
arbitrary workloads, to debug complex issues that cannot be reproduced in lab
conditions. Some recordings (such as core dumps) may contain sensitive data, so
there is an administrator approval. The earlier design was overengineered with
arbitrary requirements and limits; the maintainer asked for a radical
simplification and chose a new small core. Its whole specification is
[docs/design.md](docs/design.md). The earlier tree ends at commit `2ccfa535`
and is reference material only: its ADRs, specifications and accepted
refinements are not requirements.

Keep it small. Extend the vertical slice by the next most valuable capability
from "Not built yet" in the design, working end to end (`test/e2e/run.sh`)
before adding the next. Do not reintroduce mechanisms from the earlier tree
without the maintainer asking for them.

## Complexity must pay for itself

Assess the entire change against the observed problem. Before adding watches,
API requests, permissions, background tasks, fallback behavior, configuration
or dependencies, answer briefly in the PR:

1. How frequent and harmful is the observed problem? Flag hypothetical cases.
2. Does it help typical deployments, or mainly an uncommon path?
3. What do comparable projects do?
4. What privileges, credentials or network exposure are added?
5. How many failure or fallback states are added?
6. Would a smaller fix, documenting the limitation or doing nothing do?

When weak benefit meets questionable cost, do not build it; state the problem,
the cost and the cheaper alternative. Routine engineering choices need no
approval.

## Event-driven, no polling (maintainer, 2026-11-14)

No polling where an event source exists. Use Kubernetes watches, PostgreSQL
LISTEN/NOTIFY, push over existing connections or in-process signals. Every new
ticker or sleep loop must justify in its PR why no event source works.

## Limits need a reason (maintainer, 2026-11-14)

"If you can not give a good reason for a limit then remove the limit." A limit
stays only with a concrete resource cost, an external protocol constraint or a
maintainer decision; write the reason next to it. Prefer pagination or
streaming over caps on lists.

## Threat model and security (maintainer, 2026-11-13)

Operators keep every non-Asservat-administrator out of the Asservat
namespaces. Anyone who can write there, and any cluster administrator, is
trusted. Components trust the Kubernetes platform like other applications:
configuration from mounted ConfigMaps and Secrets, protection by RBAC and Pod
Security. Do not design defenses against namespace writers or cluster
administrators.

Every security measure must address a concrete risk and be backed by external
sources (standards, vendor guidance, incident reports, comparable projects).
If nobody outside this project tells a positive story about a measure, do not
add it. Do not let security requirements with unproven benefit stall
development or cost runtime performance.

## Invariants

- One organization per installation with central multi-cluster management; no
  tenant abstraction.
- Permissions are configured in Kubernetes only.
- Workloads keep Pod Security `restricted`; nothing is injected into them.
- All evidence downloads in its native format for local tools (Wireshark, a
  debugger). State clearly that local copies are outside Asservat's control.
- Managed evidence is stored encrypted and never served anonymously.
- No embedded LLM or agent harness, vendor telemetry, update checks, required
  SaaS or licence keys. Do not write to external ticket, chat or wiki systems.
- Say "user data" in product copy; keep "personal data" as the legal term.
- Tests use synthetic evidence only. Fixtures and test credentials never
  confer production authority.

## Workflow

Reproduce defects with a failing test before fixing them. Run `go vet ./...`,
`gofmt -l .`, `go test ./...` with `ASSERVAT_TEST_DSN` set, `helm lint
charts/asservat` and, for changes to capture, agent, chart or protocol,
`test/e2e/run.sh`. Report what ran and its actual result; never mark an unrun
check as passed. Change `docs/design.md` with the behavior.

The maintainer allows subagents where parallel work improves speed, and asks
to continue through complete user workflows without stopping at component
handoffs.

## Local machine and outward actions

Use an explicit build `TMPDIR` under `~/.cache`. Do not create paid resources,
publish releases, push registries, or alter protected branches without
authorization. Do not change this workstation's `core_pattern` or create
privileged host collectors outside disposable kind clusters or VMs: kind
shares its host kernel, so kernel-global experiments belong in disposable VMs.

Do not use stock validation phrases when corrected or qualify candor with
"honest". State the correction and act on it.
