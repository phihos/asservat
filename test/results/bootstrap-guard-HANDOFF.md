# ADR131 bootstrap guard correction

Three isolated paths: the existing guard builder, new actual-builder unit regression, and new native Kubernetes fixture. The original twenty-path ADR131 checkpoint is unchanged.

`manifest.json` SHA256: `688fcd60d4a783b05e9d3d9c8b58d8ea09ca94c246cef21fa86e55de7474e02d`
`payload.patch` SHA256: `7212ffa04f1c01a96e3841f89fc6fd09963b51480ad4d84272a973bf2b14c1e5`

Kubernetes policy variables are unavailable in matchConditions (pinned k8s.io/api v0.37.0 admissionregistration/v1/types.go:284-287). The old bootstrap builder put variables.group/name/namespace there. The correction substitutes guarded request-field expressions in its shared exact-key predicates. Variable use in validation remains; exact protected names, namespace deletion, oldObject deletion matching, administration and observation token limits are unchanged.

## Actual local evidence

All commands ran with GOMAXPROCS=2, -p 2 and TMPDIR=/home/phil/.cache/asservat-build/tmp.

- `go test -overlay overlay-before.json ./internal/adapters/kubernetes -run '^TestInitialBootstrapAdmissionMatchesWithoutPolicyVariables$' -count=1`: exit 1 at the intended unsupported variables expression (evidence/before.log).
- `go test -race -overlay overlay-after.json ./internal/adapters/kubernetes ./test/integration -run '^TestInitialBootstrap' -count=1`: exit 0; Kubernetes 1.108s, integration 1.048s (evidence/final-race.log). Integration fixtures skipped absent real services; this is source compile, not native admission proof.
- `go vet -overlay overlay-after.json ./internal/adapters/kubernetes ./test/integration`: exit 0 (evidence/final-vet.log).

## Parent-owned next qualification

The exact context selector is `^TestInitialBootstrapGuardWithRealKubernetes$` using the existing owned context harness. Native helper is written but unrun. It reproduces the original matching expression and requires actual API rejection/type-check warnings, then tests fixed policy compilation and exact protected/private/unrelated/dry-run/token scope. It creates only public fixture anchors and synthetic private-name payloads, never SQL/provider/seed authority or activation. Teardown is trusted fixture cleanup with original object UIDs and bounded exact-policy cache handling.

The separately qualified manager fixture uses `scripts/test-custody.py --fleet --run '^TestInitialBootstrapManagerWithRealServices$'`. That passing actual SQL/OpenBao/S3 result has synthetic Kubernetes authority and is distinct from this guard/native producer/compositor chain.
