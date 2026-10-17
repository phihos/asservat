# Permission observation component record

Date: 2026-10-10. This continues the [identity foundation](identity-foundation.md). The [observation contract](../architecture/permission-observation.md) defines the internal ports, limits and remaining authority boundary. No S-01/S-02 exit or complete TASK-07 is claimed.

## Research and reuse

Reuse already pinned **client-go / apimachinery v0.37.0**, the existing **santhosh-tekuri/jsonschema v6.0.3** validator and Go's standard RFC 8785 canonicalization. No new dependency version or controller framework is added. The already resolved Kubernetes SIGs YAML v1.6.0 package is used by fixture/example tests and is now marked as a direct dependency by `go mod tidy`. Explicit Go permission DTOs mirror the reviewed schema; embedded schema drift is checked by `make permission-schema-check`, also part of `go-check`.

Kubernetes documents that continued list pages retain one collection resourceVersion, while expired continuations can require restarting a list. Resource versions are opaque; individual object versions are not freshness timestamps. The implementation consequently rejects partial/inconsistent binding lists and never derives age from a numeric resourceVersion. These are protocol facts, not proof of continuous ownership history. [Kubernetes API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/)

Native `bind`/`escalate` checks concern Kubernetes RBAC roles and bindings. An Asservat custom resource requires its own protected delegation/admission design. Reading a CRD, or observing a `Ready` field, does not supply it. The real-server fixture below tests resource RBAC, not that missing writer-delegation boundary. [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-creation-or-update)

Custom-resource schema validation and admission are separate implementation facilities. This fixture deliberately permits unknown spec fields so the runtime reader encounters malformed objects; do not install its CRDs as production configuration. [CustomResourceDefinition validation](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation)

## Implemented scope

- C-01 `PermissionReader` / `NamespaceReader` observation ports, C-20 permission spec DTOs, C-21 concrete HTTPS Kubernetes reader, C-24 source identity and unaccepted mapping proposals.
- Complete bounded AccessBinding lists with namespace-incarnation checks and independent allow-only source availability. Exact source digests and current names/UIDs survive conversion; statuses do not confer acceptance.
- Selected namespace metadata and exact fixed-role value mapping for multiple owner teams. Direct group IDs still need a qualified directory; protected metadata still needs actual trust qualification.
- A correction to ordinary eligibility: an independently timed, complete deny snapshot may live at most five seconds, including an empty deny set. That deadline bounds both pre-lookup checks and final eligibility.

These components do not implement `authorization.ProjectionReader`. No accepted SQL configuration, persistent assignment transition, admission authority, writer guard, SAR adapter, public effect or durable audit is faked into existence. Existing artifact/custody code and SQL layout are unchanged.

## Reproduced defects and checks

`permission-deny-before-fix.log` records an actual failing regression: a six-second-old empty deny snapshot authorized disclosure. The fix adds separate deny timestamps and tests missing, stale, future and overlong observations, stale deny rows and current explicit-deny precedence.

`permission-independent-source-before-fix.log` records a second failing regression: an unavailable allow-only source list discarded complete explicit bindings. Source availability is now independent; incomplete binding/deny state still fails closed. Invalid automatic sources never become allow candidates.

The focused HTTPS tests cover actual client-go requests, exact pagination and opaque versions, empty intermediate pages, duplicate resources, continuation loops/410/403, object/page bounds, malformed specs, namespace/control replacement, termination, clock movement, cancellation, TLS trust, credential redirects, source minimization and canonical spec digests. Reviewed YAML examples are decoded through the same local schemas. Pure mapping tests exercise multiple owner teams, exact scope, exclusions, stale observations, unsupported source types and missing qualification.

`make permission-integration` creates one owned pinned Kind cluster and a dedicated reader service account. It installs synthetic namespaces plus test-only CRDs, then tests a 65-binding paginated read, two-team mapping proposals, resource RBAC denials, dry-run/nonpersistence, stale resourceVersion conflict, malformed-deny rejection, replacement resource identity and namespace UID pinning. It installs no workload collector and changes no host kernel setting. Source hashes are captured before/after the Go test; the owned cluster is removed in `finally`. Logs and cleanup results are in `test/results/permission-kubernetes*`.

Final commands on Go 1.27.2 used `TMPDIR=/home/phil/.cache/asservat-build/tmp`; YAML/spec gates used `/tmp/asservat-openapi-validation/bin/python`.

| Command | Actual result |
| --- | --- |
| `make go-check go-architecture-check sql-check` | Exit 0: both embedded schema bundles, vet, all Go race tests, 20 packages/34 internal import edges and three unchanged generated SQL files |
| `make permission-integration` | Exit 0: four real Kubernetes subtests; 65-binding pagination, RBAC and mutation/identity checks; source hashes unchanged during the test; no cleanup failures |
| `go test ./internal/adapters/kubernetes -run '^$' -fuzz '^FuzzPermissionJSON$' -fuzztime=15s -parallel=2` | Exit 0: 51,250 parser executions, no failing corpus |
| `make go-vuln-check` | Exit 0: no affected code/imported packages; the previously documented unused OpenPGP module-only advisory remains |
| `make spec-check architecture-check design-check openapi-check download-check investigation-check live-check` | Exit 0 for all seven design gates; these do not qualify runtime authority |
| `go mod tidy -diff` | Exit 0 with no remaining module drift |

The first combined Go/architecture invocation completed Go tests but exited 2 because the planned `api/v1alpha1` path lacked catalog ownership. C-20 now owns shared wire DTOs; the gate permits adapters to import those shapes while rejecting transport-handler imports and behavior imports from DTOs. `permission-go-check-initial.log` preserves that failure; `permission-go-check.log` is the final passing batch. No import restriction was waived.

`permission-kubernetes*-before-tidy.*` preserves the earlier passing real-server fixture. It was rerun after the YAML direct-dependency classification so the final integration input hashes match the final module. The vulnerability scan and fuzz run preceded that classification-only change; resolved versions and parser source were unchanged.

Ordinary Go tests skip the real-server test without its owned fixture. A skip is not integration success. The [verification inventory](../../test/results/permission-verification.json) records final source/log hashes after checks; it complements the integration harness's independent before/after hashes rather than claiming every gate captured them during execution.

## Remaining work

Next implement protected configuration acceptance and SQL-backed audience assignment continuity, including restart/watch-gap/A → B → A cases and independently complete deny state. Qualify source protection and IdP policy before connecting those readers to the existing eligibility evaluator. Preserve admitted target identity and all local ceilings/grants when acceptance later reaches execution.

Production structural CRDs, admission/delegated writer escape tests, status ownership/acknowledgments, namespace bootstrap trust, configured source population ceilings, group directory/SAR integration, API audit coverage and watch recovery remain open EXP-16 work. Real Kubernetes reads do not complete these requirements. Durable encrypted audit and verified publication remain required before public collection or native downloads.
