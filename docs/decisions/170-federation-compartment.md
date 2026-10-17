# ADR-170 — Federation compartment for connector-facing hub duties

Date: 2026-10-14. Status: accepted; role layout, `hub-federation` and regional `connector` processes implemented and natively qualified with synthetic setup roots; installer provisioning pending.
Requirements: REQ-FED-001/002, specs/persistence.md connection budget; TASK-03 / TASK-11.

## Context

ADR-169 keeps every connector effect on the hub: SQL49/51 source staging,
process and credential journals, encrypted audit acknowledgement, the activated
leaf registry, and the ADR-168 cluster credential store. They need distinct
logins: SQL49 pins six duty names and OIDs (source, journal, acknowledgement,
cleanup, verifier, finalizer) at the first source staging and requires all six
to exist. A staged privilege plan (outside the repository, in the build cache) mapped
their exact functions and views.

The hub compartment already projects 28 public purposes plus 4 owner-identity
purposes, each with one `MaxConns=1` pool: exactly the 32 connections per hub
replica that specs/persistence.md allows. Adding the connector duties to the hub
would exceed it.

## Decision

1. Connector-facing duties run in a separate **federation** process kind,
   which serves the ADR-169 channel and later the I-01 federation routes. It
   holds `connector-source`, `connector-journal`, `connector-ack`,
   `connector-read` (activated-leaf registry plus recovery state) and
   `cluster-credential`. It retains at most two processes, so each role has a
   connection limit of three (two processes plus the serialized installer
   verifier).
2. `connector-cleanup`, `connector-verifier` and `connector-finalizer` are
   created at installation so SQL49 can pin all six logins. They belong to the
   worker compartment and are projected nowhere until their maintenance
   consumer is composed.
3. All eight are permanent ordinals 48–55 of the existing fixed public runtime
   role layout. They reuse its provisioning, provenance comment, exact ACL and
   function-overload verification. They never enter the hub projection, and
   creating them requires the same worker binding as the other non-hub roles.
4. Grants follow the plan exactly. The journal receives the v2
   (`connector-operation-history/v2`, prepaid retirement) reserved admissions
   only, never the unreserved v1 entry points. `close_connector_backing_candidate`
   is not granted, because no adapter calls it yet. Lifecycle duties get the
   four filtered views with immutable lock keys and their own columns; only the
   finalizer reads `connector_operation_history`.

## Consequences

`InstalledSQLConnectionPlan` adds the `hub-federation` compartment: one hub
plus worker and federation now needs 32 + 16 + 10 + 1 + 4 = 63 ordinary
connections (fits PostgreSQL's default 97). Four retained hub processes need
159, which still requires a declared larger allocation. ADR-172's sixth
federation role raises these to 65 and 161.

## Verification

- Unit: ordinals, compartments and projection exclusion
  (`internal/contracts`, `internal/adapters/postgres`, `internal/adapters/kubernetes`).
- Real PostgreSQL: the initial-installation suite's
  `public-runtime-roles-{matrix,unknown-claim,lost-completion,held-lock,recovery-after-lock}`
  provisioned all 41 roles (including these 8) and verified each exact ACL and
  resolved overload. It passed with 87 tests, empty cleanup and unchanged sources
  ([result](../../test/results/adr170-roles-1/result.json)).

## Processes

`asservat hub-federation` (`bootstrap.RunFederation`) reads the fixed
`/run/asservat/federation` projection: `federation.json`
(`contracts.FederationDeployment`), one `sql-federation-<purpose>.json` per
federation role (one `MaxConns=1` pool each), connector audit MAC keys, audit
storage credentials, OpenBao audit wrap/unwrap and connector client/server
sign tokens, and a deployment-provided TLS serving certificate. Each peer is
pinned by its exact installed source document, original ConfigMap UID and
regional guard protection digest. The hub derives that peer's profile with
the same decoder the region uses
(`kube.DecodeConnectorIdentityConfiguration`). It serves the ADR-169 channel
and the ADR-168 rotation endpoint. It holds no browser, owner-signing or
evidence authority; with ADR-172's optional owner input it reads the hub
owner registry and the owner namespace's routes and guard. Refused presentations and failed conversations are logged
as one fixed line with a closed cause.

`asservat connector` (`bootstrap.RunRegional`) reads `regional.json`
(`contracts.RegionalDeployment`) and projected tokens only. It uses its own
ServiceAccount as both observer and independent probe, like the owner. It reads
and compare-and-swaps its cluster credential Secret through the API (no Secret
mount) and supervises enrollment, renewal and rotation. A fenced credential
stops the process. It logs one readiness line and closed failure causes.

## Native qualification

`TestFederationRegionalProductWithRealKubernetes` runs both product binaries as
Restricted Pods in two owned clusters. It uses the product connector role
grants, real OpenBao PKI and transit, encrypted S3 audit and the v2 retirement
layout. The regional Pod mounts no Secret. Run 10 passed: the hub's SQL shows
an accepted process for that Pod with both leaves activated, and the region
reports active credentials after the delegated registry checks, with no
restarts ([result](../../test/results/adr170-product-native-10/result.json)).
Roles, PKI, owner/fleet trust and generation 1 are explicit fixture setup; no
product installer ran.

Runs 1–9 are retained. All were test-side or diagnostic gaps:
- Run 1: missing pinned eviction tolerations in the test Pod spec.
- Runs 2 and 9: the harness and the regional input still named the fixture
  probe account rather than the product's own account.
- Run 3: the v2 policy slot reserves were not recomputed.
- Runs 4–6: the worker image was absent from the second cluster; the harness
  now loads it for this selection too.
- Runs 7–8: no failure diagnostics. The product closed-cause log lines were
  added.

## Remaining

The installer: provisioning the eight roles through the public role producer,
the federation and regional projections and Deployments/RBAC, PKI roles, the
generation-1 cluster credential and its Secret, and the serving certificate.
Also remaining: the maintenance loop for the three lifecycle duties, and the
regional process's ADR-150 observation and context-start serving, which still
need owner verification without hub SQL.
