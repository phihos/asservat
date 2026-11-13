# Helm-native installation plan

Date: 2026-11-13. Status: accepted direction (maintainer decision recorded in
AGENTS.md); implementation pending.

## Decision

Maintainer: "Yes please make installation best-practice. The installer pod
goes against all best practices. And I can really not see any security
benefit. You could even argue that a compromised installer or installer
service account does way more harm."

Helm renders every Kubernetes object. Idempotent hook Jobs do only work that
needs live external state. Plain Kubernetes RBAC and Pod Security `restricted`
protect the hub namespace. The installer Pod, its continuation, the UID-pinned
ValidatingAdmissionPolicy guards, their dry-run proofs, journals, witness and
temporary-credential retirement are removed.

What stays unchanged: per-operation authority checks against current identity,
permissions and retention; encrypted evidence and audit; SQL effect fences;
the recovery fence observed by hub-worker; key material only in the key
service; no evidence access for cluster objects alone.

## Why (measured on 2026-11-13)

- Size: about 9,000 lines of installer Go in `internal/bootstrap` and 15,900
  lines of installer, guard and protection Go in `internal/adapters/kubernetes`,
  against 2,000 lines of chart templates.
- Privilege: the bootstrap runner's ClusterRole can create namespaces, RBAC,
  ClusterRoles and admission policies, and mint service-account tokens. Today
  that runner is the most privileged identity in the system.
- Threat model: the guards stop a non-administrator namespace writer
  (ADR-080). Plain RBAC already prevents that writer from existing; cluster
  administrators can delete the guards, so they are not covered either way.
- Cost: every setting change needs a reinstall; cert-manager cannot write in
  the protected namespace; Ingress objects could not be templated; k3s token
  audiences and asynchronous admission type-checking on HA control planes
  broke installs (PRs #227, #228). Each homelab change took a 10-minute
  reinstall.

## Comparable charts

- GitLab: a pre-install/pre-upgrade `shared-secrets` Job with a Role limited to
  Secrets, create-if-missing and never rotate; migrations as a non-hook Job
  with a values-hash name suffix; Deployments wait for the schema.
- Harbor: a pre-upgrade migration Job.
- OpenBao/Vault chart: renders the auth-delegator binding; init and unseal
  stay operator or auto-unseal work.
- cert-manager: CRDs as templates behind `crds.enabled`/`crds.keep`;
  a post-install check Job with a one-verb Role.
- MinIO (Loki/Mimir): a post-install bucket Job from a declarative list.

None of them gives a hook RBAC, namespace or admission-policy create rights.
Sources are in the research notes of this plan's PR.

## Target layout

Templates (all rendered by Helm, release namespace = hub namespace):

- `_helpers.tpl`: names, labels, image, security context, resources,
  `checksum/config` annotations.
- CRDs as templates (`crds.enabled`, `crds.keep` default true).
- Per runtime component: ServiceAccount, exact Role/ClusterRole and bindings,
  Deployment, Service: hub-api (owner), hub-worker, federation, key-service,
  publisher. Download-worker namespace, Role and PriorityClass.
- `<release>-hub-config` and per-component ConfigMaps rendered from values,
  read by fixed name at fixed paths; no UIDs, guard pins or digests that only
  an installer could know.
- EvidenceStoragePool, EvidenceBudgetPolicy and the baseline retention policy
  as templated CRs.
- Generic `ingress` and `httpRoute` values for the console and the bundled
  Keycloak: `enabled`, `className`, `annotations`, `hosts`, `tls`;
  `parentRefs`, `hostnames`, `matches`. TLS mode `pod | proxy` from ADR-327.
- Peer listeners (federation, owner native, key service): Service type
  configurable (ClusterIP default for single-cluster installs, NodePort or
  LoadBalancer for remote regions), or TLS passthrough.
- Connector and collector templates for `mode: cluster|combined`.
- Bundled PostgreSQL, OpenBao, SeaweedFS, Keycloak: unchanged workloads.

Hook Jobs (Jobs, not bare Pods; `backoffLimit`, `ttlSecondsAfterFinished`,
`before-hook-creation,hook-succeeded`; all idempotent so Argo CD's
every-sync hooks are safe):

1. `secrets` (pre-install, pre-upgrade): create missing Secrets with fixed
   names, never rotate: SQL role passwords, S3 identities, installation and
   cluster IDs, artifact root key, signing keys, browser cookie key. Role:
   `secrets: create` plus `get`/`patch` on named Secrets. `existingSecret`
   overrides for each. Secrets survive uninstall.
2. `setup` (post-install, post-upgrade; one Job, one `asservat setup`
   command): wait for the selected PostgreSQL, OpenBao and object store;
   apply migrations; create or update runtime roles and grants from the
   compiled grant plan; seed the activation, trust and capacity rows;
   configure bundled OpenBao (mounts, policies, Kubernetes auth, PKI, transit)
   and SeaweedFS (buckets, IAM); write the first audit record. No Kubernetes
   API except reading its own Secrets. External providers: the operator runs
   the same command or applies the documented recipe.
3. Deployments that need the schema wait in an init container until
   `setup` reports the current schema version.

Upgrade re-runs both Jobs. Rollback keeps the schema (forward-only, the old
binary refuses a newer schema) and generated Secrets. Uninstall keeps PVCs,
CRDs and generated Secrets; erasure is a documented explicit step.

## Runtime changes

Per component (details in the research map):

- Inputs: replace `deployment.json`/`federation.json`/`regional.json` with
  Helm-rendered config by name. Remove `GuardPin`, `WorkerObjectReference.UID`,
  activation and journal fields from the contracts.
- Delete guard re-verification: `checkAdmissionGuard`, `configMapProtection`,
  owner/connector workload protection, capacity/permission/retention/
  processing guards, source guards, the owner identity journal and launch
  receipt, `VerifyPublicProjection`, hub-worker activation.
- Sources (cluster catalog, worker configuration, download environment,
  fleet, owner configuration, browser and identity settings) become plain
  ConfigMap reads under RBAC; existing five-second observation windows
  remain where they bound authority (ADR-311).
- SQL: runtime credential checks reduce to "connected as the expected role";
  `fleet_initial_activation` and the trust row are seeded by `setup`;
  `protection_digest` columns get a migration to a configuration digest or
  are dropped.

## Slices

Each slice ends in a fresh `helm install` that works, qualified on kind and
on the homelab, with its own PR.

1. **Hub console.** `secrets` and `setup` Jobs; Helm-rendered hub-api and
   hub-worker with plain config and RBAC; generic Ingress/HTTPRoute. Done
   when: fresh install, login through external or bundled Keycloak,
   processing initialization, `helm upgrade` of the origin without a
   reinstall.
2. **Capture path.** federation, key-service, publisher rendered by Helm;
   single-cluster region via the chart's `combined` mode with in-cluster
   addresses, no NodePorts. Done when: pod-status capture, inspection and
   native download.
3. **Remote regions.** `mode: cluster` connector chart, enrollment through
   the `setup`-style Job with the browser-issued bootstrap ID; peer Services
   as NodePort/LoadBalancer/passthrough. Done when: two-cluster capture.
4. **Deletion.** Remove the installer commands, continuation, guards,
   journals, witness, temporary roles and their tests and ADR text; migrate
   or drop `protection_digest`; update architecture docs, specs and gates.
5. **Bundled Keycloak and collector** move to the same templates; ADR-327's
   installer-created routes are replaced by chart templates.

## Open questions decided here

- One `setup` Job instead of five: fewer moving parts; each step is
  idempotent and ordered in code.
- No dual mode: this project is unreleased; old installations are reinstalled
  (AGENTS: no permanent compatibility framework for development layouts).
- PRs #227 and #228 fix the current installer and become obsolete with slice 4;
  ADR-327's proxy-TLS mode stays, its installer-created route moves to the
  chart in slice 1.
