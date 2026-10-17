# ADR-193 — Installed federation and regional cluster enrollment

Date: 2026-10-15. Status: accepted; steps 1–3 and 5 implemented and natively
qualified ([federation run 3](../../test/results/adr193-federation-native-3/result.json):
generation 1 from a product `BootstrapIssuer` slot;
[continuation run 53](../../test/results/adr183-continuation-native-53/environment.json):
the hub from the continuation and a second cluster from `installer-cluster`,
both leaves active, a restarted Pod readmitted, a rerun unchanged and a
non-administrator source write denied). Step 4's components are implemented
and qualified with Keycloak
([identity run 3](../../test/results/adr193-identity-3/identity-provider-environment.json));
their installed wiring waits for the hub-api public layer. Step 6 is natively
qualified ([Helm cluster run 4](../../test/results/adr193-helm-cluster-native-4/result.json)).
Step 7 pending. Retained failures: continuation runs 45–46 and 48–52,
federation run 2, identity runs 1–2, installer run 1 and Helm cluster runs 1–3.
Requirements: REQ-FED-001/002, REQ-DEP-001/005, S-02; TASK-03, TASK-11.
Builds on [ADR-168](168-rotating-cluster-enrollment-credential.md),
[ADR-169](169-delegated-regional-lifecycle-channel.md),
[ADR-170](170-federation-compartment.md),
[ADR-185](185-public-sources-and-cluster-catalog.md) and the audited bootstrap
issuance ([bootstrap issuance](../architecture/bootstrap-issuance.md)).

## Context

`hub-federation` and the regional `connector` pass as Pods in two clusters,
but only with synthetic setup roots. No product code builds either startup
document (`FederationDeployment`, `RegionalDeployment`).

Federation is incomplete on the hub:
- The continuation creates the six federation SQL logins but never projects
  them.
- The federation process reads static OpenBao token files and a synthetic
  serving certificate.
- It pins every regional source in `Peers` at startup and rejects zero
  peers.

Regional enrollment has no product path:
- ADR-168 generation 1 (`ClusterCredentials.Enroll`) has no product
  caller.
- The audited bootstrap issuance has only a test caller.
- The Helm chart's `mode=cluster` only records topology.

Three facts constrain the design:

- **Regional clusters arrive later.** They are added after the initial
  installation, and only outbound connectivity is allowed. The hub
  continuation runs inside the original 30-minute journal window, and its
  role projections cannot be claimed after that window. A later step
  therefore cannot publish new SQL credentials, and adding a cluster cannot
  be a continuation step.
- **Identity is pinned at installation level.** Connector roles and
  backing are pinned once per installation on `connector_identity_root`.
  Per-peer pins are created only by staging.
- **Enrollment has a short bound.** A bootstrap reservation mints the
  cluster and peer IDs inside a slot of at most five minutes.

## Decision

1. **Authority: audited bootstrap issuance by a fleet operator.** Enrolling a
   cluster is the fleet operator action of the protected `fleet.json`.
   - It reuses the existing bootstrap issuance: protected authorizer,
     bounded SQL reservation, encrypted issue-intent audit and `maxClusters`.
   - The hub-api hosts it as an OIDC fleet-operator operation.
   - Its SQL purposes join the fixed public role layout, so they apply to
     new installations.
   - A new generation-1 credential audit binds:
     - the bootstrap, the claim audit, the lineage and the key digest;
     - the staged source's UID, generation and protection digest.
   - The cluster catalog stays configuration, not authority.
2. **Federation peers come from SQL.** `FederationDeployment` replaces
   `Peers` with one installation-wide connector block, which matches the
   per-root pins of `connector_identity_root`.
   - A per-peer pin exists only after staging under bootstrap authority.
     Later mutation stays fenced.
   - The lifecycle handler already resolves duties from the presented
     profile, so peers resolve per request.
   - The federation starts with zero peers.
3. **The continuation provisions the federation**, after the owner
   selection, in one role operation like the permission step:
   - an immutable projection Secret holding the six SQL logins and the
     federation audit keys (from the role state's MAC material);
   - OpenBao Kubernetes-auth provider effects, like the owner, instead of
     static token files;
   - additions to the phase-3 provider recipe: the connector client and
     server PKI roles, the audit transit key, the KV bootstrap channel and
     the federation auth role. The PKI roles are installation-wide, because
     the adapter still checks the exact identity of every leaf; the sign
     token stays short-lived.
   - the operator's serving TLS Secret, whose roots the offer carries (see
     the provisioning details below);
   - TLS terminates in the Pod behind an L4 Service (LoadBalancer or
     NodePort; endpoint and server name are chart values). A TLS proxy
     would break the exporter binding.
   - a public, immutable `asservat-<id>-regional-offer` ConfigMap. It
     holds:
     - the installation, root and epoch IDs;
     - the federation endpoint, server name and roots;
     - the connector role names, the backing and the issuer roots;
     - the image digest.
4. **A regional installer CLI: `asservat installer-cluster`.** It uses the
   operator's kubeconfig for the regional cluster and has no in-cluster
   fallback. Later, Helm `mode=cluster` wraps it as a hook.
   - Inputs: the offer and the per-cluster KV bootstrap record. The
     operator reads the record with their own OpenBao access.
   - It creates, create-only and recorded by UID:
     - a `restricted` namespace and the connector account;
     - the connector Deployment, gated at zero replicas;
     - RBAC that allows only get/update on one Secret name;
     - the workload guard and the `connector-identity` source with its
       guard;
     - the credential Secret and `regional.json`.
   - Before ungating, it proves the protection with a minted short-lived
     account token. The connector proves it again at startup.
5. **Generation 1 is enrolled in-band by the connector.** No seed is
   generated outside the connector process.
   - The Secret starts at generation 0 with only the one-use bootstrap
     envelope.
   - The connector CAS-writes its pending seed before any request.
   - It then claims with an identity-free CSR over a new ADR-169
     `bootstrap` purpose, on the TLS channel pinned to the offer's roots.
   - The hub completes everything in one conversation:
     1. the claim;
     2. the delegated source read;
     3. staging;
     4. the atomic generation-1 lineage with a bootstrap-activated marker
        (migration 00064);
     5. the audit and the acknowledgement.
   - The connector then promotes its key and erases the envelope.
   - On bootstrap expiry, the operator issues a new bootstrap, and the
     installer rewrites the source with the new IDs.

## Provisioning details (2b–2d)

- **One operator apply.** The phase-3 owner provider artifact also carries
  the federation's four auth roles and policies and the two connector PKI
  roles. The applier is generic over `apply` and `inspect`, and the
  continuation verifies every named path through the inspection token, as it
  does for the owner's roles. The federation account exists before the
  outbox.
- **Installation-wide connector PKI roles.**
  - URI SANs match `spiffe://asservat.<installation>/cluster/*`.
  - Server leaves must fall under the offer's server-name suffix.
  - Each leaf's exact peer URI and server name are still verified by the
    product verifier. The sign tokens live at most 15 minutes.
- **Federation audit.**
  - The audit transit key is a separate, create-only key on the owner's
    audit transit mount.
  - The S3 audit principal arrives through the phase-3 inbox as a second
    credential. It is projected to the federation only.
- **Serving identity.** The operator supplies the federation's serving TLS
  Secret, as for the hub-api's public TLS. Connectors pin the roots it
  carries through the offer. A process-owned serving key from a PKI role
  remains possible later; it would change only the offer's roots.

## Step 3 details (3d–3e)

- **Connector backing.** The continuation derives the installation-wide
  backing from `federation.connector` (accounts, records, retention, peer
  profiles, source transitions, purge leases, validity, history footprint) and
  the capacity profile's backup values; capacity is therefore required with
  federation. Identities derive from the role setup, so a replay rebuilds the
  same backing. Source reservations are the minimum the prepaid-retirement
  validator accepts. At most 256 peer profiles and 4096 source transitions
  keep every reservation product inside int64. The backing must also
  support the fixed regional deployment shape (two serving slots, eight
  retained processes): its process run time, the retention minus two backup
  horizons, three cleanup budgets, the proof window and a minute, must be at
  least half the retention and 30 minutes. With a one-hour backup horizon
  that needs at least 15000 seconds of retention. [Continuation run 52](../../test/results/adr183-continuation-native-52/context-storage.log)
  derived a 3600-second retention, and every regional source then failed to
  decode; the continuation now refuses such settings.
- **Where the backing is checked.** `FederationDeployment.connector` and the
  offer's `connectorBacking` carry it. The bootstrap observation requires the
  read regional configuration to name exactly the root's stored backing, or
  this deployment backing before the first staging created the root.
- **SQL duties.** The claim runs on the `cluster-credential` login and its
  acknowledgement on the separate `connector-ack` login, with the same
  trust-row lock and column grants as the enrollment adapters.
- **Connector.** The regional process enrolls generation 1 before any
  ADR-168 presentation. It refuses an envelope for another slot and an
  expired envelope. A lost reply resumes with the stored pending key and the
  hub's replay. A fenced reply stops the process.
- **Credential Secret writes.** The regional workload guard is a
  namespace-wide admission policy. It now admits exactly one persistent
  UPDATE of the named credential Secret by the connector account
  (`regional.json` `clusterCredentialAccount`), like the ADR-093 Lease
  exception. [Federation run 2](../../test/results/adr193-federation-native-2/result.json)
  failed without it: the pending-seed CAS was refused before any hub request.
  Daily ADR-168 rotation had never exercised that write natively.
- **Open:** the staged profile's issuer roots and server name are the
  region's choice; leaves are still issued only by the installation-wide PKI
  roles and verified exactly.

## Step 4 details (issuance host)

- **Route.** `POST /api/v1/fleet/cluster-bootstraps` on the hub-api public
  origin, with the browser session, CSRF and an `Idempotency-Key` header. The
  body names only the display name, region and delivery profile. It is not
  an MCP tool: cluster enrollment is fleet administration, not an
  investigation operation.
- **Authority.** `EnrollmentAuthorizer` resolves the request's current
  identity and the protected `fleet.json`, which the hub-api reads with the
  fleet guard pin. Non-operators, unknown delivery profiles and exhausted
  ceilings are denied by the existing decision and SQL reservation.
- **Idempotency.** The request key digest is the SHA-256 of a fixed purpose
  prefix and the `Idempotency-Key` value. A replay returns the original
  slot.
- **Result.** The slot reference only: bootstrap, cluster and peer IDs,
  issuer epoch, dates, delivery profile and credential version. The secret
  stays in the KV channel; the operator reads it with their own OpenBao
  access.
- **SQL.** Four hub purposes, `fleet-bootstrap-reserve`, `-record`, `-audit`
  and `-activate`, keep the issuance's separate duties. Their grants are the
  trust lock plus the issuance adapters' table columns.
- **Provider.** One owner Kubernetes-auth role, `bootstrap-channel`, with KV
  `create` and `read` on `<mount>/data/connector/<installation>/*`. It joins
  the phase-3 artifact and is verified like the other roles. The operator
  supplies the KV mount and the delivery profile name; `fleet.json` must
  list that profile.
- **Federation audit scope.** The federation's audit principal now also
  writes `enrollment-claim/v1/<installation>/` and
  `cluster-bootstrap/v1/<installation>/`; the artifact lists all three
  prefixes. The owner principal gains `bootstrap-issue/v1/<installation>/`
  when issuance is enabled.
- **Dependency.** The continuation does not yet install the hub-api public
  layer (ADR-184 promoted owner). Step 4 is therefore built and qualified as
  components, and its installed wiring follows that layer.
- **Sub-steps:** 4a SQL purposes and grants (ordinals 74–77); 4b the
  provider role; 4c the issuance service and fleet reader; 4d the route; 4e
  Keycloak qualification.
- **Implemented (4a–4d).** The four purposes join the hub layout. The pinned
  fleet recipe adds one Kubernetes-auth role to the phase-3 artifact. The
  owner's provider effects gain a `bootstrap-channel` lifetime whose borrowed
  token reaches only GET or POST of one record under the installation prefix.
  `FleetBootstrapIssuance` authorizes each request from its own current
  identity. The hub-api public layer routes `POST
  /api/v1/fleet/cluster-bootstraps` when `public.fleet` is set: 403 for a
  denial, 429 for an exhausted ceiling, 201 with the slot reference.
- **Qualified (4e).** [Identity run 3](../../test/results/adr193-identity-3/identity-provider.log)
  drives the route with an actual Keycloak browser session, real SQL
  issuance logins, OpenBao KV and encrypted S3 audit. A member of another
  group gets 403 before any reservation; the operator's bootstrap is issued
  and its replay returns the same slot; a second request beyond
  `maxActiveBootstraps=1` gets 429. The fleet settings reader and trust row
  are fixture setup. Runs 1–2 failed on fixture defects: a non-TLS SQL pool
  and an absolute request URL, which the session check correctly refuses.

## Step 5 details (`installer-cluster`)

- **Inputs.** `--offer` is the hub's `regional-offer.json`. `--bootstrap` is
  the record's data object as the operator read it from the KV channel; it
  decodes with the channel's own strict spelling rules. `--kubeconfig` and
  `--context` select the regional cluster, with no in-cluster fallback, and
  the caller must be an operator identity, not a service account.
- **Objects.** In `--namespace` (default `asservat-connector`), create-only:
  the Restricted namespace, the `connector` account, its RBAC, the Deployment
  at zero replicas, the workload guard, the source guard, the
  `connector-identity` source, the generation-0 `cluster-credential` Secret
  and the immutable `regional-inputs` ConfigMap. Every object carries the
  installation/cluster marker and a template digest. A rerun reopens only
  objects whose marker and digest match.
- **RBAC.** Exact names only: get and CAS update of the credential Secret,
  reads for the lifecycle proofs, and the dry-run updates that the guards
  must deny.
- **Ungating.** Both guards are proven with a minted ten-minute token of the
  connector account, and the source must decode exactly. Only then is the
  Deployment scaled to one replica.
- **Reachability.** The operator may pin the federation's node port
  (`federation.nodePort`), so the offer's endpoint is known before the
  Service exists.
- **Diagnostics.** A failure names its installer step and a closed cause:
  an API reason, a guard-proof code or a class. Server text and object
  content are never printed.
- **Qualified alone.** [Installer run 2](../../test/results/adr193-installer-native-2/result.json)
  installs into an owned cluster from a synthetic offer and envelope, proves
  both guards with the connector token, ungates, reruns unchanged and has a
  non-administrator source write denied. Run 1 failed because both proofs
  were given one client; the protection constructors require separate
  observer and probe clients.
- **Open:** a rerun with a different bootstrap is refused; after expiry the
  operator deletes the namespace and reinstalls.

## Step 6 details (Helm `mode=cluster`)

- **Hook.** With `cluster.enabled`, a post-install/post-upgrade Job runs
  `asservat installer-cluster --in-cluster` under a release-scoped installer
  account. Like the hub chart's bootstrap runner, that account is the
  explicit trusted initial administrator of both guards. Only `--in-cluster`
  accepts a service account as the caller, and only the chart passes it.
- **Inputs.** The offer is a chart value (`cluster.offer`, public). The
  bootstrap record is never a value: the operator creates a Secret holding
  `bootstrap.json` and names it in `cluster.bootstrapSecret`; the Job mounts
  only that key. The image is pinned by digest (`cluster.image`).
- **RBAC.** The installer's ClusterRole holds every permission it grants to
  the connector account, plus the create rights for the fixed objects, the
  TokenRequest for the proof and the Deployment scale update.
- **Open:** the connector Deployment carries no image pull secret, so a
  private registry needs node-level pull credentials or a public image.
- **Qualified.** [Helm cluster run 4](../../test/results/adr193-helm-cluster-native-4/result.json)
  installs the packaged chart in `mode=cluster` from the authenticated
  registry with a synthetic offer and record. The hook's installer account
  administers both guards, the Deployment is ungated, and an upgrade reruns
  the hook without changes. Even the cluster administrator's token request
  and source write are denied: only the installer account administers the
  connector objects, so later changes go through `helm upgrade`. Runs 1–2
  failed because the Job lacked `fsGroup` for its 0440 projected inputs; run
  3 failed in the test's own token request, which the guard correctly
  denied.

## Consequences

Adding a cluster takes one fleet-operator issuance and one `installer-cluster`
run in the region. There is no inbox copy, and no hub-side Kubernetes write
outside the ADR-185 catalog entry. The federation runs from the first
installation with zero peers. Existing installations do not gain the issuance
purposes; they require a role layout migration, which is out of scope.

Open risks:
- The connector backing's `ValidUntil` needs a renewal plan.
- The installed owner probe list allows one catalog cluster slot (ADR-185).

## Implementation

1. Federation peers from SQL: contracts, federation startup and the zero-peer
   start. Requalify `TestFederationRegionalProductWithRealKubernetes` without
   `Peers`, where an unknown peer is refused.
2. Federation provisioning in the continuation, in four parts. Qualify with a
   native continuation run where the federation is Ready at zero peers.
   - **2a:** the federation projection (six SQL logins and audit keys), with
     a journal claim under the ADR-191 bracket like the permission
     projection.
   - **2b:** the phase-3 recipe gains the federation auth role, the audit
     wrap/unwrap policies and the connector client/server sign roles. The
     operator supplies the connector PKI mount, as they do the owner PKI
     mount.
   - **2c:** the federation process uses Kubernetes-auth provider effects.
     Its serving TLS comes from the operator's Secret.
   - **2d:** the federation account, Deployment, L4 Service, RBAC and the
     offer ConfigMap.
3. Bootstrap-authorized generation 1, in one hub conversation over a new
   ADR-169 `bootstrap` purpose:
   - The connector's generation-0 Secret holds only the one-use bootstrap
     envelope. It CAS-writes its pending seed before any request.
   - The hub claims the slot with the identity-free CSR and acknowledges the
     encrypted claim audit. It then binds the channel to the slot and reads
     and stages the delegated source within one five-second observation.
   - It reserves the generation-1 binding: bootstrap, key and staged source.
     The encrypted generation-1 audit is written and acknowledged next, and
     only then does the atomic activation write the lineage (migration
     00064). Audit before activation matches the existing enrollment order.
   - A replay returns the original result, even after expiry. A replay after
     use or rotation commits a fork fence.
   - The `cluster-credential` login loses its direct lineage INSERT;
     lineages arise only through the two bootstrap functions.
   - **Connector block.** `FederationDeployment` gains an installation-wide
     connector block with the hub-decided backing. A region can never choose
     the root backing at first staging.
   - Sub-steps, each testable on its own:
     - **3a:** contracts, the generation-0 Secret, request signing and the
       audit record;
     - **3b:** migration 00064, the adapter, grants and the SQL suite
       (replay, expiry, second key, revocation, fork, direct-write refusal);
     - **3c:** the hub service;
     - **3d:** transport and federation wiring with the connector block;
     - **3e:** the connector bootstrapper;
     - **3f:** the native two-cluster test using `BootstrapIssuer`, without
       `store.Enroll`.
4. The issuance host in the hub-api: SQL purposes and KV through Kubernetes
   auth. Qualify with Keycloak: non-operators and exceeded ceilings are
   denied.
5. `installer-cluster`: native run with the hub from the continuation and the
   region from the CLI.
   - Both leaves activate.
   - A Pod restart is readmitted without an administrator.
   - A rerun is idempotent.
   - A non-administrator source write is denied.
   - An expired bootstrap is refused.
6. The Helm `mode=cluster` hook.
7. Then the ADR-185 catalog entries, the ADR-192 download path and
   `APIContext`.
