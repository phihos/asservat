# ADR-204 — Installed native downloads

Date: 2026-10-18. Status: accepted; implementation pending.
Requirements: S-02 (inspection and native download in the installed journey);
REQ-DLD-001, REQ-DEP-003; TASK-03.
Amends [ADR-194](194-promoted-owner-inputs.md) decision 5 and
[ADR-192](192-capacity-before-download-paths.md) decision 3. Follows
[ADR-179](179-outbound-only-first-installed-profile.md) decision 1 (hub-local
download workers), [ADR-069](069-download-worker-dispatch.md) to
[ADR-071](071-download-worker-enrollment.md) and ADR-203 (installed publisher, in review).

## Context

An installed hub-api serves no download content: its download service needs a
current worker profile, and nothing in the installed layout produces one.
Today:

- the worker profile source holds an "unconfigured" marker in the hub
  namespace, but the profile reader requires the profile's namespace to be its
  own control namespace, and the hub namespace guard admits Jobs only from the
  built-in controllers;
- the owner input pins no worker API client (`WorkerAPIs` is empty) and no
  download path;
- no hub-worker child accepts a worker configuration revision into SQL;
- the key service authorizes `wrap` and `unwrap/verifier`, not acquisition
  unwraps;
- the hub-api serves neither worker enrollment nor the worker's native path;
- the content route accepts only tokens for the downloads resource, and the
  installed identity provider issues none.

ADR-194 decision 5 deferred the worker namespace to regional provisioning
(ADR-192 decision 3). ADR-179 decision 1, which the code follows, places the
first profile's workers in the hub region instead.

## Decision

1. **A hub-cluster worker namespace.** `installer-continue` creates
   `asservat-<id>-downloads` in the hub cluster with Pod Security `restricted`,
   its own workload guard, the worker account, the zero-priority
   non-preempting PriorityClass, the immutable worker control ConfigMap and the
   immutable store Secret. Workers never run in the hub namespace.
2. **The profile source lives with the workers.** The guarded worker profile
   source moves into the worker namespace, and the hub-api reads it with its
   pinned worker API client. The profile reader's same-namespace check stays
   as it is. The hub namespace's worker marker is removed.
3. **One hub-local path.** The first download path names the hub cluster as
   acquisition and connector cluster (the hub-api serves the worker's native
   path itself) and each joined cluster as a target. No connector runs in the
   hub cluster.
4. **Pinned at installation.** The worker API client, its projected token and
   the path are pinned in the owner input when the owner is promoted. A later
   change needs a new owner input; runtime path acceptance (ADR-192's other
   option) is deferred until a second path exists.
5. **Its own read credential.** `installer-provider-apply` gains
   `--download-evidence-credential` (GetObject and GetObjectVersion on the
   evidence bucket), stored only in the worker namespace's store Secret. It is
   separate from the publisher's (ADR-203 decision 5) so each workload holds
   only its own principal.
6. **The product image.** The worker profile names the installation's product
   image digest; `asservat download-worker` is already its command.
7. **Hub-worker acceptance.** The hub-worker gains a worker configuration
   child (`WorkerConfigurationObserver`) with two new SQL purposes (observe and
   audit) and the audit prefix `download-worker-configuration/v1/<installation>/`
   under its own Transit key, as ADR-070 requires.
8. **Acquisition unwraps.** The key service adds `unwrap/acquisition` through
   the native download key authority, with a new key-service SQL purpose that
   spends download key slots and the retention and recovery guards that
   authority needs.
9. **Owner serving.** The hub-api serves worker enrollment and the worker's
   native path on its existing private listeners, with the existing handlers.
10. **A downloads token.** The installer's identity settings name a client
    whose tokens carry the audience `<origin>/api/v1/downloads`. A browser
    session or MCP client fetches content with such a token; the MCP token's
    single `/mcp` audience stays unchanged.

## Options not taken

- **Workers in the hub namespace.** The namespace guard admits Jobs only from
  the controllers; widening it would let the hub-api create arbitrary Pods
  beside its own credentials.
- **Keep the source in the hub namespace and relax the reader's namespace
  check.** That check is what binds a profile to the namespace its Jobs run
  in.
- **Workers in the workload cluster.** ADR-179 keeps decryption out of
  workload clusters in the first profile.
- **Share the publisher's evidence credential.** Workers run arbitrary
  per-download Pods; a separate principal limits what one exposes.

## Consequences

- An installed journey can end with a native download.
- The operator supplies one more storage credential and configures the
  downloads client in the identity provider.
- Adding a second download path needs a new owner input until runtime path
  acceptance exists.
- The worst-case SQL connection plan for one hub (two retained hub-worker
  processes during a rollout) rises from 95 to 101 ordinary connections with
  the three new logins, above PostgreSQL's default of 97 usable connections.
  An installation with downloads needs `max_connections` of at least 104.

## Progress

- **Decisions 7 and 8, SQL and composition** (unit-test results only; the
  installer step, native runs and qualification are pending):
  - Purposes `worker-config-observe` (86) and `worker-config-audit` (87) in
    the hub-worker compartment, `key-acquisition` (88) in the key service's.
    Their grants are the exact statements of `WorkerConfigurations` and of
    both `NativeKeyAuthority` resolvers. The role layout digest changes
    (fresh installations only).
  - `PermissionDeployment.WorkerConfiguration` (optional): the worker
    namespace, source, guard and audit Transit key. Its two logins ride in
    the permission projection after the retention logins, and the child runs
    beside the permission stream, like retention, because the section
    arrives with that projection after the hub-worker starts. Without the
    section there is no child and no login.
  - `KeyServiceDeployment.Downloads` (optional): a pinned copy of the
    worker profile document, parsed like the guarded source. It only selects
    the profile; every spend still needs SQL's current audited revision to
    equal it. Topology pins come from the guarded cluster catalog, and a
    catalog change restarts the service, as for the publisher. Without the
    section the authority map is unchanged.
- **Decision 9, owner serving, and decision 2's hub-api side** (unit-test
  results only; installer wiring, native runs and qualification are pending):
  - Only with a configured worker profile, the owner port (9443, the
    in-cluster owner Service) is split by ClientHello. The exact process name
    stays the owner relay. The pool's fixed serving name (the
    `owner-bootstrap/v1` name already in every owner server leaf) reaches
    worker enrollment over HTTP/1.1, and the worker native path over h2 with
    client roots from the profile's current issuer roots, per handshake.
  - Enrollment reuses the owner runtime's exact-owner forwarder and locators.
    The native path (`HubWorkerAdmission`) attaches only an operation this
    exact process owns, on a path whose connector cluster is the hub
    cluster. It forwards nothing, so a second hub-api replica cannot serve
    another replica's conversation.
  - Workers dial the Service but verify the fixed name. `WorkerControl`
    gains the optional `address` and `native.exchangeAddress` (connectivity
    only); absent, documents and digests are unchanged.
  - With exactly one pinned worker API in its own namespace, the hub-api
    reads the guarded profile source with that API's client and proves its
    guard with `native-kube-probe-<cluster>-<namespace UID>.token`. More than
    one worker API is refused; none keeps the hub namespace source.
- Found while composing: the hub-api's download purposes lack SELECT on the
  processing tables their download fence reads (the test fixture grants
  them), so an installed download would be refused until they get it.
