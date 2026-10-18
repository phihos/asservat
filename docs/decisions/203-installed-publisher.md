# ADR-203 — Installed publisher

Date: 2026-10-18. Status: accepted; implementation in progress.
Requirements: S-02 (encrypted publication in the installed journey); REQ-DEP-003,
REQ-FED-002; TASK-03.
Completes [ADR-181](181-asynchronous-publication-verifier.md) (the `asservat
publisher` process); follows [ADR-198](198-installed-key-service.md) (installed
key service) and [ADR-196](196-regional-cluster-join.md) decision 7 (catalog
topology pins).

## Context

A stored capture becomes visible only after the publisher verifies and
publishes it. The process exists, but `installer-continue` deploys nothing for
it, so an installed capture stays `stored_unpublished` and the installed S-02
journey cannot reach inspection or download. The process also expects inputs
that the installed layout cannot supply:

- **Static OpenBao tokens** for the audit Transit key (`audit-wrap.token`,
  `audit-unwrap.token`). Installed workloads authenticate to OpenBao with their
  own projected Kubernetes tokens (ADR-147, ADR-193); nothing produces or
  rotates static tokens.
- **A verifier certificate as files** (`verifier-tls.crt`/`.key`). No issuer
  signs `key-client/verifier/*` URIs: the worker PKI role allows only
  `key-client/acquisition/*`, and a key peer may live at most an hour.
- **A read-only evidence credential and an audit credential** for
  `context-verification/v1/<root>/`. The installer receives neither; the only
  evidence credential is the regional write-only one.
- **At least one fixed retention topology pin.** At `installer-continue` time
  there is none: pins live in the cluster catalog and arrive when a region
  joins (ADR-194 decision 6, ADR-196 decision 7).

## Decision

1. **Workload.** `installer-continue` deploys `asservat-<id>-publisher` in the
   hub namespace after the key service: steps `publisher/projection`,
   `publisher/identity`, `publisher/workload` and `publisher/settle`. One
   replica, Pod Security `restricted`, no Service and no route.
2. **SQL.** A projection Secret carries the six existing publisher logins and
   `publisher-roles.json`, claimed as `PublisherProjection` in the public role
   state, exactly as the key service's projection is.
3. **OpenBao identity.** The publisher logs in with OpenBao Kubernetes auth
   using a projected token for its own account
   (`https://asservat.<inst>/publisher-provider/<cluster>`). A recipe derives
   three purpose roles, each with update on one path:
   - `audit-wrap`: `<audit mount>/encrypt/asservat-<id>-publisher-audit`;
   - `audit-unwrap`: `<audit mount>/decrypt/asservat-<id>-publisher-audit`;
   - `verifier-sign`: `<worker PKI mount>/sign/asservat-<id>-verifier`.

   The publisher is the only reader of its verification audit, so it gets its
   own Transit key, created by the provider setup artifact like the
   federation's.

   Logins and renewals are gated by the owner workload guard's current proof
   and the recovery state, as the federation's are. The input names the
   hub-api Deployment the guard proof probes, because the publisher's SQL
   logins cannot read the owner configuration. The static token files are
   removed.
4. **Verifier certificate.** The worker PKI mount gains the role
   `asservat-<id>-verifier`, which allows only the URI SAN
   `spiffe://asservat.<inst>/key-client/verifier/*` and a 20-minute TTL. The
   publisher creates a P-256 key in process, uses a fresh UUID peer ID per
   process, signs an identity-free CSR through `verifier-sign` with the URI in
   the sign request (as worker certificates are), checks the leaf names
   exactly that URI and chains to the worker PKI roots, and renews at half
   the period. The key never leaves the process; the certificate files are
   removed. A compromised publisher can mint only verifier certificates, which
   carry no authority beyond its own: every unwrap still needs ADR-181's
   per-attempt SQL grant.
5. **Operator credentials.** `installer-provider-apply` gains
   `--evidence-read-credential` (GetObject and GetObjectVersion on the
   evidence bucket; no list, write or delete) and
   `--publisher-audit-credential` (PutObject, GetObject and GetObjectVersion
   on `context-verification/v1/<root>/` of the audit bucket). Both reads name
   object versions. Both arrive through
   the inbox and are copied into the publisher's own Secrets. The provider
   setup artifact lists both credentials and their permissions. Separate
   credentials keep evidence reads out of every other hub workload and give
   each audit writer its own prefix.
6. **Topology pins from the catalog.** The publisher reads the guarded cluster
   catalog at startup with the same guard and probe proof as the hub-api, and
   unions the joined slots' pins with its fixed list, which may now be empty.
   When the catalog digest changes it exits and the kubelet restarts it, as
   the hub-api does. A regional capture is therefore published once its
   region has joined.
7. **No readiness route.** The publisher serves nothing. The installer waits
   for the Deployment to settle; the native test qualifies the publisher by
   publishing the installed journey's capture.

## Options not taken

- **Publish from the hub-worker or hub-api.** ADR-181 isolates the unwrap
  authority and the evidence read in their own process; merging them would
  undo that.
- **Keep static tokens and certificate files.** The installer cannot produce
  them without holding long-lived OpenBao credentials, and they would not
  rotate.
- **Have the hub-api issue verifier certificates** through the acquisition
  enrollment coordinator. That path proves an acquisition Pod and token; the
  verifier needs none of it, and the PKI role's URI constraint bounds what the
  publisher can sign.
- **Share a credential with the download workers.** None exists in the
  installer, and sharing would widen both workloads' access.

## Consequences

- An installed capture is verified and published without test help.
- The operator supplies two more storage credentials.
- A region that joins after installation restarts the publisher once, like the
  hub-api.

## Progress

- **Implementation** (unit tests pass): the publisher's projection claim and
  Secret, account and credential Secrets, Service-less workload and RBAC,
  inbox keys and `installer-provider-apply` flags, the continuation steps
  `publisher/identity`, `credentials`, `verify`, `projection`, `workload` and
  `settle`; the provider recipe, setup, artifact section and readback
  (`VerifyPublisher`); the provider effects for the audit Transit key and
  verifier signing; the in-process verifier credential; and the process
  composition with the guard proof, catalog pins and restart on catalog
  change. Native qualification is pending.
