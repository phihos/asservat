# ADR-203 — Installed publisher

> Superseded in part by ADR-328 (2026-11-13): the owner workload guard proof that gated OpenBao logins, the guarded catalog read with its dry-run UPDATE probe, the hub namespace guard pairs and the bridge exemption no longer apply. The publisher reads the catalog ConfigMap under RBAC and logs in with its projected token; Helm deploys it instead of `installer-continue`. The separate process, OpenBao purpose roles, verifier certificate, separate storage credentials and per-attempt SQL unwrap grants remain valid.

Date: 2026-10-18. Status: accepted; implemented; installed verification, audit acknowledgement and catalog publication observed.
Requirements: S-02 (encrypted publication in the installed journey); REQ-DEP-003,
REQ-FED-002; TASK-03.
Completes [ADR-181](181-asynchronous-publication-verifier.md) (the `asservat
publisher` process); follows [ADR-198](198-installed-key-service.md) (installed
key service) and [ADR-196](196-regional-cluster-join.md) decision 7 (catalog
topology pins).

Current qualification (2026-10-20): the installer deploys the publisher with
its provider setup, credentials and protected inputs.
Independent fresh lifecycles
using the compiled verifier and publisher roles pass publication, historical
replay and purpose-isolation checks, with synthetic current authority.
Resumed native48
completed acquisition and storage, followed by installed verification, encrypted
verification-audit acknowledgement and catalog publication. The
SQL postmortem
records publication at `2026-10-20T18:09:06.234647Z`. The generic custody row
remains `stored_unpublished`; the separate verification, audit and catalog
records establish publication.

Native48's overall installed test exited 1. Its public capture response remained
`OutcomeUnknown`, and an exhausted admission-resolution reservation stopped the
fixture before fresh capture/case reads or download.

Resumed native49
again reached installed verification, audit acknowledgement and catalog
publication, then recovered the accepted capture and completed fresh authorized
`get_capture` and `get_case` reads with one published artifact. Its outward
capture replies remained `OutcomeUnknown`; the fresh reads independently
established the result. The overall test still exited 1 at the deletion fixture's
strict bucket-policy comparison: the provider returned a singleton `Action` as a
scalar rather than an array. No deletion fault was applied and no download
session was created. Native download, revocation, expiry, deletion and the
complete S-02 workflow remain unqualified.

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

1. **Workload.** Helm deploys `asservat-<id>-publisher` in the hub namespace
   (originally `installer-continue` steps `publisher/projection`,
   `publisher/identity`, `publisher/workload` and `publisher/settle`). One
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

   Logins and renewals are gated by the recovery state. The static token
   files are removed.
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
6. **Topology pins from the catalog.** The publisher reads the cluster
   catalog ConfigMap at startup under RBAC, as the hub-api does, and
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

Historical checkpoints recorded before the 2026-10-20 status refresh above:

- **Implementation** (unit tests pass): the publisher's projection claim and
  Secret, account and credential Secrets, Service-less workload and RBAC,
  inbox keys and `installer-provider-apply` flags, the continuation steps
  `publisher/identity`, `credentials`, `verify`, `projection`, `workload` and
  `settle`; the provider recipe, setup, artifact section and readback
  (`VerifyPublisher`); the provider effects for the audit Transit key and
  verifier signing; the in-process verifier credential; and the process
  composition with the guard proof, catalog pins and restart on catalog
  change. Native qualification is pending.
- CI run 39091781828
  installed every publisher step, including the readback of the
  operator-applied OpenBao setup, but the process stopped with a generic
  message; the next run, with startup phases, stopped at `publisher/catalog`:
  the hub namespace guard denied the publisher's catalog probe because no
  pair named its account. The pair, the larger bound and the bridge
  exemption above fix that.
