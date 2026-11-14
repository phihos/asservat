# ADR-106 — Regional API context start and completed-result provenance

> Superseded in part by ADR-328 (2026-11-13): Pinned namespace/Pod/specification identities, the native admission probe and namespace-UID guard matching defended against writers in the Asservat namespace and no longer apply. The execution identity, its SelfSubjectReview binding, the SQL execution row and the one-attempt start protocol remain valid.

Status: implementation decision under the maintainer's continuation authorization.
Native qualification and deployment remain separate from this decision.

ADR-104 makes a Kubernetes API status snapshot independent of a node collector.
This continuation joins the existing accepted capture, local start journal,
wrap-only producer, semantic verifier and catalog publication. It does not
introduce another broker, generic job system or approval evaluator.

Use a dedicated Restricted regional execution Pod with its own ServiceAccount.
The compiler's collector image must equal the configured execution image. An
API-server SelfSubjectReview binds its projected credential to that account and
Pod; RBAC and Pod Security protect its namespace (ADR-328). A
fresh local process epoch identifies an instance. A Pod token does not prove
process uniqueness or historical workload cleanliness. Reusing the hub-owner,
connector or download-worker role would improperly combine their authorities.

Migration 00035 adds one immutable execution identity per already accepted
capture/attempt. Separately credentialed preparation rechecks the same current
identity, permissions, complete default audience, compiled scope, prepaid
storage, retention and recovery inside the transaction. Only the acknowledged
first insertion may create the local start object. Unknown SQL or Kubernetes
replies permit exact original lookup, with the original deadline and no new
identities. The original observed Kubernetes UID is recorded before Ready.
Execution consumes the existing journal's resourceVersion CAS; only a definite,
still-current result permits capture. Restarted instances cannot inherit the
stored process binding. Unknown starts remain spent.

The private `apiContextStart/v1` profile replaces target node/boot claims with
exact executor Pod/account/process binding. Historical `onTriggerStart/v1`
serialization and node validation remain unchanged. Each control namespace has
its own start journal; separation of capacity and execution accounts relies on
RBAC, not on namespace-UID admission guards.

Successful acquisition records its original start/acquisition/completion times
and exact bounded ciphertext copy receipts. Publication uses this immutable
history plus current permission, retained-policy and recovery fences. It never
requires the observed Pod or original human request to remain alive. The
existing independently credentialed verification audit gains omitted optional
API execution provenance; this preserves historical node audit bytes and avoids
a second outcome-audit protocol. SQL independently matches the completed result
before verification acknowledgement and publication. A caller-supplied digest
or stored object cannot replace that check.

The same execution row drives Running, known acquisition failure and uncertain
storage progress. No status releases capacity. This initial path starts within
the original request-owned five-second authority interval; it does not freeze
human groups for queued or restarted work. The private connector dispatch route,
protected regional provisioning, finite start-record retirement, deployed
supervision, case navigation and public collection enablement remain pending.
