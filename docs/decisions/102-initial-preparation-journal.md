# ADR-102 — Persist bounded installation creation intent

Status: accepted engineering continuation of ADR-101. Actual qualification is
recorded in [implementation progress](../implementation-progress.md).

## Decision

Reuse the staging policy's public preparation ConfigMap as a bounded creation
journal. Retain the exact installation, preparation request, public plan digest,
new namespace and admission identities in its initial document. The private
[wire contract](../../specs/contracts/initial-preparation.schema.json) permits at
most 64 ordered Kubernetes create intents within 48 KiB. It contains only public
resource identity/specification digests and acknowledged UIDs/resource versions.
Credentials, secret-payload hashes, evidence and arbitrary provider responses
remain outside it. This introduces no database table, CRD, service or dependency.

Persist an intent before its external create. Only the first acknowledged,
UID/resource-version-qualified journal update may report a fresh attempt.
Concurrent callers lose the comparison or read the same spent intent. A timeout,
lost reply, failed final protection check or later retry cannot report freshness,
even if a read finds the desired value. The supervisor reconciles the exact
resource; it never turns a pending record into another create permission.

Record only an independently verified create receipt. Receipts cannot be
replaced; a pending record blocks the next intent. Repeating the same observed
receipt is read-only. A journal acknowledgement is scheduling/provenance state,
not current authority to perform an operation, clean-history proof, encrypted
audit, SQL activation or recovery approval.

Require online administrator identity, the retained journal UID and independent
native staging enforcement before reads or updates and after writes. All checks
share the original at-most-five-second deadline. A removed staging guard makes
this facet unavailable; handover and final-guard access require their own
composition. Missing initial state is not permission to regenerate it.

## Basis and boundaries

Kubernetes's [update contract](https://kubernetes.io/docs/reference/using-api/api-concepts/#updates-to-existing-resources)
uses resource versions to reject stale writes. This design uses conditional PUT
with strict decoding and no automatic retry; the stronger uncertain-outcome rule
is an Asservat decision. A [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/)
is suitable for the public record only; actual credentials stay in protected
Secrets and purpose-specific providers. Sources checked 2026-10-11.

The initial namespace creator and journal creation can still fail before their
root identities are durably handed to the full supervisor. They return known
creation provenance and do not adopt unknown same-named resources. The complete
supervisor must retain those roots, reconcile partial setup, verify resource
inventory and every effect, and compose final protection/provider retirement.
The current journal covers ordered Kubernetes creates during staging. It is not
the provider transaction log, a complete Helm installation or an automatic
first-installation/recovery reset mechanism.

The first actual producer consumes this journal for the predefined writer
account and installation RBAC. Bind the public workload-plan digest, stamp each
operation, verify the exact returned/current object and record only its actual
receipt. Unknown replies allow matching lookup, never another POST. Arbitrary
resources, Secret payloads and Pod creation are outside this producer's scope.
