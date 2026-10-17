# ADR-110: Bounded public operation intent and result audit

- Status: accepted for staged implementation; runtime remains disabled
- Date: 2026-10-11
- Requirement: REQ-AUT-005; S-02
- Owner: C-08 Audit; C-20 composes the public gate

## Decision

Use one server-created `request_id` for each admitted browser/MCP invocation and
its encrypted immutable intent/outcome. Pass that ID as a typed private call
parameter through the existing presentation service; it is not a public field,
context key or second user idempotency ceremony. Intent acknowledgement precedes
application work and outcome acknowledgement precedes metadata delivery. The
final response retains its original caller, identity and metadata deadlines.

Reuse existing Tink control-audit framing and conditional object storage. Each
phase reserves one create attempt before provider I/O. Unknown replies permit
exact lookup/verification only. The journal cannot queue or retry business work;
C-09's original submission key remains the capture recovery authority. An
immutable outcome describes prepared bytes and permanently records client
receipt as unknown. It never claims delivery merely because a socket write
succeeded.

Migration 00040 provides separate normal/resolution pool rows, bounded lazy
principal accounts and immutable operation records. Every account has fully
backed finite record capacity; each record reserves two maximum 64 KiB objects.
Changing clients or rotating an input/output MAC key cannot reset spend. Use a
separate stable account MAC key/version, preserving ordinary audit-key rotation.
A future stable-account-key migration must verify a finite mapping that retains
all existing charges. No developer has to configure an account.

Normal traffic cannot use resolution pool slots or its configured process rate,
concurrency, SQL pools and provider clients. Future download cancellation needs its separately protected stop-authority
path and reserved audit resources; the current read-scope wrapper must not be
silently broadened. Other supported loss-recovery controls preserve their
underlying authorization. Backing updates use bounded
revision CAS and retain all charges; shrinking below retained account spend is
rejected. This is logical budget isolation, not a measured hardware scheduling
or provider service-level guarantee.

## Reasons and limits

Capture-intent and download-batch audit describe different events and cannot
stand in for metadata reads or public calls. Reusing their encryption and
receipt verification avoids a new event framework or crypto format. The initial
six-operation wrapper covers typed context/case invocations including invalid
inputs and read-scope denials that reach it. It is not connected to production
transport: existing MCP SDK/ingress errors still need the same authenticated
admission boundary, and invalid-auth/pre-admission exhaustion needs bounded
security evidence/counters. Full REQ-AUT-005 compliance is not claimed.

Two encrypted phase records require two wraps, two independent unwraps and two
PUT/GET pairs. These costs are separate from an artifact's three wrap calls and
matter for two-second polling. A fixture measures actual counts and latency;
no synthetic CPU measurement supplies production throughput defaults.

There is no refund or deletion in this staged schema. Positive writer completion,
purge/checkpoints, finite audit cleanup and protected key/configuration provision
remain enablement prerequisites. ADR-111's four-copy artifact completion does not
authorize these two audit objects. Expiry, 404 or canceled HTTP cannot release
charges. Unknown outcomes stay spent, and audit-only finishing never revives
human authority or application effects.

See [operation audit](../architecture/operation-audit.md) for implementation,
verification scope and the remaining production boundary.
