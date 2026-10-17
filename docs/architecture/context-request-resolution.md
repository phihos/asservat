# Resolving uncertain context requests

C09 exposes `ContextInvestigation.ResolveContextRequest` through a distinct
`ContextRequestResolution` port. It uses current identity and recovery, then
returns a typed accepted-or-closed disposition with an original private
`ValidUntil`. Only an acknowledged transaction can supply the closed result.
Both browser and MCP must retain this deadline through final identity checks,
encoding and the socket write, just as for other protected metadata.

`ContextRequestResolutions` is a separate PostgreSQL facet and credential.
It locks recovery before the permission root, looks up the exact request key,
then the immutable preview ID, then bounded legacy matches. A private decoder
validates the existing canonical compiler scope, digest, actor, capture ID,
execution class, target and deadline before current ordinary read authorization.
The old key with another request still conflicts after current authorization.
Accepted lookup does not require a live Pod or an available collector.

Owned passive previews can be closed with current identity, read OAuth scope
and recovery after target permission is removed: this discloses no target data
and only removes possible future admission. Existing accepted work still needs
current target read entitlement. Another actor/client's UUID is treated as no
request owned by this caller; its negative marker cannot affect the real owner.

A close writes its triple once while keeping the original blueprint and deadline.
A missing preview needs a finite actor/client negative fence, rather than an
inference from a missing SELECT. Fences and previews share the existing passive
quota. Creation checks closed/fenced state before insertion or exact retry.
Reviewed SQL admission checks the same durable row under the same root lock
and compares all frozen IDs, scope, target, placement, retention, audience and
assessment rules. Final SQL time also bounds the original preview deadline.
No retained preview observation becomes current collection authority.

Migration 00036 keeps the earlier progress guard's immutable fields and adds
preview ID. Its preview/fence triggers pin their search path and reject clearing
or rewriting closure, early deletion and deadline changes. Runtime roles have
no trigger/function modification or broad capture/custody writes. Native fixture
sources assert SQLSTATE 42501 for those role boundaries.

The staged focused unit/race tests pass for application capture/planning,
PostgreSQL helpers and domain capture. They cover strict canonical historical
scope parsing, read-scope recovery without acquisition composition, lost closure
responses, malformed dispositions, private deadlines and sequential original
identity/recovery intervals. SQL generation matches sqlc v1.31.1 and the Go
architecture check passes. The integration package compiles; without the owned
fixture environment it skips native execution, which is not a native result.

Native sources add close/admit races, closed and missing-preview recreation,
alternate-key legacy recovery, cross-client isolation, shared passive budgets,
expired original create rejection, current target revocation, narrow roles and
identity expiry behind a root lock. Those sources have not yet run against the
owned PostgreSQL/S3 fixture in this staged checkpoint. Five-minute negative-fence
wall-clock expiry, a deliberately lost PostgreSQL COMMIT acknowledgement,
restore, final public mapping and the merged release gates remain qualifications
outside these local unit results.

No new external service or library is needed. Historical request lookup still
uses the existing unkeyed v1 compatibility digest; a future protected keyed
lookup migration and finite request tombstones remain part of metadata privacy
and U13 retirement work. No capture/evidence/audit row is deleted by this slice.
