# ADR-126: Bind connector identity to automatic process enrollment and bounded renewal

Status: Accepted design; the isolated component checkpoint has no installed runtime enablement. Actual qualification and outstanding retirement work are listed in [the architecture contract](../architecture/connector-renewal.md).

## Context

A connector needs its own client identity and a separate server identity for private native exchanges. A clientAuth certificate cannot serve as serverAuth. Normal Kubernetes Pod and container restarts must not require repeated administrator bootstrap or create new logical accounts that reset signing/audit limits.

## Decision

Keep the installation/cluster/logical connector identity stable. Current Pod-bound TokenReview, live Pod/account/controller reads and independently protected source/guard proof may enroll a new bounded process epoch with two process-owned P-256 keys. No request provides a chosen human actor or fabricates an authenticated TLS leaf. The existing legacy bootstrap identity remains historical and unchanged.

Retain one pending epoch per Pod and separately bounded serving/retained epochs. A same-Pod replacement retires the prior serving epoch atomically only when the new client and server leaves both have independent encrypted audit acknowledgement. Old pending/unknown epochs, signing attempts and possible leaves remain charged. A delayed reply cannot activate an epoch retired by a newer admission. Rolling Pods consume independently bounded serving slots.

Each process has an original finite end. Thirty-minute leaf periods and one-minute overlap derive from its original admission; each purpose/period has at most two nonrefundable provider attempts. The process renews or replaces its epoch before that original end. Distinct private signing roles, roots, DNS/URI constraints and current exact-leaf registration checks remain mandatory on reused TLS connections. Historical certificate results can finish their original audited activation only within their existing bounds; an unknown provider claim never permits another signature.

Migration49 adds purpose-specific process/source/credential/backing rows and six authenticated SQL duties. Reuse the encrypted operation pair and finite cleanup machinery with an explicitly qualified private actor/layout and stable peer account. Public human encodings and operation allowlists stay unchanged. Exact private functions admit business records; audit credentials cannot invent those records. The per-intent auditor selects the immutable already-admitted policy without a revision cache or relaxed writer deadlines.

Separate immutable behavioral profile identity from full protected configuration/backing identity. Backing-only renewal keeps existing process/key/leaf provenance unchanged, but all current consumers still compare the complete observed backing revision/digest against exact accepted or recognized pending state. A dedicated acknowledged backing-transition pair precedes atomic source-role promotion. Unchanged observation is not renewal, and known mutation/rollback commits a fence. Both staging and its terminal close/promotion are charged at stage admission. Exhausted source-transition capacity denies ordinary authority, while the exact prepaid terminal transition remains possible.

Five fixed security-barrier lifecycle views expose only the current session login's pinned identity roots and identity lane. Explicit columns, local CHECK OPTION, immutable-key update guards and separate duty grants preserve the underlying complete-history tables without RLS. PostgreSQL defines CURRENT_USER within a view as its invoker and notes that security barriers can lock rows later filtered out; actual role/owner and bounded contention tests are therefore required. [PostgreSQL CREATE VIEW](https://www.postgresql.org/docs/current/sql-createview.html)

## Consequences

This checkpoint supplies production domain/application/SQL/provider/credential components and a fast real SQL/S3 fixture source. It does not supply the complete installed connector listener/renewal supervisor, independent production backing qualification or all cleanup producers. The typed retirement-only live proof is separate from ordinary issuance proof. Distinct prepaid historical retirement tickets, finite source/profile/root retirement, the real minimum-time cleanup case and installed role/issuer/bootstrap composition are required before runtime enablement; a current live actor is not assumed to exist after a crash or expiry. Removing the final cluster must leave an ordinary installation able to enroll another cluster. Permanent root minimization belongs only to explicit whole-installation teardown.
