# Recovery fence for effects

REQ-DB-005 requires that evidence effects stop when the database is restored or the installation is suspended for recovery. C-04 owns one `installation_recovery` row: installation ID, recovery epoch (database incarnation) and state (`active`, `suspended`, `recovery-blocked`). The `setup` Job seeds the first row. A restore or administrator recovery transition changes the epoch or state. Fleet configuration reads never change this row and never suspend it (ADR-330 D1).

## Use

An operation records the recovery epoch it was authorized under in its `DownloadAuthority` or context-admission decision ([download authorization](download-authority.md)).

Every effect transaction (download session start, response start, context admission, verification, catalog publication, workload quota charge) reads the recovery row `FOR SHARE` and requires state `active` and the recorded epoch. Shared row locks do not conflict with each other, so effects across the installation do not serialize. A recovery transition updates the row, waits for in-flight effect transactions and makes every later effect fail. Holding the lock never extends any deadline.

The installation-to-database association comes from process configuration; a caller cannot select another installation. Quota charges lock only the affected workload allocation row with a conditional update (`used + n <= limit`), never an installation-wide permission or trust row (ADR-330 D7).

A recovery epoch change is published with `NOTIFY`; started responses and other long-running effects listening for it end (ADR-312). Accounting completion, cancellation and audit rows for already started work may still be written; they create no new disclosure.

## Privileges

The hub process role can read and share-lock the recovery row. It cannot change state or epoch. Only the `setup` Job and the administrator recovery procedure change them. Restore reconciliation is specified in [persistence](../../specs/persistence.md).
