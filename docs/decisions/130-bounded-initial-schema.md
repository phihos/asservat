# ADR-130: Separate bounded first-installation schema administration

Status: accepted implementation direction; qualification tracked in the implementation checkpoint.

The supported installer needs to prepare its database before the existing first-activation coordinator can inspect the exact pristine schema. Passing administrator credentials to the preparation or activation workload would erase the established separation between DDL, role preparation, audit and activation.

Use a separate private `initial-schema` command with the same immutable protected installation plan, distinct DDL login, embedded reviewed migrations and one public claim/completion record in the existing preparation root. Explicit capability declaration preserves old serialized plans. The original claim binds the database incarnation, authenticated DDL role, independently pinned setup manager and exact binary migration bundle. No extra SQL control table or independently trusted activation root is introduced.

Use the already selected Goose version3.28.0 Provider with a purpose-specific session gate and one transactional upward migration at a time. Up/UpByOne's unlocked HasPending initialization is unsuitable. Standard metadata creation happens once under the same lock after the protected original claim; Goose cannot recreate it or run Down through this facet. Unknown replies remain unresolved until exact current original-prefix inspection; neither table absence nor a new binary authorizes an unrelated attempt. Complete replay performs no repair.

The root is long-lived installation provenance; each actual phase has fresh current administrator/guard authority limited by its original five-second deadline. The process itself is finite. DDL is not recovery readiness, and a postmaster/database change requires the separate recovery protocol. Initial activation continues to require its own exact inventory, witness and independently acknowledged encrypted audit.

The setup manager must be established and pinned before the final plan. This increment accepts a supplied manager and installs only the compiled narrow grants. ADR131 owns the supported automatic producer, original private credentials and retirement; operators are not intended to hand-author OIDs. Resuming preparation after child-role creation uses a separate read-only schema-completion check; completed installation uses passive history and does not reopen active DDL or setup credentials.

Implementation and limitations: [initial schema architecture](../architecture/initial-schema.md).

Primary implementation references: [Goose Provider](https://pressly.github.io/goose/documentation/provider/), [pinned Provider API](https://github.com/pressly/goose/blob/v3.28.0/provider.go), [pinned lock and transaction handling](https://github.com/pressly/goose/blob/v3.28.0/provider_run.go), [PostgreSQL transaction-level and session-level advisory locks](https://www.postgresql.org/docs/18/explicit-locking.html#ADVISORY-LOCKS).
