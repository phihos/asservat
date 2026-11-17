# Hub schema migrations and query bindings

`00001_baseline.sql` creates the complete hub schema of an empty database
([hub persistence](../specs/persistence.md)). It replaced the pre-release
migration chain; no released database used that chain, so there is no upgrade
path from it and no Down section. Schema changes are new numbered goose
migrations (`00002_*.sql` and on), transactional and Up-only.
`currentSchemaVersion` in `internal/adapters/postgres/custody.go` names the
head; `asservat setup` applies pending migrations as the schema-owning role and
creates the runtime roles and their grants. Runtime roles never own schema
objects or modify the goose history.

Upgrades have no downtime ([ADR-335](../docs/decisions/335-usable-by-default.md) D13):
migrations are expand/contract. A migration only adds or widens, so the
previous release's binary keeps working against the new schema; removing
anything it still uses waits one release.

`queries/` holds the sqlc query definitions. Use `make sql-tools` for pinned
sqlc and goose. `make sql-check` regenerates the bindings in a private
temporary directory and compares them with
`internal/adapters/postgres/custodydb`; after an intentional schema or query
change, run the pinned `sqlc generate`, review the generated code and run the
real-PostgreSQL tests (`make custody-integration`).
