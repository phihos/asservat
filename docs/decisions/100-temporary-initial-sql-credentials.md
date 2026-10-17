# ADR-100 — Temporary initial-installation SQL credentials

Status: accepted engineering refinement under the ongoing implementation
authorization. Measured qualification is recorded in [progress](../implementation-progress.md).

## Decision

Use three random, installation-specific PostgreSQL logins for ADR-099's
preparation, audit acknowledgement and activation facets. A separate trusted
maintenance principal provisions them. That principal needs `CREATEROLE` and
the precise schema/table/column grant options; it is not a superuser and must
never be mounted into the activation Pod or ordinary services.

Generate independent 256-bit secrets, persist their exact closed
[private state](../../specs/contracts/initial-sql-credentials.schema.json) in
protected immutable storage before creating roles, and keep one fifteen-minute
password validity interval. Bind that state to the installation and the digest
of its complete public startup plan. Replay neither replaces passwords nor
extends validity. Matching names are insufficient: verify exact role attributes,
memberships, ownership, grants and original expiry, then authenticate the supplied
passwords over verified TLS using SCRAM only.

The activation executable independently derives the exact installation/purpose
username and enforces SCRAM-SHA-256 before connecting. Distinct foreign-purpose
credentials or an HBA trust/password/MD5 fallback must not turn an expired or
substituted credential projection into authority.

Derive salted SCRAM-SHA-256 verifiers client-side using
[`xdg-go/scram` v1.2.0](https://github.com/xdg-go/scram/tree/v1.2.0).
Never send plaintext passwords as role DDL or bind parameters. PostgreSQL warns
that password-changing SQL can expose plaintext in server logs; its
[role documentation](https://www.postgresql.org/docs/18/sql-alterrole.html)
and [CREATE ROLE contract](https://www.postgresql.org/docs/18/sql-createrole.html)
support submitting the already-derived verifier. This is a narrow use of an
established protocol implementation; pgx still handles connection authentication.
Verifiers and persisted credential bytes remain sensitive.

Lock the exact current application table inventory. Creation requires an unused
database, allowing only the same never-activated, suspended/recovery-blocked
fleet root. Create all three roles and their grants atomically. Missing subsets,
foreign state, password mismatch or permission drift fail without adoption.
Reject application grants through `PUBLIC`, ambient schema/database creation,
and accessible application `SECURITY DEFINER` functions. Ordinary catalog reads
and database `CONNECT`/`TEMP` defaults are not activation authority.

Retirement locks the same tables, disables new login and the password, revokes
all known table, column and schema grants, and verifies the resulting state.
It retains the role names as non-login tombstones. It is idempotent and works
after expiry; provisioning cannot reactivate retired roles. Existing SQL
connections are not terminated by `NOLOGIN`: revoking their effect privileges
is required too. Unexpected grants require explicit maintenance reconciliation;
do not report them as retired or silently erase unrelated permissions.

## Scope

This implements the SQL provider portion, private state codec and protected
Kubernetes Secret producer/reader, not a complete installation supervisor.
The Secret adapter proves the exact configured administrator, native namespace
protection, immutable startup plan and original gated Pod before one create-only
request. Lost replies permit exact retained-content lookup, never a new password
or replacement. Reads require the retained Secret UID and current protection;
their cleanup path does not require the Pod to remain running.

The native fixture still supplies the maintenance principal, clean namespace,
guard/startup provisioning and external key/store credentials.
Production orchestration, key/store credential retirement, local-key
bootstrap and restart/restore remain separate work. None of these logins provide
ordinary runtime collection or evidence-disclosure authority. No migration or
public API changes.
