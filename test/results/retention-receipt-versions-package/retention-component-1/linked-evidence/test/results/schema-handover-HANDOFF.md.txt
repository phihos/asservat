# Product schema to original activation qualification

Parent-owned isolated seven-path continuation for ADR-130. Not integrated or
native-qualified at this checkpoint. Integrate only with the verified initial
schema package; its types and actual loader are prerequisites.

The opt-in `--initial-schema-handover` mode selects exactly
`TestInitialSchemaHandoverWithRealServices` on one owned cluster. It bypasses both
fixture Goose migration and broad fixture runtime grants, scrubs inherited mode
environment variables, and requires the exact selected parent test to pass. The
ordinary modes retain their existing migrated database and cluster counts.
Embedded Go migration files now participate in source hashing; this supersedes
the earlier one-line context-harness hashing stage.

The new fixture checks SQL is empty, supplies a separate finite fixture manager
with no application grants, runs the actual protected schema loader from a
separate filesystem projection, checks original bundle/manager/DB incarnation
and unchanged complete replay, removes the DDL credential file, then executes
the existing actual preparation/original activation Pod/audit/cleanup workflow.
It checks schema provenance survives activation and passive reopening.

The schema loader runs inside the test process. The existing original activation
Pod runs the actual compiled executable. This does not qualify an in-Pod schema
command, production manager/bootstrap provisioning, general restart/restore or
public investigation. The fixture supplies administrative/provider roots and
credentials explicitly.

Shared technology copy describes Goose's private installer library use and its
actual module-selected protobuf/logr/asm changes; decisions index links ADR-130.

Verification performed against immutable
`../initial-schema-20261012/review-20261012a` (all 23 payload hashes verified):

- `compile.log`: selected integration fixture source compiles; exit 0, native
  tests skip without the explicit owned fixture variables. Not a native pass.
- `vet.log`: integration package vet exits 0 using the same overlay/module file.
- `harness.log`: 15 synthetic selection/environment/CLI/migration-exclusion and
  embedded-source mutation checks pass, without starting external services.

`manifest.json` records every original base hash and staged payload hash. No live
source files were edited. Re-run affected gates after integration; actual SQL
and composed Kubernetes/SQL/OpenBao/S3 qualification remain required.
