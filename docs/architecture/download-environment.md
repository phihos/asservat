# Processing and download environment

Reader, store and connector placement is static Helm configuration ([artifact downloads](../../specs/artifact-downloads.md)); there is no separate delivery-policy document. Processing decisions are SQL rows. This composition belongs to C-03 ordinary authorization and C-15 privacy; it adds no second permission evaluator.

## Processing restrictions

`ProcessingChanges` records privacy-operator decisions (restrict, release) as SQL rows; `ProcessingReads` reads them. A captured artifact's lineage row is written in the same transaction as catalog publication; there is no permissive backfill. The reader traverses the stored lineage with a recursive query that detects cycles and looks up matching rules through an index; the graph and rule set are bounded by the stored rows, with no node, parent or rule count cap. Missing nodes, cycles, unsupported origins and missing state deny. Artifact rules and workload/acquisition-time rules apply to current and later matching artifacts at read time.

Each decision is one SQL transaction that updates the rule, checks the operator's current rights and writes one audit row (ADR-330 D6). The request carries an idempotency key; a retry returns the stored outcome (D7). A restriction stays in force until an explicit release; expiry of a rule's date never releases it.

## Use in an operation

`CurrentDownloadEnvironment` takes authorized `ContextDownloadEvidence` and the principal, and resolves processing state once per operation. Its result is part of the operation's `DownloadAuthority` and is reused under the same bounds ([download authorization](download-authority.md)). The SQL effect that starts a session or response reads the artifact's processing state in the same transaction and refuses a restricted artifact. The hub never unwraps artifact keys.

A restriction blocks new sessions, metadata views and responses. A response that already started continues to its original bounds ([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md)); restriction never triggers another capture or grants replacement capacity.

Ordinary `get_case` evaluates eligibility and retained audience before reading processing state for existence-sensitive artifacts. It discloses no native filename or checksum.
