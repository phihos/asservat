# Processing and download environment

[ADR-127](../decisions/127-current-processing-and-download-placement.md) separates deployment/client delivery policy from durable processing decisions. This composition belongs to C-03 ordinary authorization and C-15 privacy; it adds no second permission evaluator.

## Delivery policy

`download-environment.json` is a ConfigMap rendered by the Helm chart, closed by [its schema](../../specs/contracts/download-environment.schema.json) and at most 128 KiB. Each hub process reads it from a mounted file or a shared informer. The last valid revision stays in force until a newer valid revision replaces it (ADR-330 D1); an invalid update is rejected and logged, and the previous revision remains. The accepted revision and digest are logged.

The policy selects, per client and region, which configured store/reader paths may deliver. It may permit or remove a configured path; it cannot invent a reader, hub pool or processing location. Empty permitted sets deny. A client allowlist alone does not grant disclosure.

## Processing restrictions

`ProcessingChanges` records privacy-operator decisions (restrict, release) as SQL rows; `ProcessingReads` reads them. A captured artifact's lineage row is written in the same transaction as catalog publication; there is no permissive backfill. The reader follows at most 64 nodes, 16 parents each and 1,024 rules. Missing nodes, cycles, unsupported origins and missing state deny. Artifact rules and workload/acquisition-time rules apply to current and later matching artifacts at read time.

Each decision is one SQL transaction that updates the rule, checks the operator's current rights and writes one audit row (ADR-330 D6). The request carries an idempotency key; a retry returns the stored outcome (D7). A restriction stays in force until an explicit release; expiry of a rule's date never releases it.

## Use in an operation

`CurrentDownloadEnvironment` takes authorized `ContextDownloadEvidence` and the principal, and resolves delivery policy and processing state once per operation. Its result is part of the operation's `DownloadAuthority` and is reused under the same bounds ([download authorization](download-authority.md)). The SQL effect that starts a session or response reads the artifact's processing state in the same transaction and refuses a restricted artifact. Reader dispatch compares the selected store and region with the accepted path. The hub never unwraps artifact keys.

A restriction blocks new sessions, metadata views and responses. A response that already started continues to its original bounds ([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md)); restriction never triggers another capture or grants replacement capacity.

Ordinary `get_case` evaluates eligibility and retained audience before reading processing state for existence-sensitive artifacts. It discloses no native filename or checksum.
