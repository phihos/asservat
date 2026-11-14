# Privacy and administrator retention limits

Read with [evidence lifecycle](evidence.md), [authorization](authorization.md) and the [privacy research](../docs/research/privacy-retention.md). These are product controls; operators assess their own processing arrangements before making compliance claims. Retention is stored as deadlines on each artifact and shortened by events ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D12).

## REQ-PRV-001 — Purpose, classification and collection minimization

"User data" means data concerning or supplied by users of the observed application, including internal tools; it is distinct from the legal term "personal data".

The administrator owns the diagnostic purpose, permitted workload scope, storage locality and retention. The chart ships usable defaults (a generic incident-investigation purpose, every namespace outside the excluded system namespaces, hub-region locality, the baseline below), so a default installation collects. Captures reuse these settings; legal basis, DPIA and processor arrangements are documented outside the evidence.

Privacy classification is independent of the `raw`, `extract` and `metadata` access classes: `unknown`, `potentialPersonalData`, `personalData`, `specialCategoryPossible`, `verifiedNonPersonal`. Unknown is treated as potential personal data. Cores, heaps, logs, files, command output, profiles and network captures default to potential personal data. Only a reviewed, versioned transform with an administrator-approved field model may produce `verifiedNonPersonal`; encryption, redaction, hashing or a clean scan never establish anonymity.

Collectors derive the evidence type from the actual acquisition: `coreDump`, `heapDump`, `packetCapture`, `syscallTrace`, `logs`, `files`, `profile`, `commandOutput`, `context` or `other`. Maintainers cannot downgrade a classification. Derived artifacts inherit parent deadlines.

Default presets collect bounded context; full environments, payloads, broad file trees, all-node capture and continuous high-frequency profiling are not defaults. Collection ceilings can forbid classes or actions per workload. [Capture assessment](capture-assessment.md) shows possible content before collection.

### SC-PRV-001

Given a core with synthetic user records and a profile with a user-bearing sample label, when collected or transformed, then both receive privacy controls regardless of file extension or extract class. A user-supplied nonpersonal label and a clean pattern scan cannot weaken those controls.

## REQ-PRV-002 — Canonical administrator policy and precedence

`EvidenceRetentionPolicy` is a CRD in the hub control namespace; local administrators may add policies in their cluster's connector namespace, which the connector pushes to the hub. Both namespaces are administrator-only ([ADR-328](../docs/decisions/328-administrator-only-namespaces.md)). Status reports `observedGeneration`, the effective digest, applied clusters and blockers.

One installation-wide baseline sets finite maxima for evidence, case metadata and audit metadata; it defaults to 14 days for evidence (including cores), 30 days for case metadata and 90 days for audit, changeable on `helm upgrade` ([example](../examples/retention-policy.yaml)). Further policies select clusters, namespaces and workloads, optionally with rules by privacy class and evidence type. All matching policies apply and the shortest maximum wins; local policies only tighten. Selector dimensions are ANDed, values within a dimension ORed. Unknown classification matches potential-personal-data rules; `other` evidence matches every type-specific rule. Policies leaving no positive usable time are refused. Without a baseline no collection starts. Maintainers may request shorter retention; longer requests are clamped. Shares last until the evidence's access end ([ADR-335](../docs/decisions/335-usable-by-default.md) D7).

Collection stores the resolved deadlines on the artifact (REQ-PRV-003). When a policy event arrives, the hub applies it to existing evidence with one set-based update per affected set (`expires_at = LEAST(expires_at, …)` and the same for `delete_by`), matching each artifact's recorded cluster, namespace and workload, and writes one audit row. Shortening is monotonic, so late events converge; a longer maximum or a deleted policy never extends a stored deadline. Deleting the only baseline suspends new collection.

`preview_retention_change` (browser only, administrators, [ADR-240](../docs/decisions/240-retention-impact-preview.md)) applies proposed policy changes to the current set and runs one aggregate SQL query over stored deadlines. It reports affected counts per cluster, privacy class and evidence type, how many become unreadable or due at once and the earliest new deadlines, and lists clusters whose local policies have not reached the hub as incomplete. It writes nothing.

### SC-PRV-002

Given a global 24-hour limit and a local 6-hour core rule, when a maintainer requests 7 days or moves a core into a shared case, then its limit stays 6 hours. Tightening to 2 hours makes existing older cores due for immediate expiry and deletion. Raising to 48 hours does not revive or extend earlier artifacts.

### SC-PRV-009

Given retained artifacts under a 24-hour baseline and an administrator, when they preview lowering the baseline to ten minutes, then every artifact is affected and the earliest new deletion is the earliest anchor plus ten minutes, with access ending five minutes earlier; a limit already passed counts the artifacts as unreadable and due now. Previewing 48 hours, or deleting a policy, affects none. A cluster whose local policies have not reached the hub is listed as incomplete. A caller who is not an administrator receives `AdministratorRequired` before any proposal is decoded; MCP does not offer the operation; nothing is written.

## REQ-PRV-003 — Age, access cutoff and deletion deadline

Age starts at the first acquisition into Asservat (for a ring, its oldest included segment), not at upload or last access. Imported runtime files may use a trustworthy earlier source-creation time. A derived artifact uses the earliest parent anchor. Clock uncertainty resolves toward earlier expiry.

Each artifact row stores:

```text
hardDeleteBy = min(anchor + every applicable maximum, parent deleteBy values)
expiresAt = min(anchor + requested/default age,
                hardDeleteBy - deletionBudget, parent expiresAt values)
deleteBy = min(hardDeleteBy, expiresAt + deletionBudget)
```

`expiresAt` ends access and starts deletion; `deleteBy` is the storage deadline. The deletion budget (default 5 minutes, administrator-configurable) is the retention worker's time to delete one artifact and sits inside the maximum: a 6-hour maximum allows access for 5 hours 55 minutes.

Reads, shares, cursors, analysis, query results, caches and uploads respect these deadlines; expiry is part of each effect statement. Case titles, indexes, manifests and stored query results with evidence-derived data inherit them; a content-minimized case shell follows the case-metadata policy. Each recurrence gets new deadlines. The manifest records classification, evidence type, purpose, anchor and basis, requested age, resolved maximum, deletion budget and the applied policies; later shortenings update stored deadlines, never the manifest. Only REQ-PRV-005 holds may lengthen a requested expiry, within the maximum.

Relative ages are shown before acquisition and timestamps afterwards. Automatic deletion covers managed copies, not copies already disclosed.

### SC-PRV-003

Given a core acquired at 12:00 with a 6-hour cap and 5-minute deletion budget, when upload completes at 12:20 and an extract is produced at 17:50, then neither can be read at 17:55 and both are due for deletion by 18:00. Sharing, recurrence, copying or analysis cannot restart the clock. A pre-trigger ring starts its deadline at its oldest included acquisition.

## REQ-PRV-004 — Delete every managed copy and report failures

Each artifact's objects live under its own prefix. SQL holds content-minimized references to every managed copy (derived extracts, query output, caches, staging volumes, node spools). Collectors and connectors enforce each local copy's `expiresAt` also while the hub is unreachable.

After `expiresAt` the retention worker deletes every object and version under the prefix and every registered copy, and sweeps again at `deleteBy` to catch late writers. Bucket lifecycle rules (`AbortIncompleteMultipartUpload`, `NoncurrentVersionExpiration`) remove abandoned parts and versions ([S3 lifecycle](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html)). States: `Accessible`, `ExpiredDeletionPending`, `DeletedVerified`, `DeletionOverdue`. `DeletedVerified` means the second sweep found nothing and every copy reported removal; it is not proof of physical sanitization. A minimal tombstone is kept until the backup horizon passes.

Failures retry with backoff; passing `deleteBy` alerts and pauses new collection for the affected allocation (the whole backend only when the failure affects it). Access stays denied. A failing item never blocks later due work.

Evidence is excluded from control-data backups. Restores apply current ceilings, grants, shares, deadlines and tombstones before serving anything; unknown state fails closed.

### SC-PRV-004

Given an expired object with a noncurrent version, a derived result and an offline node spool, when deletion runs, then deleting the current object does not report completion. Access is denied, pending copies stay visible to operators and a `deleteBy` overrun alerts. An object written by a late writer after the first sweep is removed by the second. Restoring an old catalog cannot disclose or recreate expired evidence.

## REQ-PRV-005 — Preservation and immutable-storage conflicts

A debugging hold may extend a shorter requested lifetime up to the applicable maximum. It needs retention authority, scope, reason, finite expiry and audit, grants no readership and cannot override erasure or restriction. `legalExceptions` defaults to `disabled`, so no hold exceeds the maximum.

Object Lock and legal hold are not enabled on the evidence bucket by default. Storage profile preflight checks bucket defaults, lock modes and backup retention; a storage minimum longer than the permitted maximum is `RetentionConflict` and blocks affected collection. An existing compliance-mode lock that prevents deletion denies access and is reported, never claimed deleted.

### SC-PRV-005

Given a 6-hour maximum and an ordinary hold for 3 days, when requested, then storage cannot extend beyond 6 hours. A 30-day compliance-mode bucket fails preflight. If a conflicting locked object exists, shortening the policy revokes ordinary access and reports the storage conflict without a deletion claim.

## REQ-PRV-006 — Rights requests and restricted processing

A privacy operator is an administrator or holds `privacy-operator` through a hub-cluster ClusterAccessBinding ([REQ-PER-001](permissions.md#req-per-001--canonical-permission-configuration)). The Processing console locates candidate evidence by case, workload, time and purpose, inspects lineage, restricts processing, requests early erasure and tracks completion. There is no global user-content index.

Restriction blocks ordinary analysis, disclosure, sharing and reuse until released. It is SQL state ([ADR-127](../docs/decisions/127-current-processing-and-download-placement.md)): rules over artifacts or workload-time scopes, each change a revisioned row with an audit row. Matching evidence published later is restricted too. Early erasure ([ADR-321](../docs/decisions/321-exact-early-erasure.md)) uses the same deletion worker for the artifact, its derivatives and copies. Access and correction responses are prepared as reviewed extracts outside Asservat's public download path; evidence is never silently edited.

Discovery cannot prove complete coverage of arbitrary cores; a broader restriction or deletion by workload and time is allowed. The processing inventory export covers purposes, locations, categories, retention, share recipients, declared processors, deletion backlog and exceptions. The product does not decide legal exceptions.

### SC-PRV-006

Given a validated erasure request covering an incident, when a privacy operator deletes its candidate artifacts, then derived summaries, versions and query caches enter the same deletion plan. A legally preserved item is separately restricted and explained; a missing user tag is not reported as proof of absence.

### SC-PRV-010

Given a privacy operator, when they restrict a published artifact from its case, reload the restriction inventory and release the exact current revision, then new ordinary case reads and native-response starts are refused while restricted and recover for the same artifact after release. Inventory is operator-only. Replaying a change with its idempotency key adds no second audit row. A revision conflict requires refreshed state and another explicit decision. Started responses keep their original bounds (ADR-312).

### SC-PRV-011

Given a retained published artifact under restriction, a privacy operator can find it by its case ID or by workload identity and a half-open acquisition interval, optionally filtered by exact purpose. Results show effective deadlines and the direct parent IDs recorded at publication. An ordinary evidence reader cannot search, and the audit row commits before metadata is returned. The operator can select a result for restriction.

### SC-PRV-014

Given a privacy operator, the console exports the retained processing inventory as audited JSON pages (artifacts including deleted attempts, share recipients, native sessions, operations, rules, technical paths and declared processors), each page stating its observation time and coverage, sized to the hub-api per-response budget (256 KiB). Missing processor declarations and an explicit empty list are distinct. Completion requires exhausting every section. An ordinary reader cannot export. Exported copies are outside managed deletion.

### SC-PRV-013

Given a privacy operator who searched by exact workload and a half-open UTC acquisition interval, the console can review and confirm one restriction for that entire scope, including matching evidence published later. The purpose filter narrows discovery only. Edited search fields invalidate the selection. The change uses one idempotency key; matching reads and response starts are refused; another workload and an anchor at the exclusive end stay outside. Release restores access under the original deadlines.

### SC-PRV-012

Given a retained published artifact, a privacy operator selects it in the Processing console and confirms an exact early-erasure request ([ADR-321](../docs/decisions/321-exact-early-erasure.md)). The request and its audit row name the artifact; the same idempotency key replays the original decision. Ordinary access closes and the artifact becomes due for deletion before its previous expiry, keeping its hard deletion deadline. The operator can reload the request's pending, overdue or verified deletion state.

## REQ-PRV-007 — External agents, transfers and operational privacy

Locality policy covers raw storage, decryption, derived results, indexes, backups and configured destinations. A client acting for a user receives exactly what that user may read (ADR-335). Administrators register OAuth clients; Asservat cannot control an agent's model provider or retention. Prompts and tool results are not logged and no telemetry is sent. The recipient client and disclosure time are recorded. Delivered results cannot be recalled. The product sends no breach notifications; the operator assesses notification duties.

### SC-PRV-007

Given an approved agent receives a bounded extract, when the original expires, then Asservat denies further access and deletes managed copies while reporting the prior disclosure. It never claims deletion from that agent's history. A raw-locality profile that sends personal extracts to another region shows that flow in the inventory and policy preview.

## REQ-PRV-008 — Backup horizons and expiring index segments

The installation documents its control-data backup and WAL retention H. A row deleted at its deadline survives in backups for up to H; backups are read only through restore, which applies tombstones and deadlines first (REQ-PRV-004, [ICO right to erasure](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/)). Status and the inventory show H next to each control-data period. Evidence bytes, full manifests and extracted text are never in SQL or its backups.

Share rows are deleted after expiry plus the case-metadata period. A known-principals row (REQ-AUT-001) is deleted when its principal has not signed in for the audit-metadata period.

Regional evidence-text indexes are in memory within the reader Pod's memory request, rebuilt by the earliest indexed deadline and never backed up. Shortening or early erasure rebuilds the index without affected records.

### SC-PRV-008

Given 90-day metadata and a documented seven-day backup horizon, when a row reaches its deadline, then it is deleted on day 90, status shows the seven-day horizon, and a restore of a day-89 backup does not serve the row. Given an index segment containing a six-hour core extract, expiry or early deletion removes the managed segment copies, not only its search hit.

### SC-PRV-015

Given a manual or capture-time share, when it expires and the case-metadata retention passes, then the share row is deleted. Replay, revocation and transfer do not move that time. A recurring revoke-all affects only its own shares and cannot recreate a deleted one.

## Related privacy rules

- **Discovery copies.** [Guided selection](guidance.md) samples, projections and recommendation drafts are managed copies under the ordinary baseline; a preview's lifetime is not a retention anchor.
- **Capture history.** Settings snapshots ([REQ-HIS-003](capture-history.md)) are SQL rows with their own `expires_at`; content-bearing snapshots carry the evidence deadline.
- **Syscall traces and profiles.** `syscallTrace` follows all evidence rules; arguments default to potential personal data. CaptureProfile definitions are configuration and never hold evidence samples or credentials ([capture profiles](capture-profiles.md)).
- **Live views.** [REQ-LIV-005](live-watch.md#req-liv-005--privacy-transient-data-and-saving) applies audience, region, minimization and inherited deadlines to transient rows; payloads never enter SQL, logs, URLs, browser storage or backups.
- **Downloads.** Native downloads ([REQ-DLD-004](artifact-downloads.md)) are recorded disclosures; local copies cannot be deleted by Asservat.
