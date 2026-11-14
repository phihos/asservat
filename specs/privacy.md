# Privacy and administrator retention limits

Read with [evidence lifecycle](evidence.md), [authorization](authorization.md) and the [privacy research](../docs/research/privacy-retention.md). These are product controls; an operator's processing arrangements must be assessed before making compliance claims. Retention is stored as deadlines on each artifact and shortened by events ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D12).

## REQ-PRV-001 — Purpose, classification and collection minimization

Use "user data" for data concerning or supplied by users of the observed application, including internal tools. This product term is distinct from the legal classification "personal data"; privacy controls also apply to other sensitive application data.

The installation administrator owns the diagnostic purpose, permitted workload scope, storage/analysis locality, client disclosure policy and finite retention policy. The chart ships usable defaults for each (a generic incident-investigation purpose, every namespace outside the excluded system namespaces, hub-region locality, a disclosure policy admitting the console for every data class and the bundled MCP client for metadata and extracts, and the baseline below), so a default installation collects; the administrator adjusts them before relying on them for production data. Ordinary captures reuse these settings; maintainers supply incident context rather than a legal-basis decision per request. CRDs hold purpose and policy references, not legal documents or user details. An authorized operator documents legal basis, special-category conditions, transparency, processor arrangements and DPIA outside the evidence.

Privacy classification is independent of the `raw`, `extract` and `metadata` access classes: `unknown`, `potentialPersonalData`, `personalData`, `specialCategoryPossible` and `verifiedNonPersonal`. Unknown evidence receives at least potential-personal-data restrictions. Core/heap dumps, logs, arbitrary files, command output, profiles and network captures default to potential personal data; approved workload metadata may raise them. Profile labels, paths, IP addresses and audit identities can identify people. Encryption, redaction, payload stripping and hashing alone do not establish anonymity.

Collectors derive the evidence type from the actual acquisition: `coreDump`, `heapDump`, `packetCapture`, `syscallTrace`, `logs`, `files`, `profile`, `commandOutput`, `context` or `other`. A heap delivered through a custom collector remains a heap when known; an arbitrary binary file or command output without a qualified producer classification uses conservative `other` rules. A maintainer cannot downgrade classification or relabel a core as metadata. Only a reviewed, versioned transform with an administrator-approved field model may produce `verifiedNonPersonal`; a scanner finding no matches is insufficient. Derived artifacts inherit parent deadlines.

Default presets collect bounded diagnostic context. Full environment, arbitrary annotations, local-variable values, packet payload, broad recursive files, all-node capture and high-frequency continuous profiling are not default evidence. Redact or project before durable retention where feasible; complete removal of user data from binary dumps is never promised. Operators can forbid classes or actions for selected workloads through collection ceilings.

[Capture assessment](capture-assessment.md) presents possible content before collection, including transient inspection versus retained fields and the actual mechanism. Notices are mechanism-derived warnings, not scans proving absence, consent or certification.

### SC-PRV-001

Given a core with synthetic user records and a profile with a user-bearing sample label, when collected or transformed, then both receive privacy controls regardless of file extension or extract class. A user-supplied nonpersonal label and a clean pattern scan cannot weaken those controls.

## REQ-PRV-002 — Canonical administrator policy and precedence

`EvidenceRetentionPolicy` is a namespaced CRD in the hub control namespace; local administrators may add policies in the connector namespace of their cluster, which the connector pushes to the hub when they change. Kubernetes is its configuration interface, and both namespaces are administrator-only ([ADR-328](../docs/decisions/328-administrator-only-namespaces.md)). The CRD schema and CEL validation check values; status reports `observedGeneration`, the effective policy digest, backend compatibility, which clusters have applied it and bounded blockers.

One installation-wide baseline sets finite maxima for evidence, case metadata and audit metadata. Additional policies select enrolled clusters, namespaces and workloads by selectors. All matching policies apply and the shortest maximum wins. Local policies only tighten. Rules can further shorten evidence retention by privacy class and evidence type. There is no priority override or user-selected retention profile. Unknown classification matches potential-personal-data rules; a stricter known class also matches less specific personal-data rules. Without an observed baseline no collection starts. The hub watches policies with an informer; the cached set stays valid until replaced (ADR-330 D1).

The baseline supplies defaults; narrower policies may lower them. The chart's baseline defaults to evidence 14 days (including cores and heap dumps), content-minimized case metadata 30 days and audit metadata 90 days, with the same maxima; these are product choices, not legally approved periods. The administrator changes them on `helm upgrade` or by editing the baseline. The [example](../examples/retention-policy.yaml) shows a baseline with a shorter rule for cores. Maintainers can request shorter retention; longer requests are clamped and displayed. Shares last until the evidence's access end; no separate share cap applies ([ADR-335](../docs/decisions/335-usable-by-default.md) D7).

Within a policy scope, selector dimensions are ANDed; cluster IDs and rule lists are ORed within their dimension. Omitted scope fields match all; an empty scope is the baseline only in the hub. A rule's present privacy/type dimensions are ANDed; omitted dimensions match all. Privacy matching expands unknown to potential-personal-data, personal to personal/potential and special-category-possible to special/personal/potential. `other` evidence matches every type-specific cap in scope. At most 64 applicable policies per plan; overflow fails planning with a consolidation diagnostic.

Several defaults resolve to the shortest. The largest required deletion budget is used inside the shortest maximum; an intersection with no positive usable time is refused. Applied policies must agree on the purpose reference. Explicit-recipe and composed captures accept the same shorter `retention` request as presets.

Collection resolves the policies and stores the resulting deadlines on the artifact (REQ-PRV-003). When a policy add or update event arrives, the hub applies it to existing evidence with one set-based SQL update per affected set: `expires_at = LEAST(expires_at, …)` and the same for `delete_by`, over artifacts whose recorded cluster, namespace and workload match the policy (label selectors match the current labels of the recorded namespace or workload; an artifact whose namespace or workload no longer exists matches only policies without label selectors). Each update writes one audit row. Shortening is monotonic, so a late event converges. A longer maximum or default applies only to new collections; it never extends a stored deadline or resurrects evidence. Deleting a policy never extends deadlines; deleting the only baseline suspends new collection. A policy added and deleted entirely while the watch was disconnected may be missed; this follows Kubernetes level-triggered semantics. An increased deletion budget fits inside the stored hard deadline; when no readable time remains, access closes and cleanup is due at once. Applying a shortening through Kubernetes is the authorization to enforce it; no second confirmation is needed.

### SC-PRV-002

Given a global 24-hour limit and a local 6-hour core rule, when a maintainer requests 7 days or moves a core into a shared case, then its limit stays 6 hours. Tightening to 2 hours makes existing older cores due for immediate expiry and deletion. Raising to 48 hours does not revive or extend earlier artifacts.

`preview_retention_change` (browser only, [ADR-240](../docs/decisions/240-retention-impact-preview.md)) is for administrators, checked before any proposal is decoded. Input is 1–16 EvidenceRetentionPolicy create (spec), update (UID and spec) or delete (UID) changes for the hub namespace or, with `source_cluster_id`, one cluster's local policies; specs pass the CRD checks. The service applies the changes to the current policy set and to the stored deadlines of at most 10,000 retained artifacts not yet due, exactly as the event update would. It reports affected counts per cluster, privacy class and evidence type, how many would become unreadable or due at once, and the earliest new access end and deletion. A longer maximum and a deleted policy change nothing. A cluster whose local policies have not reached the hub is listed as incomplete; an update or delete of an unknown UID is not evaluated; a truncated scan says so. The reply warns when the hub would no longer have exactly one baseline. It writes nothing.

### SC-PRV-009

Given retained artifacts under a 24-hour baseline and an administrator, when they preview lowering the baseline to ten minutes, then every artifact is affected and the earliest new deletion is the earliest anchor plus ten minutes, with access ending five minutes earlier; a limit already passed counts the artifacts as unreadable and due now. Previewing 48 hours, or deleting a policy, affects none. A cluster whose local policies have not reached the hub is listed as incomplete. The scan stops at 10,000 artifacts and says so. A caller who is not an administrator receives `AdministratorRequired` before any proposal is decoded; MCP does not offer the operation; nothing is written.

## REQ-PRV-003 — Age, access cutoff and deletion deadline

Age starts at the first acquisition into Asservat, not upload completion, case creation or last access, and includes the oldest retained pre-trigger ring segment. Imported runtime files use an earlier trustworthy source-creation time when available; record `acquisition` versus `sourceCreation` basis. A derived artifact uses the earliest parent anchor. Clock uncertainty resolves toward earlier expiry; an unsafe clock prevents fresh sensitive collection or disclosure.

Each artifact row stores:

```text
hardDeleteBy = min(anchor + every applicable maximum, parent deleteBy values)
expiresAt = min(anchor + requested/default age,
                hardDeleteBy - deletionBudget, parent expiresAt values)
deleteBy = min(hardDeleteBy, expiresAt + deletionBudget)
```

`expiresAt` is the access cutoff and start of deletion; `deleteBy` is the latest storage deadline. The configurable deletion budget (proposed 5 minutes) sits inside the maximum. Policy values that leave no positive usable time are refused. A 6-hour maximum with a 5-minute budget allows access for at most 5 hours 55 minutes. Both timestamps and the constraining rule are shown.

Reads, shares, cursors, analysis staging, query results, caches and uploads respect these deadlines. Expiry is part of each operation's authorization and of the effect statement; analysis ends at the cutoff. An upload is never committed after `expiresAt`. Each recurrence gets new deadlines and never renews old artifacts. Mixed-source results use the earliest parent deadlines. Case titles, snippets, indexes, manifests and stored query text or results containing evidence-derived personal data inherit the deadline; a content-minimized case shell may follow the case-metadata policy. Audit has its own finite retention and never embeds evidence content.

The encrypted manifest records privacy class, evidence type, purpose reference, classification source, anchor and basis, requested age, resolved maximum, deletion budget, `deleteBy` and every applied policy UID, generation and digest. Later shortenings update the stored deadlines and write audit rows; immutable manifest provenance is never rewritten. Ordinary policy changes only shorten. The preservation decisions in REQ-PRV-005 are the only exception: a hold may extend a shorter requested expiry within its hard cap, and a legal exception replaces only the restricted-preservation storage deadline; neither restores ordinary access. Temporary copies register the same deadlines before data is written.

Relative access and deletion ages are shown before acquisition and actual timestamps afterwards. Views, sharing and MCP use the same handling notice and deletion state; automatic deletion covers managed copies, not already disclosed external copies. Deletion is never shown as verified only because a timestamp passed.

### SC-PRV-003

Given a core acquired at 12:00 with a 6-hour cap and 5-minute deletion budget, when upload completes at 12:20 and an extract is produced at 17:50, then neither can be read at 17:55 and both are due for deletion by 18:00. Sharing, recurrence, copying or analysis cannot restart the clock. A pre-trigger ring starts its deadline at its oldest included acquisition.

## REQ-PRV-004 — Delete every managed copy and report failures

Each artifact's object-store data lives under its own prefix. SQL holds content-minimized copy references and lineage for artifacts, derived extracts, query output, index/cache material, staging volumes and node spools. Collectors, connectors and analysis workers enforce each copy's stored `expiresAt` locally, also while the hub is unreachable.

The retention worker deletes from the stored deadlines: after `expiresAt` it deletes every object and version under the artifact's prefix and every registered copy, removes wrapped object keys and manifests, and runs a second sweep at `deleteBy` to catch late writers. Bucket lifecycle rules `AbortIncompleteMultipartUpload` and `NoncurrentVersionExpiration` remove abandoned parts and old versions ([S3 lifecycle](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html)). A delete marker alone is not deletion. States: `Accessible`, `ExpiredDeletionPending`, `DeletedVerified` and `DeletionOverdue`, with last attempt, storage class, next retry and opaque copy references. `DeletedVerified` means the second sweep found no object or version under the prefix and every registered copy reported removal; it is not proof of physical sanitization or third-party erasure. Offline node acknowledgements and inaccessible replicas block it. A minimal tombstone without filenames or user identifiers is kept for restore suppression until the backup horizon passes.

Failures are retried with bounded backoff; an overrun of `deleteBy` alerts and reports the oldest overdue age. An overrun is a policy breach, never an extension. By default new collection pauses for the affected allocation while deletion is overdue; a backend-wide pause applies only when the failure affects the backend. Unaffected allocations stay usable under [capacity isolation](capacity.md). A storage outage, offline machine or immutable object can make deletion late; the product reports it and never certifies absolute physical deletion. Access stays denied throughout. Shared Transit-key deletion is never described as selective cryptographic erasure. Cleanup pages advance past failed items and revisit them; a permanently failing item never hides later due work.

Raw evidence, derived evidence and plaintext scratch are excluded from general-purpose backups by default. A qualified backup or replication profile honors each artifact's deadline across all copies; a snapshot lifetime that keeps evidence past its cap is incompatible. Control-state backups omit evidence, have finite documented retention and restore behind an authorization gate. Before serving restored data, apply current ceilings, expired grants and shares, stored deadlines and tombstones; unknown state fails closed. Image and symbol caches may have a separate policy only when they contain no captured user data.

### SC-PRV-004

Given an expired object with a noncurrent version, a derived result and an offline node spool, when deletion runs, then deleting the current object does not report completion. Access is denied, pending copies stay visible to operators and a `deleteBy` overrun alerts. An object written by a late writer after the first sweep is removed by the second. Restoring an old catalog cannot disclose or recreate expired evidence.

## REQ-PRV-005 — Preservation and immutable-storage conflicts

An ordinary debugging hold may extend a shorter requested lifetime only up to the applicable administrator maximum and never grants readership. It requires explicit retention authority, scope, reason, finite expiry and audit. It cannot bypass erasure or restriction decisions or renew expired evidence. Holds are service-managed decisions on existing evidence, not permission to create another copy.

Default `legalExceptions: disabled`: even a hold labelled legal cannot exceed the maximum. The optional `reviewed` mode is pending the maintainer's legal-hold preference. If enabled, a legal retention decision identifies exact artifacts, a protected legal-case reference, a compliance reviewer distinct from the requester, a finite replacement deadline, a review date and justification. All matching policy authorities must permit it. Original and exceptional deadlines are recorded and shown in the compliance inventory. It authorizes restricted preservation, not ordinary debugging or MCP access beyond the original expiry. No automatic renewal or blanket namespace exception exists. A legal-reference string alone never validates a legal basis.

Evidence retention is separate from audit integrity policy. Blanket Object Lock or legal hold is not enabled on the evidence bucket by default. Preflight checks bucket defaults, object lock modes, replica locks and backup retention before accepting a storage profile. A storage minimum longer than the permitted maximum is `RetentionConflict` and blocks affected collection. A compliance-mode lock can make shortening impossible: access is denied, the conflict reported and escalated, and deletion never claimed. Storage-enforced preservation is advertised only for qualified backend modes.

### SC-PRV-005

Given a 6-hour maximum and an ordinary hold for 3 days, when requested, then storage cannot extend beyond 6 hours. A 30-day compliance-mode bucket fails preflight. If a conflicting locked object exists, shortening the policy revokes ordinary access and reports the storage conflict without a deletion claim.

## REQ-PRV-006 — Rights requests and restricted processing

A privacy operator is an administrator or a holder of the `privacy-operator` role granted by a hub-cluster ClusterAccessBinding ([REQ-PER-001](permissions.md#req-per-001--canonical-permission-configuration)); no separate operator list exists. The privacy-operator workflow locates candidate evidence by workload, time, purpose and controlled incident references; inspects lineage; restricts processing; requests early deletion; and tracks completion and exceptions. There is no permanent global user-content index. Optional application-supplied opaque subject references are encrypted, access-controlled and share the evidence deadline; they are hints, not proof that untagged cores contain no subject data.

Restriction prevents ordinary analysis, disclosure, sharing and reuse while a preservation or rights workflow resolves the request. Early erasure propagates to all derivatives and copies through the same deletion worker. Access and correction workflows prepare bounded, reviewed personal-data extracts for the controller's response channel, protect other people's data and record decisions; they never expose a raw core or add a public download endpoint. Immutable evidence is not silently edited; disputed facts are annotated or a corrected derived view is generated with provenance.

Restriction state is durable SQL state ([ADR-127](../docs/decisions/127-current-processing-and-download-placement.md)): rules over immutable artifact or workload-time scopes, each change and release a revisioned row with its audit row. A newly published matching capture or a replacement artifact ID cannot establish unrestricted processing. Unsupported derivatives and unknown restored state deny.

Automated discovery cannot prove complete coverage in arbitrary cores; uncertainty is reported and a broader deletion or restriction by workload and time is allowed. The content-minimized processing inventory covers purposes, locations, categories, retention, sharing recipients, configured processors, deletion backlog and exceptions. The product does not claim to fulfil every data-subject request or decide legal exceptions.

### SC-PRV-006

Given a validated erasure request covering an incident, when a privacy operator deletes its candidate artifacts, then derived summaries, versions and query caches enter the same deletion plan. A legally preserved item is separately restricted and explained; a missing user tag is not reported as proof of absence.

### SC-PRV-010

Given a privacy operator, when they restrict a published artifact from its case, reload the restriction inventory and release the exact current revision, then new ordinary case reads and native-response starts are refused while restricted and recover for the same artifact after release. Inventory is operator-only. Replaying a change with its idempotency key adds no second audit row. A revision conflict requires refreshed state and another explicit decision. Started responses keep their original bounds (ADR-312). The console never treats a missing browser state as release.

### SC-PRV-011

Given a retained published artifact under restriction, a privacy operator can find it by its case ID or by workload identity and a half-open acquisition interval, optionally filtered by exact purpose. Results show effective deadlines and the direct parent IDs recorded at publication; empty filtered pages can carry a continuation. An ordinary evidence reader cannot search, and the audit row commits before metadata is returned. Findings do not establish that any user appears in the evidence or that all derivatives are known. The operator can select a result for restriction.

### SC-PRV-014

Given a privacy operator, the console exports the retained processing inventory as bounded audited JSON pages: artifacts including retained deleted attempts, share recipients, native sessions, operation responses, processing rules, technical paths and processor organizations declared in configuration. Every page states its observation time, revision, selection ceiling and coverage. Missing processor declarations and an explicit empty list are distinct; technical regions do not imply processor identities. The console downloads finite parts and offers continuation; completion requires exhausting every section; a principal change or cancellation clears unfinished output. An ordinary reader cannot export. Exported local copies are outside managed deletion.

### SC-PRV-013

Given a privacy operator who searched by exact workload and a half-open UTC acquisition interval, the console can review and confirm one restriction for that entire scope. The review states that every purpose and result page is covered, including matching evidence published later. The purpose filter narrows discovery only. An empty page does not prevent reviewing the scope. Edited search fields invalidate the selection; cancellation submits nothing. The change uses one idempotency key; matching reads and response starts are refused; another workload and an anchor at the exclusive end stay outside. Reloading preserves scope and revision for release; a same-key retry adds no audit row. Release restores access under the original deadlines.

### SC-PRV-012

Given a retained published artifact, a privacy operator selects it in the Processing console and confirms an exact early-erasure request ([ADR-321](../docs/decisions/321-exact-early-erasure.md)). The request and its audit row name the artifact; the same idempotency key replays the original decision. Ordinary access closes and the artifact becomes due for deletion before its previous expiry, keeping its hard deletion deadline. The operator can reload the request's pending, overdue or verified deletion state. An acknowledgement or elapsed deadline does not establish physical deletion; the deletion worker verifies all managed copies.

## REQ-PRV-007 — External agents, transfers and operational privacy

Locality policy applies to raw storage, decryption, derived results, hub indexes, backups, support bundles and configured event destinations. The hub region and remote client disclosures are part of the data-flow inventory; local raw storage alone does not keep all personal data in a region. The administrator approves clients and data classes for external AI disclosure and supplies the organizational handling policy. Client allowlisting constrains recipients but cannot enforce their model provider, geography, logging or retention.

Bounded extracts and least disclosure are the default. Prompts and tool results are not logged; no product telemetry is sent. Asservat expiries govern managed copies; delivered results cannot be recalled. The recipient client and disclosure time are recorded without raw output. Operators arrange downstream handling and transfer safeguards.

Breach response uses an auditable incident timeline, involved evidence classes and recipients, containment and deletion state. A capture trigger is not automatically a personal-data breach. The operator assesses notification duties; the product sends no automatic notification.

### SC-PRV-007

Given an approved agent receives a bounded extract, when the original expires, then Asservat denies further access and deletes managed copies while reporting the prior disclosure. It never claims deletion from that agent's history. A raw-locality profile that sends personal extracts to another region shows that flow in the inventory and policy preview.

## PostgreSQL, protocol evidence and retained copies

PostgreSQL base backups, WAL, replicas and restored databases are managed control-data copies. Evidence bytes, full manifests and extracted text stay out of SQL. Minimal identities and relationships have finite metadata and backup retention; row deletion is not backup erasure, and REQ-DB-005 gates restores. Regional text indexes and HTTP header projections are user-data evidence with inherited deadlines. Live rings, parser buffers, frozen segments and encrypted disk spools carry their own stored expiry. Network headers or an HTTP allowlist never establish anonymity. Team management and sharing never extend an artifact's cutoff or grant an external client permission beyond its policy.

Share rows are deleted after their expiry plus the case-metadata retention period. A known-principals row (REQ-AUT-001: username, display name, groups seen) is deleted when its principal has not signed in for the audit-metadata period; it holds no evidence. Revocation, transfer and repeated publication never extend that. Deleting the row does not claim erasure from backups, which expire with the documented backup retention (REQ-PRV-008).

## REQ-PRV-008 — Backup horizons and expiring index segments

The installation documents its control-data backup and WAL retention H. A row deleted at its deadline survives in backups for up to H more; those backups are beyond use and are never read except through the restore gate ([ICO right to erasure](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/)). A restore applies tombstones, stored deadlines and lifecycle decisions before serving anything (REQ-PRV-004). Status and the processing inventory show H next to each control-data retention period. Evidence bytes are never in control-data backups.

Regional evidence-text indexes delete at the storage-copy level. The initial implementation uses bounded memory indexes on qualified no-swap/no-core nodes, torn down and rebuilt by the earliest indexed deadline; evidence text is never backed up. An optional durable index partitions by finite expiry cohorts (default at most five minutes), encrypts each independently and deletes the entire cohort, snapshots and obsolete segments by the earliest member deadline; query filtering or a per-document delete alone is insufficient. Shortening or early erasure destroys affected cohorts and rebuilds only eligible records. Shard and file counts and rebuild work are capped; `IndexRebuilding` is reported while SQL catalog discovery stays available.

### SC-PRV-008

Given 90-day metadata and a documented seven-day backup horizon, when a row reaches its deadline, then it is deleted on day 90, status shows the seven-day horizon, and a restore of a day-89 backup does not serve the row. Given an index segment containing a six-hour core extract, expiry or early deletion removes the managed segment copies, not only its search hit.

### SC-PRV-015

Given a manual or capture-time share, when it expires and the case-metadata retention passes, then the share row is deleted. Replay, revocation and transfer do not move that time. A recurring revoke-all affects only its own shares and cannot recreate a deleted one.

## Discovery and recommendation copies

[Guided selection](guidance.md) acquisition recipes have a 15-minute requested lifetime with ordinary classification, approved projection, deletion budget and retention clamping. Samples, process/flow projections, analysis scratch, cached pages and evidence-bearing recommendation drafts are managed copies. Paths, IPs, packet-derived text and user goals never enter unbounded SQL or audit fields. A preview's or recommendation's lifetime is not a retention anchor. Saving a selector as configuration is explicit and keeps no sampled traffic or process list.

## Capture settings retained for reuse

REQ-HIS-003 in [capture history](capture-history.md) governs history summaries and parameter snapshots independently of artifact retention. A seven-day summary default does not authorize keeping evidence-derived settings, user identifiers or arguments for seven days. Snapshots are SQL rows with their own `expires_at`; content-bearing snapshots carry the applicable shorter deadline, and backup copies follow REQ-PRV-008; only approved pure configuration follows the metadata policy. Repeating neither renews source content nor revives expired evidence. UI and MCP report summary availability separately from repeatable-settings availability.

## Reusable configuration and syscall traces

`syscallTrace` is an evidence type subject to all maxima, acquisition-time deadlines, derivatives and managed-copy deletion. Metadata and arguments default to potentially personal; argument or buffer variants never gain longer retention by reclassification. Approved metadata projections exclude arguments, paths, pointers and buffers.

CaptureProfile definitions are configuration, not an exemption: credentials or discovery samples are never laundered into Kubernetes specs, catalog descriptions or SQL indexes. Parameter edits, composition previews and history snapshots keep evidence-derived lineage and deadlines. Saving a reusable profile requires the configuration privacy checks in [capture profiles](capture-profiles.md); profile versioning does not reset source retention.

## Transient live-view privacy

Live viewing is processing of potential user data even without a saved artifact. [REQ-LIV-005](live-watch.md#req-liv-005--privacy-transient-data-and-saving) applies source audience and authority, region, field minimization and inherited deadlines before emission. No generic raw live content is supported in the first release. Each row expires at the earlier of its privacy deadline and the watch deadline, never later than source, content or view authority; server replay is at most 1 MiB per watch (REQ-LIV-003). Access loss reaches the browser as a terminal `AccessRevoked` item on the open event stream or the current `read_live_watch` wait, also for paused views; rows are cleared on it, on logout, closure and expiry. Disconnected browsers rely on local row deadlines. Payloads never enter SQL, logs, URL parameters, browser storage or backups. Live scope, display filter and save reasons are minimized SQL control rows deleted at their control-data deadline ([ADR-310](../docs/decisions/310-finite-approved-live-observation.md)); rows themselves stay in the serving process's memory. Delivered text may be copied by external agents; notices never promise recall.

Authorized native downloads are supported for all evidence under [REQ-DLD-004](artifact-downloads.md). They do not reset managed retention or create a remotely erasable local copy. The disclosure is recorded, new or resumed transfers are refused after revocation or expiry, and external-copy handling is labelled. This investigation feature is distinct from privacy-rights responses.
