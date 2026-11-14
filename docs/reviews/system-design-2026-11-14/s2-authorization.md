# S2 spec audit: authorization, permissions, policy automation, investigation approval, privacy

Scope: `specs/authorization.md`, `specs/permissions.md`, `specs/policy-automation.md`,
`specs/investigation-approval.md`, `specs/privacy.md` in `/home/phil/Projekte/asservat-specreview`
(main at f9ccd35b). Read-only audit. Line numbers refer to that worktree.

Maintainer capabilities that must survive (AGENTS.md "Authority and invariants" and the
dated maintainer decisions): one organization; Kubernetes-only permission configuration;
automated permission management with configurable inheritance including pod exec rights;
expiring policy grants for automatic intrusive actions with administrator-configured
finite approval periods; sharing within the organization (capture-time and explicitly
bounded recurring-policy sharing); multiple owner teams with immutable creators;
administrator-enforced maximum evidence retention; protection against capture storms and
cross-workload storage exhaustion; one independent approval covering a manual capture
plus the same human's result inspection/download; native downloads; ADR-311 (one
authorization per operation, 30 s / 60 s reuse); ADR-312 (started downloads run to their
original bounds); ADR-328 (Asservat namespaces administrator-only, no self-verification);
ADR-329 (AccessBindings in application namespaces); Helm-native installation.

Severity counts: **high 10, medium 8, low 4** (22 findings).

---

## High

### H1. AccessBinding storage and delegation envelope contradict ADR-329

- **Where:** permissions.md:9, 13, 26 (SC-PER-001), 30, 46 (ADR-237 previewer envelope), 59 (SC-PER-010), 130; policy-automation.md:7, 25-31 (DebugPolicy "in the hub control namespace (like AccessBindings)"); authorization.md:23.
- **Current design:** AccessBindings and PermissionSources live in the protected hub control namespace and name a cluster plus a namespace UID. A permission admission guard enforces each writer's "configured cluster/namespace delegation envelope". `preview_access_change` gives delegation "previewers" an envelope-restricted view.
- **Problem class:** obsolete text that contradicts a maintainer decision; a bespoke delegation layer where Kubernetes namespace RBAC already does the job.
- **Cost:** Every binding write goes through a custom admission guard plus envelope evaluation. Hub-namespace write access must be handed out to provisioning identities, which contradicts ADR-328's admin-only namespaces. The envelope rules for previews add a second authorization model (permissions.md:46).
- **Maintainer or agent:** ADR-329 (maintainer, 2026-11-13) moves bindings to application namespaces under ordinary RBAC and removes the envelope and the guard. The envelope was agent-added (ADR-189/237).
- **Replacement:** Make AccessBinding a namespaced CRD in the application namespace it grants, scoped to its own namespace, with no cluster or namespace-UID fields. Each region's connector observes it with an informer and delivers it over the existing permission observation. PermissionSources stay administrator-managed in the Asservat namespace. For the open escalation question in ADR-329, there is external precedent for a standard mechanism: a Helm-rendered ValidatingAdmissionPolicy that uses the CEL `authorizer` to require the writer to hold a synthetic `bind` verb on `accessroles.asservat.io/<role>`. This is the same pattern as Kubernetes RBAC's `bind`/`escalate` checks ([RBAC privilege-escalation prevention](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping)), the CSR `approve` verb on `signers` ([CSR authorization](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#authorization)) and cert-manager's approver check ([cert-manager approval](https://cert-manager.io/docs/usage/certificaterequest/#approval)). The policy is only added if that evidence is accepted. It uses a [VAP authorizer check](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/), not a runtime proof. Decide `spec.automation` the same way: either keep it as an administrator-only PermissionSource-like object in the Asservat namespace (recommended, because automation creates a machine principal), or gate it with a `bind` check on `accessroles/automation`. Replace the ADR-237 previewer envelope with "a caller may preview changes in namespaces where a SubjectAccessReview says they can `create accessbindings`".
- **Must change together:** targets.md, interfaces.md / OpenAPI (`preview_access_change`), contracts/*AccessBinding* schema, examples/access-binding-*.yaml, docs/architecture/permission-observation.md and permission-acceptance.md, mcp.md (`explain_access` wording), charts CRDs.

### H2. Guard live-proof and dry-run probe text survives ADR-328

- **Where:** permissions.md:70-72 (`admissionEnforced`: "Guard configuration and parameters must themselves be protected", "A guarded key is authoritative only after its existing values have been reviewed or reasserted"), 80 ("live proof — pinned policy and binding unchanged and an unprivileged probe's dry-run namespace update denied by exactly this guard, within its original five-second interval"), 82-89 (ADR-324 probe isolation), 134 (workload guard probe account, empty probe namespace with a ResourceQuota); privacy.md:3 ("Installing current write protection does not authenticate pre-existing policy values"), 7 ("exact immutable configuration/content pins").
- **Current design:** Permission sources grant only while a five-second dry-run probe proves that the admission policy denies writes. Existing values need "review" before a guard counts, and retention topology needs immutable content pins.
- **Problem class:** self-verification of installer state; requirements that defend against trusted actors; expiry-driven proof.
- **Cost:** Probe accounts, probe namespaces and ResourceQuotas exist per cluster. Every source sees a recurring dry-run API write every ≤5 s. Each proof failure adds another unavailable state ("kept, granting nothing"). Proof scheduling has to be coordinated across guards (ADR-324).
- **Maintainer or agent:** ADR-328 (maintainer): "no admission policies pinned to object UIDs, no dry-run denial or access-review probes … Helm-installed admission policies protect those labels (ADR-247), with no runtime proof". The probe design is agent-added.
- **Replacement:** Helm renders the namespace and workload label ValidatingAdmissionPolicies. A PermissionSource with `admissionEnforced` grants while it exists, and the policy's presence is the operator's responsibility, as with any VAP-dependent controller (for example Kyverno and Gatekeeper users). Drop probe accounts and namespaces, proofs, "historical value review", the ADR-324 isolation paragraph and the topology content pins. `administratorManaged` is just the PermissionSource itself: an administrator wrote it.
- **Must change together:** targets.md, capacity.md (the "capacity selector guard" reuse), retention-topology/observation architecture docs, deployment-profiles.md, charts.

### H3. Assignment-ID continuity (A → B → A) machinery for evidence audiences

- **Where:** permissions.md:5, 76 ("Every watch transition that changes the derived grants is accepted before the next; a new LIST never claims continuity"), 146, 176-184 (REQ-PER-008), 188, 192; authorization.md:119, 239 (shares Suspended when a pinned assignment is replaced; "a re-granted binding is a new assignment"); policy-automation.md:17, 50.
- **Current design:** Every permission grant is an immutable assignment ID. Evidence manifests pin assignment IDs. A relist cannot prove there was no A → B → A ownership round trip, so uncertain assignments are invalidated and re-minted. Each derived-grant transition is accepted serially through audited SQL, with encrypted object audit for each transition. Shares and policies pin assignment IDs and suspend when they are replaced.
- **Problem class:** journals/ledgers for one fact; serialization (one accepted transition at a time); per-transition encrypted audit; edge-triggered history where Kubernetes controllers are level-triggered.
- **Cost:** Every namespace or workload metadata change and every relist can churn assignments. A relist after a connector restart re-mints IDs and suspends shares and policies across a whole cluster, which is an availability hit that grows with namespace count. An operator re-applying an unchanged binding (delete/create in GitOps) silently suspends shares and breaks policy sponsorship.
- **Maintainer or agent:** The maintainer requires that a new owner team must not silently see old evidence (implied by "artifact shares remain concrete snapshots" and the inheritance requirement). The assignment-ID/continuity mechanism is agent-added (ADR-050/242).
- **Replacement:** Record the audience at collection as stable issuer-scoped group IDs with roles (`(issuer, groupID, role)`), plus the namespace and workload UID. A read is allowed when the caller currently holds that role through any current allow for that workload and the group is in the recorded audience. A new team B never appears in old audiences, so it gets no access. If ownership round-trips back to A, A sees its own old evidence again, which is harmless. Level-triggered evaluation from the informer cache needs no continuity proofs, serial acceptance or re-minting. Kubernetes controllers are explicitly level-based ([controller pattern](https://kubernetes.io/docs/concepts/architecture/controller/), [sig-api-machinery controllers guide](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-api-machinery/controllers.md)). Grafana and GitLab team permissions evaluate current team membership against resource ownership, not historical grant IDs. Shares and policy sponsorship pin group IDs, not assignment IDs, and suspend only when no current allow for that group exists.
- **Must change together:** evidence.md / artifact-format (accessProvenance), execution.md (collection-scope `policyAuthority`), persistence.md (assignment tables), live-watch.md (retained source audience), artifact-downloads.md, contracts schemas, docs/architecture/permission-acceptance.md.

### H4. Five-second deny and "issuance fact" windows contradict ADR-311

- **Where:** permissions.md:144 ("deny cache at most 5 seconds", "original five-second preflight bounds", "original current at-most-five-second issuance facts"), 148 ("The complete deny set has an independent observation deadline even when empty"); policy-automation.md:52, 54 ("complete deny-state maximum of five seconds"), 92 (settings observations expire within five seconds), 148; authorization.md:75 ("original current five-second proofs"); permissions.md:80 (proof "within its original five-second interval").
- **Current design:** Deny state, source facts, settings and proofs each carry their own ≤5 s observation deadline. Positive decisions last 30/60 s and are "invalidated" by connected changes. These windows stack across helpers.
- **Problem class:** expiry-driven freshness forcing re-reads; stacked windows.
- **Cost:** Every 5 s per cluster or source the system re-reads or proves deny state. When a refresh is late (a GC pause or a slow API), requests fail closed even though nothing changed. This multiplies with source count and is the class of availability failure recorded earlier for retention followers.
- **Maintainer or agent:** ADR-311 (maintainer): "authority is checked once per operation and reused for at most 30 s … Do not reintroduce stacked five-second authority windows." The 5 s deny rule is agent-added.
- **Replacement:** Use one informer-backed cache of bindings, denies and sources, valid until the next watch event replaces it (no TTL), as kube-apiserver's own RBAC authorizer does with shared informers. Mark it unavailable only while the watch is disconnected beyond resync. Each operation takes one snapshot and reuses it for ≤30 s (ADR-311). Delete every "five-second" clause and the "independent deny deadline".
- **Must change together:** identity-eligibility architecture doc, execution.md, capacity.md, live-watch.md, mcp.md:89-92 (per-poll five-second reconstruction), artifact-downloads.md.

### H5. Polling where event sources exist (metadata journals, policy scheduling, policy-source observation)

- **Where:** permissions.md:80 ("the hub rereads it every 10 seconds"), 134 ("the hub-worker reads it every 10 seconds"); policy-automation.md:41 ("polling stops at the next cycle"), 52 ("Reuse the existing 15-second policy scheduling loop … to maintain all authorized replicas"), 124-127 ("Healthy source observations last 30s with 15s trigger polls").
- **Current design:** Each connector keeps a LIST+watch "journal" with synthetic value-change versions, and the hub pulls it every 10 s. Policy sources are re-observed on 30 s lifetimes. A 15 s loop renews every authorized replica's ongoing lease.
- **Problem class:** polling and periodic full resends where watches and pushes over existing connections exist; journals.
- **Cost:** Work is O(clusters × key sets) every 10 s, plus O(policies × replicas) SQL lease renewals every 15 s, even when nothing changes. Up to 10-15 s of latency is added to permission and policy changes. Deactivation takes effect only "at the next cycle".
- **Maintainer or agent:** The standing rule (event-driven, PR #237) is a maintainer rule. The intervals are agent-added.
- **Replacement:** The connector runs informers and pushes deltas (namespace or workload key values, AccessBindings under H1) over its existing hub connection. The hub applies each delta when it arrives and requests a full resync only after reconnect or a digest mismatch. This is the pattern of OCM work-agent status feedback ([ManifestWork](https://open-cluster-management.io/docs/concepts/work-distribution/manifestwork/)), Karmada's push-mode agent and Argo CD's watch-based cluster cache ([Argo CD HA](https://argo-cd.readthedocs.io/en/stable/operator-manual/high_availability/)). Policy-source changes come from an informer on DebugPolicy, and activation or deactivation signals in-process (or via NOTIFY) to the scheduler. Ongoing leases: see H6.
- **Must change together:** capacity.md, execution.md / action-lifecycle.md (trigger evaluation), persistence.md:71 ("polling recovers missed notifications": use resync on reconnect instead), docs/architecture/configuration-reconciliation.md.

### H6. Ongoing and finite policy-observation leases renewed with fresh facts; signed local permits

- **Where:** authorization.md:69 ("Local prepaid permits use bounded Kubernetes compare-and-swap"), 75 (ADR-261/263 leases, "<=60 seconds" permits), 77, 81 (SC-AUT-004), 265-278; permissions.md:144, 152-156 (SC-PER-006: "a quiet renewal needs new current facts and locked source/current-authority reads"); policy-automation.md:50-56 ("signed local permits remain necessary"), 146-151.
- **Current design:** Ongoing recorders hold ≤30 s leaves. Each renewal re-reads current facts under SQL locks, and the 15 s loop renews every replica. Finite actions get a ≤20 s lease. Permits are signed, and local slices are tracked in Kubernetes objects via CAS.
- **Problem class:** per-step revalidation; timer-driven renewal; bespoke signed permits over an already mTLS-authenticated channel; Kubernetes objects as counters.
- **Cost:** Renewal SQL load per replica every 15 s grows linearly with monitored replicas, which the maintainer requires to be "all authorized replicas". A hub hiccup longer than 30 s stops every ongoing recorder fleet-wide. API writes on local clusters scale with action starts.
- **Maintainer or agent:** The maintainer requires expiring policy grants and storm protection, and ADR-312 sets the "run to original bounds" precedent. Renewal cadence, signatures and Kubernetes CAS permits are agent-added.
- **Replacement:** Issue one admission per source start, bounded by the accepted policy, grant and binding hard ends. The source then runs to those bounds, as ADR-312 does for downloads. Revocation, deactivation, deny and binding removal are pushed as stop messages over the existing connector connection. On disconnect, the connector or collector stops sources after a single documented offline grace period (one configuration value). Permits travel over mTLS and need no signatures. Local budget slices stay in the connector's memory or SQL on the hub, not in Kubernetes CAS objects. Precedent: Kubernetes node leases and kubelet pod lifecycle (run until told to stop, with an eviction grace), and continuous profilers such as Pyroscope or Parca agents, which run until reconfigured.
- **Must change together:** action-lifecycle.md, capacity.md, execution.md, live-watch.md, persistence.md, ADR-261/263 superseded.

### H7. Synchronous encrypted object-store audit on every operation, plus the audit retirement protocol

- **Where:** authorization.md:203-215 (REQ-AUT-005, ADR-112, ADR-115); privacy.md:100-102, 126 ("reserves release audit capacity before admitting a restriction"); policy-automation.md:43, 48 ("Require durable encrypted acceptance audit before eligibility"), 120 ("encrypted public operation intent is acknowledged before source/control mutations"); permissions.md:5, 120 (immutable encrypted audit event per SAR decision change).
- **Current design:** Every admitted tools/call, read, mutation, denial and SAR decision change writes an encrypted object audit intent and outcome before or after the effect. Audit has its own capacity reservations (records, objects, bytes, principal accounts) that are "never refunded". Retirement uses deletion certificates, a no-certificate fence, independent absence verification and residual-history charges.
- **Problem class:** synchronous encrypted audit and object-store writes on the hot path; spent-on-uncertain accounting; bespoke deletion-certificate protocol.
- **Cost:** Each request pays at least two object PUTs plus KMS-wrapped encryption, so latency and S3 request cost scale with request rate, including polls. Audit capacity exhaustion becomes a new outage mode. Retirement is a multi-step state machine per record.
- **Maintainer or agent:** Agent-added. The maintainer lists "unencrypted managed evidence storage" as forbidden but sets no audit format requirement.
- **Replacement:** Append audit rows to a time-partitioned PostgreSQL table in the same transaction as the effect, and fail the operation if the insert fails. This matches the Vault precedent of failing requests when no audit device can record ([Vault audit devices](https://developer.hashicorp.com/vault/docs/audit)) without per-request object I/O. Export sealed batches (for example every N records or minutes) to object storage for long-term retention, as Kubernetes batch audit backends do ([Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)). Retire by dropping partitions past audit retention ([PostgreSQL partitioning](https://www.postgresql.org/docs/current/ddl-partitioning.html)) plus object-store lifecycle expiration on batch prefixes. Drop audit capacity reservations, certificates and absence verification. Cover permission-change provenance with Kubernetes audit logs (permissions.md:38 already relies on them) instead of per-transition encrypted events.
- **Must change together:** persistence.md (REQ-DB audit outbox), interfaces.md, mcp.md, artifact-downloads.md, live-watch.md, evidence.md, docs/architecture/operation-audit-lifecycle.md and operation-audit-overdue.md (superseded).

### H8. Retention source journaling, checkpoints, catch-up and signed snapshots

- **Where:** privacy.md:3-9, 37 ("signed policy snapshots with a default 30-second freshness and a 60-second maximum … leases"), 51, 55 (preview depends on "accepted, fresh, audited and caught up"), 266-268.
- **Current design:** Retention policies are observed through a durable watch watermark with checkpoints. Transient added-then-deleted policies are reconciliation obligations, and bookmarks must not renew freshness. Each earlier catch-up needs audit receipts. Effects revalidate "complete accepted source versions" and topology pins. Local enforcement uses signed 30/60 s snapshots.
- **Problem class:** edge-triggered history journals; expiry-driven freshness; bespoke signed snapshots; per-effect revalidation.
- **Cost:** Retention availability gates collection and disclosure fleet-wide. Any watch gap or late audit blocks every new effect, and the spec records an earlier sustained-availability failure in this exact path. Catch-up pages run 16 attempts at a time and serialize.
- **Maintainer or agent:** The maintainer requires administrator-enforced maximum retention. Watermarks, checkpoints, signed snapshots and transient-policy obligations are agent-added (ADR-055/056).
- **Replacement:** Use a level-triggered informer on EvidenceRetentionPolicy. Each artifact already pins its deadlines at collection (privacy.md:65-74), so a disconnected collector needs no snapshot lease. On every policy add or update event, run one set-based SQL `UPDATE … SET expires_at = LEAST(expires_at, …)` over matching artifacts. Shortening is monotonic, so an event handled late still converges. Document that a policy added and deleted entirely within a watch disconnect may be missed. This is standard Kubernetes level-triggered semantics, and nobody outside the project shows harm from it. Hub-to-local propagation pushes policy over the existing connection (H5). Loki's compactor-based retention is the comparable time-based design ([Loki retention](https://grafana.com/docs/loki/latest/operations/storage/retention/)). Drop signed snapshots, topology pins, lifecycle-audit receipts as gates, and the "historical labels unknown" handling.
- **Must change together:** evidence.md, capacity.md, artifact-downloads.md, docs/architecture/retention-*.md (checkpoints, catchup, topology, effects, lifecycle), persistence.md.

### H9. Signed submission envelopes (ADR-062) and the admission adapter for policy and capture submission

- **Where:** permissions.md:160-166 (REQ-PER-007: signed canonical envelope, nonce consumption, replay record, OpenBao Ed25519 JWS, five-second public-key trust); policy-automation.md:33, 48 ("atomically consume the authenticated submission nonce").
- **Current design:** Direct Kubernetes and GitOps submissions require a qualified admission adapter that signs a canonical envelope. The controller verifies it after persistence, consumes a nonce and retains the replay record.
- **Problem class:** bespoke crypto/enrollment where Kubernetes RBAC and standard admission `userInfo` suffice; defends against trusted writers.
- **Cost:** A dedicated signing key and key lifecycle, an admission webhook on the hot path, nonce tables and a 5 s trust re-observation. ADR-228 already removed this for hub-held policies activated in-process.
- **Maintainer or agent:** Agent-added. The maintainer requires Kubernetes-only permission configuration and team automation, not signatures.
- **Replacement:** Keep in-process `activate_policy` (ADR-228) as the human path. For GitOps, the policy executes only within its `spec.automation` envelope. Whoever can write the DebugPolicy is authorized by RBAC, as CronJob, Argo Workflows (`serviceAccountName`) and Flux multi-tenancy (impersonated `serviceAccountName`, [Flux multi-tenancy](https://fluxcd.io/flux/installation/configuration/multitenancy/)) treat writers. Record the actual writer from Kubernetes audit or `managedFields` for provenance. Approval review of changed execution scope stays. Drop the envelopes, JWS, nonces, replay records and the signing key.
- **Must change together:** execution.md (submission provenance), docs/architecture/policy-submissions.md, ADR-062 superseded, contracts.

### H10. Canonical sharing requirements diverge from the implemented simplified design

- **Where:** authorization.md:129-139 (SharingIntent SQL record), 155-159 (registration, selections, PendingApproval/Active/Draining/Completed/Suspended/Denied/Revoked/Expired), 173-181 (REQ-SHR-006: derivation-chain traversal ≤256 manifests/depth 64, CAS snapshot revisions, child shares per selection, publication slots, audit outbox), 187-195 (tombstones, intent revision), versus refinements at 147 (ADR-235: "no SharingIntent record") and 167 (ADR-239: counter on the acceptance, Draining derived).
- **Current design:** The canonical requirement mandates a full SharingIntent state machine with registration ledgers and tombstones. The implementation refinements already replaced it with one counter and ordinary shares.
- **Problem class:** duplicated state machines; a spec that contradicts its own implemented, simpler design.
- **Cost:** The heavy design is the target for future increments, and reviewers have to reconcile two contracts. It carries eight intent states, two ledgers and a 256-manifest traversal per publication.
- **Maintainer or agent:** Capture-time and bounded recurring-policy sharing are maintainer requirements. The intent machinery is agent-added.
- **Replacement:** Promote the ADR-235/239 refinements to the canonical text. A capture or policy acceptance carries an immutable sharing instruction with a counter. Publication creates an ordinary EvidenceShare in the publication transaction. Revoke-all is an update by acceptance ID, and the state is derived. Add output selection later as a field on the same instruction (selected action IDs), with provenance checked by the capture UID recorded on the artifact, not by graph traversal. Keep the ADR-323 retirement out (see M5).
- **Must change together:** capture-profiles.md (alias map, authorization.md:288), interfaces/mcp (`list_shares`, `revoke_share`, `stop_future_sharing`), examples/sharing-intent.yaml, persistence.md (REQ-DB-002/003 lock order for intents).

---

## Medium

### M1. Decision-time SAR repeated on every read, persisted per principal, with encrypted audit per decision change

- **Where:** permissions.md:120 (ADR-245), 192 ("Every read path … repeats the caller's recorded review of the artifact's Pod before its permission read").
- **Current design:** Before preview, request, explain and each read, hub-api asks the connector to submit a SubjectAccessReview. Results become persistent per-principal assignments and SQL rows, and every decision change writes an immutable encrypted audit event.
- **Problem class:** chatty per-request cross-cluster round trips; per-decision encrypted audit.
- **Cost:** One hub → connector → API server round trip per read (N per case listing) and per poll. Encrypted object writes follow every change.
- **Maintainer or agent:** Pod-exec inheritance is a maintainer requirement. Per-read SAR plus audit plus persistent assignments is agent-added.
- **Replacement:** Cache SAR results per (principal, groups, pod or namespace attributes) in the connector for the ADR-311 30 s window, with a shorter negative TTL. This is the standard kube-apiserver webhook-authorizer behavior (`--authorization-webhook-cache-authorized-ttl` default 5 m, unauthorized 30 s; [kube-apiserver flags](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)). Batch SARs for multi-artifact listings. Record the audience as the principal (H3) without a persistent assignment row. Audit through the normal operation audit (H7).
- **Must change together:** targets.md, docs/architecture/permission-acceptance.md, ADR-245.

### M2. Browser settings as a pinned protected ConfigMap with a five-second SQL projection and epochs

- **Where:** policy-automation.md:92 (misplaced REQ-AUT-001 text: "pinned protected ConfigMap", "separate five-second SQL projection", "Source replacement/rollback and reused epochs are rejected"); authorization.md:8-13, 312-314 ("intersect … the current settings observation's original deadline").
- **Current design:** Session settings are observed with ≤5 s lifetimes, projected into SQL and versioned with never-reused epochs. Login and refresh fail closed when the observation is stale.
- **Problem class:** guard-era self-verification (pinning, rollback rejection); expiry-driven freshness; defends against ConfigMap tampering by trusted writers.
- **Cost:** A recurring read per hub replica plus SQL writes, and login outages when the observation is late.
- **Maintainer or agent:** Agent-added (ADR-061). ADR-328 says to trust mounted ConfigMaps.
- **Replacement:** Mount the settings ConfigMap and reload on file change, or on a Helm-driven rollout via a checksum annotation (the standard Helm pattern). When an issuer, client or origin changes, invalidate sessions by storing the settings digest in the session row and rejecting a mismatch. Sessions follow the oauth2-proxy and Grafana model: server-side session row, fixed max lifetime and refresh-token rotation. Move the paragraph out of policy-automation.md.
- **Must change together:** docs/architecture/browser-sessions.md, deployment-profiles.md, charts.

### M3. Spent-on-uncertain accounting and full conservative charging

- **Where:** authorization.md:69, 73, 75 ("On ambiguous execution, charge the full reservation conservatively … Reclaim unused budget only after authoritative proof"), 211 (audit), 261, 271; investigation-approval.md:172 ("maxBytes includes retransmission and uncertain spend"), 176, 310 ("reservations … never refunded").
- **Current design:** Unknown outcomes remain charged forever, and expiry never refunds.
- **Problem class:** exactly-once / spent-on-uncertain accounting where idempotency keys suffice.
- **Cost:** Transient network errors permanently burn grant and capacity budgets. Users then hit `Exhausted` after flaky runs and need new approvals.
- **Maintainer or agent:** Storm protection and finite budgets are maintainer requirements. The never-refund rule is agent-added.
- **Replacement:** Give each reservation an idempotency key (already present: "Retries reuse the same reservation"). The connector reports the terminal outcome (started, not started, bytes used) when it reconnects, and the hub settles to actual usage. Only reservations with no report by the grant's hard end are charged in full. Precedent: [Stripe idempotent requests](https://stripe.com/docs/api/idempotent_requests). Kubernetes ResourceQuota also recomputes usage from actual objects rather than keeping uncertain charges.
- **Must change together:** capacity.md, persistence.md, artifact-downloads.md, live-watch.md.

### M4. Deletion requires writer-quiescence proofs and an encrypted copy inventory

- **Where:** privacy.md:88-98 (REQ-PRV-004: encrypted lineage/copy inventory in object storage, "all four writes must be acknowledged and the one-use producer joined", writer fencing), 106.
- **Current design:** Before purge, cleanup must prove positive writer completion. Without that proof, the charge and the overdue status remain.
- **Problem class:** self-verification state machines; spent-on-uncertain.
- **Cost:** Every artifact carries a writer-closure protocol, and failed or uncertain writes stay charged and overdue indefinitely (the spec says this is "not established" for those cases).
- **Maintainer or agent:** Maximum retention is a maintainer requirement. The quiescence protocol is agent-added.
- **Replacement:** Upload commit already refuses after `expiresAt` (privacy.md:76). Add bucket lifecycle rules `AbortIncompleteMultipartUpload` and `NoncurrentVersionExpiration` ([S3 lifecycle examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html)). Delete by per-artifact prefix after `expiresAt`, then run a second sweep at `deleteBy` to catch late writers. Keep content-minimized copy references in SQL only. This is how Loki, Tempo and Sentry retention work. Keep `DeletionOverdue` reporting.
- **Must change together:** evidence.md, capacity.md, docs/architecture/custody-transactions.md, context-deletion.md.

### M5. Share metadata retirement bound to prepaid operations (ADR-323)

- **Where:** authorization.md:121; privacy.md:230, 244 (SC-PRV-015).
- **Current design:** Each share is bound to one prepaid operation's "live-removal cutoff" and residual-history charge. Shares that cannot fit return unavailable. Retirement requires independent audit-object verification.
- **Problem class:** spent-on-uncertain; bespoke lifecycle for small metadata rows.
- **Cost:** Share creation fails for backing reasons unrelated to sharing, and each share has its own cleanup state machine.
- **Maintainer or agent:** Agent-added.
- **Replacement:** Share rows are deleted (or their partition dropped) after expiry plus the case-metadata retention. The backup horizon is documented once per installation (L2).
- **Must change together:** persistence.md, ADR-323 superseded, interfaces (error codes).

### M6. Child raw grants materialized per artifact and client

- **Where:** investigation-approval.md:170-180 (REQ-INV-002), authorization.md:310.
- **Current design:** After a verified commit, C-03 creates a child rawQuery grant per (parent, artifact, client) in a SQL transaction with audit and shared-counter reservation.
- **Problem class:** duplicated grant records for one fact (the parent decision).
- **Cost:** An extra transaction and audit per artifact × client, plus materialization-failure states ("pending access with a retry of materialization").
- **Maintainer or agent:** One approval covering capture plus result access is a maintainer requirement. AGENTS.md also summarizes "exact child grants are created only after verified commit", but that reads like an agent design summary; the maintainer should confirm.
- **Replacement:** At read or download, evaluate the parent grant directly. It allows the operation if the artifact's recorded capture UID and action ID match the approved resultAccess, the caller is the same human on an approved client, and the shared pool has budget, which is a single SQL counter. No child rows, materialization retries or `Unavailable` state. This keeps "no unknown artifact in an executable grant", because the parent never names artifacts.
- **Must change together:** artifact-downloads.md (REQ-DLD-002), mcp.md (`get_grant` children), persistence.md.

### M7. Per-step revalidation after blocking reads and locks

- **Where:** authorization.md:43 ("Recheck identity/source/evidence deadlines after blocking reads; time spent resolving another dependency cannot extend freshness"), 304 (live: "Recheck at view open, cursor/read/update and actual delivery"); investigation-approval.md:174, 205; policy-automation.md:54 ("Fetch external proofs before SQL locks and recheck deadlines/revisions after all blocking work"), 77, 113.
- **Current design:** Each helper rechecks deadlines and authority after every wait.
- **Problem class:** per-step / per-helper revalidation.
- **Cost:** Repeated reads per operation, plus spurious failures when a check crosses a 5 s boundary mid-request.
- **Maintainer or agent:** ADR-311 (maintainer) sets one authorization per operation, reused ≤30 s.
- **Replacement:** Authorize once at operation start and carry an `Authority{validUntil}` value. SQL effect statements include `now() < validUntil` and revocation predicates in their WHERE clause (one cheap check per effect). Live views use the same 30 s reuse plus pushed revocation.
- **Must change together:** live-watch.md, mcp.md, artifact-downloads.md, persistence.md (REQ-DB-003).

### M8. Sensitive observation bytes reserved centrally per slice

- **Where:** authorization.md:261-271 (REQ-AUT-006), 290.
- **Current design:** Wire bytes entering sensitive parsers are charged in cumulative grant pools. Conservative byte slices are reserved in SQL before dispatch, and unused credit stays spent.
- **Problem class:** central accounting on the data path; spent-on-uncertain.
- **Cost:** Grant pools drain by the worst case (`R × (seconds+1)`) regardless of actual traffic, and sessions need multiple coordination points.
- **Maintainer or agent:** Bounded packet capture is a maintainer requirement. Cumulative observed-byte grant pools are agent-added.
- **Replacement:** The collector enforces per-session rate and byte limits locally (token bucket) and reports actual observed bytes at session end. The hub settles the grant pool from those reports, as in M3. Keep maxSessionSeconds and maxConcurrentSessions.
- **Must change together:** syscalls.md, capacity.md, action-lifecycle.md.

---

## Low

### L1. Paused live views poll status for revocation

- **Where:** privacy.md:262.
- **Problem:** Polling where the existing long-poll could carry a terminal revocation batch.
- **Replacement:** Return a terminal `AccessRevoked` item on the current `read_live_watch` wait. Agent-added.
- **Must change together:** live-watch.md.

### L2. Backup-horizon arithmetic gates collection

- **Where:** privacy.md:234, 240 (SC-PRV-008).
- **Current design:** For each data class, live removal is due by `hardDeleteBy − H − cleanupBudget`, and an incompatible profile blocks collection.
- **Replacement:** Document the backup retention. At restore, apply tombstones and lifecycle decisions before serving (already in privacy.md:96). Regulator guidance accepts putting backups "beyond use" until they expire ([ICO right to erasure](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/)).
- **Maintainer or agent:** Agent-added.

### L3. Implementation-status and qualification prose mixed into requirements

- **Where:** permissions.md:3-5; authorization.md:21; privacy.md:3-9, 51, 98-102, 266; policy-automation.md:92-151 (an accumulation of increment notes, including the browser-settings paragraph that belongs in authorization.md).
- **Problem:** Readers cannot tell the requirement from the status of an increment, which is how obsolete guard-era text survives.
- **Replacement:** Move status to docs/implementation-progress.md and keep the specs normative.

### L4. Same-client binding for resume of an approved plan

- **Where:** investigation-approval.md:196-232 (ADR-252 `approvedAcceptance/v1` blueprint retention, `resume_requires_original_client`).
- **Current design:** Resume requires the original OAuth client, and the blueprint is retained under quotas through the review window.
- **Problem:** The maintainer's decision says "same human". Client binding beyond the reviewed client list adds UI states (`can_resume`, `can_resolve`) for a speculative risk.
- **Replacement:** Allow any reviewed client of the same human to submit. Drop the separate resolve path.
- **Maintainer or agent:** Agent-added.

---

## Cross-cutting replacement summary

1. **Watches, not polls (H4, H5, H8, M2):** informers (connector) push deltas over the existing connection. Caches stay valid until replaced and are stale only on disconnect.
2. **One authority per operation (H4, H6, M7, M1):** ADR-311 snapshot ≤30 s, SQL predicates on effects, and pushed revocation for long-running sources.
3. **Group-based audiences (H3, H10, M6):** remove assignment IDs, continuity proofs and child grants. Evaluate current group roles against the recorded audience.
4. **SQL-transactional audit with batched export (H7, M5):** remove audit capacity, certificates and retirement protocols.
5. **Trust RBAC and Helm (H1, H2, H9):** ADR-329 namespaced bindings, Helm VAPs without proofs, no signed envelopes, and a VAP `authorizer` `bind` check only if escalation evidence is accepted.
6. **Settle on reported outcomes (M3, M4, M8):** use idempotency keys and report outcomes on reconnect. Lifecycle rules replace writer-quiescence proofs.
