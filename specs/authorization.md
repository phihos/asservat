# Authorization, approvals, sharing and audit

Mechanisms follow [ADR-330](../docs/decisions/330-event-driven-system-design.md): one authorization per operation reused for at most `identity.AuthorityRecheckInterval` (30 s; 60 s for the shared delivery-policy observation) and never past an original deadline ([ADR-311](../docs/decisions/311-operation-authority-recheck.md)); started streams run to their original bounds ([ADR-312](../docs/decisions/312-started-downloads-run-to-original-bounds.md)); audit is a database row; effects carry idempotency keys.

## REQ-AUT-001 — Identity and ordinary access

Human sessions use a qualified external OIDC provider or the [local identity alternative](deployment-profiles.md#req-dep-002--local-identity-without-a-second-permission-system). External sessions use OIDC code/PKCE and bounded refresh; local identity preserves equivalent principal, assurance and revocation semantics and standard OAuth access for MCP/CLI. Verified external groups are synchronized by replacement, including removals; stored profile data and session cookies never renew claim freshness. There is no mandatory directory-admin account or personal offline token for recurring team capture. IdP logout and external deprovisioning are distinct; login-only synchronization cannot guarantee immediate external revocation. Qualified back-channel logout may invalidate sessions; SCIM/security-event integrations are optional. Recurring execution follows [team policy automation](policy-automation.md).

Every user-facing operation resolves a principal `(issuer, subject, clientID, identityType)` from validated credentials: signature, issuer, audience, expiry/not-before and configured client binding. ID tokens are never access tokens; client-supplied groups or roles are never trusted. `azp`/`client_id` is normalized per issuer; ambiguous claims are refused. Tokens and backend errors never enter ordinary logs or responses.

The installation serves one organization. Administrators configure trusted issuers, audiences, clients and eligible organization users/groups. A valid token alone does not establish eligibility; the configured membership policy must admit the identity. Eligibility does not imply workload access. No tenant or organization ID exists on principals, grants, shares or artifacts. The [Keycloak profile](../docs/architecture/keycloak-profile.md) is the first supported provider.

Browser sessions ([ADR-060](../docs/decisions/060-bounded-browser-sessions.md)) are server-side session rows with a fixed maximum lifetime, encrypted server-held tokens, one-use refresh rotation and logout, following the oauth2-proxy and Grafana model. GET requests never refresh a session; `POST` refresh requires the exact origin and CSRF token. Session settings ([closed schema](contracts/browser-settings.schema.json)) come from a mounted ConfigMap, reloaded on file change or on a Helm rollout through a checksum annotation. Each session row stores the digest of the issuer, client and browser origin it was created under; a mismatch with the current settings invalidates it. A lower maximum lifetime shortens existing sessions (expiry is the minimum of the stored expiry and creation plus the current maximum); a higher one never extends them. Local sign-out and verified provider revocation work without the provider. Session creation or refresh never grants step-up or recurring execution. A session-backed identity is valid until the earliest of token expiry, session expiry and group freshness; downstream authorization keeps that bound. A native download holds no server-side refresh ownership ([ADR-224](../docs/decisions/224-remove-download-refresh-owners.md)); an interrupted download resumes after an explicit console refresh.

Ordinary access is namespace/workload entitlement across enrolled clusters through [permission management](permissions.md). Entitlements include the cluster UUID, so equal names in different clusters confer nothing. RBAC is not inferred as an evidence ACL without a configured source. Unauthenticated errors reveal no artifact existence.

### SC-AUT-001

Given matching subject strings from two issuers or a token for another audience, when a case is queried, then the identities are not conflated and the wrong-audience token is refused before case discovery. A settings change of the issuer, client or origin invalidates existing sessions; lowering the maximum lifetime shortens them.

## REQ-AUT-002 — Authorization composition

A read must satisfy:

```text
valid, organization-eligible identity AND artifact retained AND no deny
AND (ordinary evidence entitlement OR active EvidenceShare coverage)
AND required OAuth scope
AND (if raw: active per-principal/client raw operation grant)
AND remaining query/output budget AND audit row writable
```

Ordinary entitlement uses the role and recorded-audience rules in [permission management](permissions.md); `evidence-reader` alone confers no raw eligibility. A scope alone is never a grant. A share is never a raw grant or capture permission. Deny wins over both. Group shares use current qualified membership; raw grants stay bound to the calling principal and client.

An operation authorizes once at its start, before any evidence lookup, and carries the result as an `Authority{validUntil}` value: the earliest of check time plus the recheck interval and every original hard end. SQL effect statements include `now() < validUntil` and the relevant revocation predicates (share, grant, restriction state) in their `WHERE` clause; there are no per-helper rechecks. The ordinary evaluator's success cannot substitute for accepted execution, local ceilings, grant/share conditions or the effect statement. Its matching bindings describe the caller, not the full audience of a capture.

### SC-AUT-002

Given a user with `evidence:raw` and a valid raw grant but no ordinary entitlement or share, when memory is requested, then access is refused. An extract-only share still does not permit raw access.

## REQ-AUT-003 — Individual and policy grants

`AccessGrant` distinguishes artifact queries, automatic policies and individual captures. Raw grants bind existing artifact digests and operations. Policy grants bind policy UID, execution digest, workload/recipe scope and finite future budgets. Ad hoc grants bind one accepted capture UID and its execution digest. [Execution identity](execution.md) defines digest separation; unknown future artifacts are never raw-query targets.

Individual grants require a distinct authenticated human approver holding `action-approver` for the target and recent step-up. An approval cannot widen the requester's entitlement. Default expiry: 1 hour for ad hoc capture; at most 8 hours for a raw-query grant; policy grants default to seven days. Approval settings set a finite default and maximum (configurable up to 365 days), with narrower local maxima winning; expiry beyond the effective maximum is refused and never self-renews. Lowering the maximum clamps existing grants from their original issue time; raising it never extends them. Sharing and raw-query maxima are separate. Grant ownership cannot be transferred.

A recurring-policy grant keeps the human or service requester as provenance and separately binds `policyExecutor` and `policyAuthority`. Self-approval compares the reviewer with the human requester, never with the executor. The grant confers no personal result access, raw query, download or sharing; creator departure alone does not invalidate team authority.

The approval page shows exact scope and impact, supports approve/deny/revoke, protects against CSRF and clickjacking, and records requester and approver issuer/subject/client, reason, authentication context and digest. Automation identities cannot approve themselves. Step-up is verified from qualified IdP assurance or server-verified local authentication (REQ-DEP-002), never a UI checkbox.

Packet and syscall plans that need review (a raw-byte filter predicate, or every recording when `approvals.requireRecordingApproval` is set) are individual grants ([ADR-249](../docs/decisions/249-sensitive-acquisition-grants.md)). `request_capture` opens one review bound to the plan's capture UID, execution digest, data class, reasons, requesting human and finite lifetime, and is refused with `ApprovalRequired` until an approved, unrevoked, unexpired grant covers exactly that plan for that still-eligible requester. `decide_review` (browser) requires a distinct human with a current, undenied `action-approver` allow for the target; approving additionally requires the access token's signed `acr` to be one of `approvals.stepUp.acrValues` and `auth_time` at most `maxAgeSeconds` old. Without configured step-up nothing can be approved. Denial and `revoke_grant` (requester or current approver) only restrict and need no step-up. An approval lasts one hour from the decision, never past the result-access `notAfter`. `get_grant` shows the plan to the requester or a current approver only.

### SC-AUT-003

Given a raw or capture request, when its requester attempts approval through another client under the same identity, then self-approval is refused. A reviewed policy runs approved automatic actions until its expiry or budget; a changed recipe requires review again.

## REQ-AUT-004 — Budgets, reservations and revocation

Each execution or query reserves its grant bytes and counts in one hub SQL transaction together with [capacity](capacity.md) before it starts. A reservation has a unique operation ID (idempotency key), bounds and state. A retry with the same ID returns the existing reservation; it never starts the action again. Counters are per grant and change with conditional updates. When the outcome is known (started or not, bytes and operations used), the reservation is settled to actual usage and the remainder is released. Connectors and collectors report outcomes when the work ends or, after a disconnect, when they reconnect; only a reservation with no report by the grant's hard end is charged in full ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D7).

`maxExecutions` counts individual authorized action starts for capture grants and individual query operations for raw-query grants. A recipe with three intrusive actions consumes three executions; extra process fanout adds one per actual start. Each action reserves its worst-case bytes before it starts; the UI shows action count and maximum bundle cost. Grant counters are independent of capacity reservations; both must succeed.

At most 64 active reservations per grant. Query concurrency defaults to 4 per principal and 32 per installation. At a limit, reject or queue within a bounded deadline.

Collection is admitted once per source start under one permission snapshot and bounded by every hard end (grant, policy, binding, local ceiling, session). A budget slice delegated to a connector lives in the connector's memory and is settled through the same outcome reports; Kubernetes objects are never counters. Work and its admission travel over the connector's mTLS connection and need no signatures.

Revocation refuses new reservations, admissions, cursors and share-dependent reads as soon as it commits. Running sources receive a pushed stop over the connector connection; a source whose connector is disconnected runs to its admitted hard end, and the stop is delivered when the connection returns if that end has not passed. Started downloads run to their original bounds (ADR-312). A started upload may finish without new acquisition while the artifact's deadlines allow. A query is one operation: it is authorized at its start and refused at its next start after revocation.

### SC-AUT-004

Given two simultaneous raw requests sharing a 64 KiB remaining budget, when each asks for 64 KiB, then at most one reservation succeeds. A controller crash after dispatch cannot make the same intrusive action run twice: the retry with the same operation ID finds the existing reservation. When the connector reconnects and reports that the action never started, the reservation is released. Revocation refuses the next query and stops the running source.

## REQ-SHR-001 — Explicit evidence sharing within the organization

An evidence owner (`evidence-owner` on the workload and the `evidence:share` client scope) may create an `EvidenceShare` that grants named users or stable group IDs access despite their ordinary ACL. Creation requires current access to each included artifact; receiving a share never confers sharing authority.

A share binds an explicit snapshot of artifact versions (each a published artifact at its verified version), 1–8 User or Group recipients with stable IDs of the configured issuer, allowed data classes and operations, reason, the immutable creator, its management (REQ-SHR-008) and expiry. Default expiry is 24 hours, at most seven days and never beyond the artifact's access deadline. Future recurrences, artifacts and extracts are excluded; extending a snapshot is a new decision. Capture-time and policy sharing instructions (REQ-SHR-004/005) create ordinary concrete shares at publication, never an open-ended subscription. No anonymous link capability exists; URLs are authenticated navigation links. A share also grants the recipient the native download of exactly the shared versions with the `evidence:download` scope ([ADR-233](../docs/decisions/233-recipient-native-download.md)), charged to the workload's transfer allocation.

Recipients must be eligible organization users or groups; eligibility is enforced at every use. An unapproved issuer, an identity outside the organization policy or evidence of another installation is refused. Group IDs are stable and issuer-scoped; display names are insufficient.

A share is evaluated after the ordinary evaluator refuses and before any evidence lookup; current denies win. State is derived at read time: Active, Expired, Revoked, Suspended.

### SC-SHR-001

Given a developer without the payments workload ACL, when an owner shares two existing stack extracts with that user's group, then the user can query those extracts. A later occurrence and an unshared file stay inaccessible. A recipient from an unapproved issuer is refused even if the creator is an administrator.

### SC-SHR-009

Given a published pod-status artifact and an eligible user named by no AccessBinding, when the user calls `get_case`, then it is refused exactly like an absent case. When an evidence owner shares that artifact with the user, the user's `get_case` returns only that artifact with access `shared` and the user can prepare and Range-download its native file. After revocation, the next `get_case`, `prepare_artifact_download` and content request are refused; a started response runs to its original bounds. A current deny of the user or share expiry refuses as well. When every managing team loses `evidence-owner` the share is Suspended; when a managing team holds it again the share is Active again.

## REQ-SHR-002 — Shared view and raw access

Discovery projects a minimal shared case view: permitted case ID and title, authorized timeline entries, artifacts and available operations. Hidden artifact names or counts, other cases, workload inventory, labels and facets are never exposed through counts, pagination or error differences. Cursors bind principal, share IDs and query snapshot.

Sharing raw evidence requires raw-sharing authority and independent approver review; recipients still need their own operation grant. Extract shares are owner-approved. The approval page shows both the share and the raw grant when composing access.

### SC-SHR-002

Given a shared case with one visible extract and three hidden artifacts, when the recipient lists, searches, paginates or guesses IDs, then no hidden count, name or existence is disclosed. An approved raw share without an individual raw-query grant returns `GrantRequired`.

## REQ-SHR-003 — Revocation and group freshness

Current managers (REQ-SHR-008), the creator and installation administrators can revoke at once. Artifact expiry, loss of organization eligibility, an explicit deny and share expiry end access regardless of cached results. Group membership is revalidated by a qualified IdP adapter or fresh assertions; default maximum membership staleness is five minutes, and stale group claims cannot extend it. Providers without usable group freshness support user shares only.

Evidence already seen by a recipient or agent cannot be clawed back. Creation, approval, recipient access, scope changes, expiry and revocation write audit rows. No share operation sends chat or email notifications.

### SC-SHR-003

Given a recipient with a valid cursor, when the share is revoked, then the next page is refused. Removal from a shared group stops new disclosure within the freshness bound.

## REQ-SHR-004 — Share results when requesting collection

An evidence owner may include `sharing` in a capture request (`preview_capture`/`request_capture`, DebugCapture `spec.sharing`). It names 1–8 eligible recipients of the requester's issuer, optionally the outputs and an absolute `notAfter` (future, at most seven days). It applies only to that capture UID and its resolved plan. Omission means no sharing; the ordinary audience is unchanged. Collection still requires collection rights, approvals and capacity independently of sharing.

Default outputs are the recipe's administrator-approved metadata and extract outputs; raw outputs are never included by default. Explicit `outputs` name action IDs from the compiled plan (at most 16); unknown actions fail validation, and raw outputs need independent raw-sharing review (REQ-SHR-006). The basic path asks only for recipients; the reason defaults to the capture reason.

Sharing authority (`evidence-owner` and `evidence:share`) is checked in the admission transaction; without it the whole request is refused before execution (`SharingNotPermitted`). The accepted capture carries one immutable sharing instruction: recipients, outputs, end, creator and management. There is no separate intent record. The browser's "Share results with…" section and MCP `request_capture` use the same evaluator; MCP needs `evidence:share` when sharing is present.

At publication, the catalog transaction creates one ordinary EvidenceShare for each published artifact whose recorded capture UID and action ID match the instruction ([ADR-235](../docs/decisions/235-capture-time-sharing.md)), provided a managing team or the personal creator still holds `evidence-owner` and the end has not passed; the unique key (capture UID, artifact) makes replay create nothing more. Share expiry is the minimum of `notAfter` (default 24 hours after publication), seven days after publication and the artifact's access end. Full manager, deny and recipient checks run at every read. When no share can be created the capture still publishes; `get_capture` reports `sharing.state` (`Pending`, `Shared` with share IDs, `SharingUnavailable`) separately from collection.

### SC-SHR-004

Given an owner requests a capture with an incident-response group and no explicit outputs, when collection and the approved extract finish, then only metadata and extract outputs become shared. The group cannot see raw logs or another capture. A caller with collection permission but no sharing authority cannot attach the instruction.

### SC-SHR-010

Given an evidence owner with `evidence:share` who reviews a pod-status capture with one recipient, when the request is accepted and the capture publishes, then exactly one share of the published artifact exists, a replayed publication creates no other, `get_capture` reports `Shared`, and the recipient's `get_case` returns the artifact with access `shared`. A requester without `evidence-owner` is refused before any capture exists. If the end passes before publication, the capture publishes without a share and reports `SharingUnavailable`.

## REQ-SHR-005 — Explicit sharing of recurring policy results

A DebugPolicy may include `spec.sharing` only with `futureCaptures.maxCaptures` (1–100) and an absolute `notAfter` (at most seven days after activation) ([ADR-239](../docs/decisions/239-recurring-policy-sharing.md)). There is no "all future evidence" option. Activation reviews it first: without `sharing_reviewed`, `activate_policy` returns `SharingReviewRequired` stating that repeated collections will be shared, with recipients, maximum captures and end. Activation requires `evidence:share` and an `evidence-owner` group allow on the envelope's binding for a sponsoring group; those groups are the instruction's management. A capture-action approval is not a sharing approval; raw outputs always need independent review.

The policy acceptance carries the instruction and a counter. Each admitted capture of that acceptance claims one slot in its admission transaction, while under both limits, the policy generation unchanged since acceptance and sharing not stopped or revoked; the capture receives a capture instruction that publication turns into ordinary shares (REQ-SHR-004). A capture admitted without a slot is unshared and never backfilled. Sharing never blocks an otherwise authorized capture and never overrides storm or resource limits. Each capture gets its own concrete shares; a shared case view never includes other occurrences merely because they correlate.

A new policy generation stops claims for the old acceptance; activating it is a new acceptance with its own counter and no backfill. `stop_future_sharing` (`sharing_intent_id` = the acceptance ID) stops further claims while already claimed captures still publish; existing shares stay. State is derived: active, limitReached, expired, stopped, policyChanged, revoked; `get_policy_status` reports it, its revision and the captures shared.

### SC-SHR-005

Given a reviewed policy instruction limited to ten captures and ending at 18:00, when capture ten is admitted and its extract publishes at 17:50, then it is shared. Capture eleven, an old occurrence and a capture under a changed generation are excluded. An extract published after 18:00 is not shared, and a restart does not renew the end or the counter.

### SC-SHR-012

Given an activated policy whose sharing allows three captures, when four captures are admitted, the last two by a restarted hub, then the first three are shared and the fourth is not, and the counter stays three. After an edit, captures are unshared until the new generation is activated, whose acceptance shares only later captures. Revoke-all of the first acceptance revokes exactly its shares and leaves the new acceptance's shares active. After a manager stops a third acceptance's sharing, its already claimed capture still publishes a share and the next capture is unshared. A sharing policy is never activated before its review was returned and accepted.

## REQ-SHR-006 — Concrete publication and approval boundaries

Publication shares an artifact only when its recorded capture UID matches the instruction's capture, its action ID is one of the selected outputs, its classification matches the selected output class and it is committed and verified. Provenance comes from the capture UID and action ID the producer recorded on the artifact, never from labels, client case IDs or graph traversal. Mixed-capture comparisons, recipient query results, newly requested analyses and changed projections never qualify. No eligible output gives `NoEligibleOutputs`, never a share of the raw fallback.

Shares created by publication are ordinary EvidenceShare rows with concrete artifact versions, their origin (acceptance or capture, artifact), creator, management, operations and expiry; they never include future artifacts or allow resharing. The unique key (origin, artifact) makes retries idempotent and prevents recreating a revoked share. At most 64 artifacts per capture; installation share quotas apply in addition. At a quota, publication reports `SharingCapacityUnavailable` and the capture stays useful to its normal audience. Shares never copy evidence and never extend retention.

Raw outputs are approved separately from metadata and extract outputs: owner-approved selections may publish while raw selections await independent approval. Raw approval binds the digest of the instruction (outputs, recipients, plan, limits, end); one reviewed recurring decision may cover those future outputs within its limits. Approval must be valid at publication; its revocation ends dependent shares. Recipients still need their own artifact- and operation-bound raw-query grants; none is created for unknown future artifacts.

### SC-SHR-006

Given a capture with an approved extract output and a pending raw-core output, when artifacts publish, then the extract becomes visible and the core stays unshared until raw-sharing approval. An artifact of another capture or action, or a publication after revocation, is not shared. Replaying a publication creates one share. Approved raw sharing alone still cannot run `read_memory`.

## REQ-SHR-007 — Stop, revoke and explain automatic sharing

Any current manager (REQ-SHR-008), the creator or an installation administrator can Stop future sharing or Revoke the instruction and its shares. Stop prevents new claims; already claimed captures still publish before the end; existing shares stay until their own expiry or revocation. Cancelling a single capture does not retract evidence already shared; the UI offers explicit revocation.

Revoke-all is `revoke_share` with `sharing_intent_id` (the acceptance or capture ID) and the expected revision: one update by origin revokes exactly that instruction's shares and stops its pending and future captures from being shared. Independently granted access and unrelated shares are unaffected. A revoked share is never recreated. Revocation is terminal; a GitOps reapply of the same generation cannot resurrect it. Policy suspension, deletion or a new generation stops claims without revoking earlier shares; the edit and delete previews say so and offer revoke-all.

The UI shows recipients, selected outputs, end, captures shared and remaining, outputs shared, pending or blocked, approval state and whether Stop or Revoke was chosen. Recipients discover a case only after a concrete artifact is shared. No outbound notifications or exports are added. `list_shares` shows owned instructions and share origins; received views stay concrete-artifact-only. `revoke_share` never changes capture authority or approves raw access.

### SC-SHR-007

Given an owner revokes an instruction while a late extract publishes, when publication retries or a recipient follows an old cursor, then nothing is disclosed. A revoked share is not recreated on replay. Stopping a recurring instruction lets already claimed captures publish while blocking new claims; revoking it ends every dependent share.

## REQ-AUT-005 — Durable audit

Every admitted authenticated `tools/call`, UI/API evidence access, grant/share mutation, intrusive action start and authorization denial writes one append-only audit row in the same PostgreSQL transaction as its effect ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D6). If the row cannot be written, the operation fails: no evidence is disclosed and no intrusive action starts. This follows Vault's fail-closed audit ([Vault audit devices](https://developer.hashicorp.com/vault/docs/audit)). Operations without a database effect (a read) write their row before returning output. A row records principal, normalized operation, keyed argument digest, case/artifact/share/grant IDs, decision and reason, reservation ID, output size and digest and trace ID; never raw arguments, tokens, matched log contents, memory or packet fields. Predictable secret arguments use a keyed digest.

Invalid credentials and pre-admission overload do not get individual rows; bounded counters and security logs record them. After admission, a scope denial, invalid input or unknown tool is audited. If the client disconnects after the result was committed, the row records delivery unknown. Background capture may keep already observed encrypted data while recording an audit gap, but never manufactures an approval.

The audit table is partitioned by time. Rows are exported in sealed batches to the object store or a SIEM, optionally under Object Lock ([Kubernetes audit backends](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)). Retention drops whole partitions past the audit retention policy and expires exported batches by object-store lifecycle rules ([PostgreSQL partitioning](https://www.postgresql.org/docs/current/ddl-partitioning.html)). Ordinary object storage is not immutable against an administrator. Kubernetes audit records permission configuration changes.

### SC-AUT-005

Given a completed query result, when the audit insert fails, then no result is sent. Retrying a mutation with its idempotency key returns the original outcome and its audit row; each new invocation gets a new request ID. No user-managed idempotency key is required for ordinary reads.

## REQ-SHR-008 — Multiple owner teams and immutable creators

Several issuer-qualified groups may hold `evidence-owner` for one workload through AccessBindings or metadata sources. Owner is a sharing and reading role, not collection permission. A share or instruction records the immutable `createdBy` from authenticated submission and `management`: either the creator or 1–8 stable owner group IDs. No member list is copied. The creator is never replaced by a controller, a group or the last editor.

`management` defaults to the creator's groups that currently hold `evidence-owner` covering the artifact inside its recorded audience ([ADR-232](../docs/decisions/232-concrete-evidence-share.md)); more than eight are refused with `ManagementTooBroad`, never truncated. A creator without an owner group manages personally. `create_share` accepts `management: {mode: teams}` naming groups the creator belongs to that hold `evidence-owner` inside the audience, or `mode: creator`; anything else is refused with `ManagementNotHeld` ([ADR-238](../docs/decisions/238-share-management-transfer.md)). An installation administrator (a current fleet operator) who may share can name any group that currently holds an undenied `evidence-owner` allow covering the artifact inside its audience; the audience is never widened. Review-source maintainership supplies no team ownership or sharing authority.

A current manager is a human with `evidence:share` who belongs to a managing group that currently holds an undenied `evidence-owner` allow covering the artifact. Membership changes within that group keep management, so a share survives its creator's departure. Managers list (`list_shares(view=owned)`, with `revision`, `created_by`, `managed_by`; received rows stay minimal), stop and revoke without fresh approval. The creator can always revoke. A share is Suspended while no managing group holds such an allow and becomes Active again when one does. Management never supplies artifact-read or raw-query rights and never widens an audience or confers resharing. A management view shows opaque IDs, expiry and controls, not hidden evidence, other recipients or team membership.

`transfer_share(share_id, expected_revision, idempotency_key, management)` lets a current manager replace the managing groups with groups they belong to under the same rules (`mode: creator` only for the creator); an administrator may assign current owner groups, which also resumes a share whose managing groups no longer exist. Transfers write an audit row, add one revision and never change creator, recipients, artifacts or expiry. Revoked or expired shares are never transferred. An administrator may `revoke_share` any share without evidence rights; it grants no read. `list_shares(view=administration, limit ≤ 100, cursor)` lists every share for administrators, newest first, with IDs, phase, expiry, revision, `created_by` and `managed_by`, never recipients or evidence. For recurring policies, managers of a new generation are set by its new acceptance.

Raw-sharing review always needs a human distinct from the requester or creator, even within one managing team or across clients. An `action-approver` of a managing team may approve another person's request; co-ownership is not approval. Grant requester and client bindings are not transferable.

UI and MCP `list_shares(view=owned)` include manageable personal and team shares and instructions, not everything the caller can read. "Created by" and "Managed by" are shown separately to managers. Selecting managing teams is optional. See the [two-team binding](../examples/access-binding-owners.yaml).

Policy grant details ([ADR-259](../docs/decisions/259-policy-grants-and-observation-spend.md)) let current members of a sponsoring group inspect the original workload and policy scope, effective expiry and reservation counters without becoming reviewers or gaining evidence access. Policy details omit capture, preview and Pod fields and personal result access. `can_revoke` reports current management or reviewer rights separately from `can_decide`. Policy counters are reported by policy status; a grant's remaining budget is not guaranteed collection capacity.

### SC-SHR-008

Given two managing owner teams, when the creator leaves and another current member revokes the share, then revocation succeeds and provenance still names the creator. Losing one team does not disable the other; losing both suspends dependent access. A recipient, a forged group reference or the creator on another client cannot self-approve raw sharing. Transfer does not change expiry.

### SC-SHR-011

Given a share managed by team A, when a member of A who also belongs to team B transfers management to B, then B's members manage it, A's members no longer do, creator, recipients and expiry are unchanged and the revision increases by one. A transfer to a team the caller does not belong to, or that lacks `evidence-owner` for the artifact, is refused; a non-manager's transfer is refused before any catalog read. When B is deleted from the identity provider the share stays Suspended; an administrator assigns team C, which holds `evidence-owner` inside the audience, and the share is Active again with the original creator and expiry. An administrator cannot assign a group without such an allow, a person, or a revoked share. An administrator without evidence rights lists every share without recipients and revokes another team's share; the recipient loses access at the next read and the administrator still cannot read the artifact.

## REQ-AUT-006 — Sensitive observation sessions

Raw packet rings, HTTP parsing and payload-sensitive predicates need authority before any sensitive observation, including discarded bytes; a frozen-output `maxBytes` is insufficient. Grants for these capabilities specify `observationLimits`: finite `maxSessionSeconds` (at most one hour), cumulative `maxObservedBytes`, `maxBytesPerSecond` and `maxConcurrentSessions`.

The collector enforces each session's rate and byte limits locally with a token bucket over the wire bytes entering the sensitive parser or predicate, including retransmissions. Admission reserves the session's bound, the minimum of remaining grant and policy pools and `maxBytesPerSecond × (session seconds + 1)` (the extra second is the initial burst). The collector reports the observed bytes when the session ends or, after a disconnect, on reconnect, and the hub settles both pools to that report (REQ-AUT-004). A restart of the sensor or a changed `grantRef` cannot reuse settled bytes. At exhaustion the session stops with `ObservationBudgetExhausted`; independently authorized cheap monitoring continues. A session never renews itself into unbounded approval.

Ordinary sanitized network observation still consumes administrator CPU, rate and memory budgets. Sharing maxima, snapshot storage and action starts are separate limits. Reserved and settled observation counters and reserved executions are visible in the accounting model. A raw-filter predicate on otherwise sanitized output needs the same limits.

### SC-AUT-006

Given a 16 MiB raw ring with a 1 GiB observation grant, when more than 1 GiB would enter the sensitive pipeline, then observation stops even if no snapshot was frozen. A fifteen-second session at 16 MiB/s reserves 256 MiB and, after observing 40 MiB, settles both pools to 40 MiB. Restarting the sensor cannot reuse spent bytes. Logs and other cheap context stay armed.

## Composition and syscall authorization

CaptureProfile publication grants no execution authority. Collection approval binds the resolved version and digest of every component, typed edits, expanded recipe, dependencies and aggregate budgets under [composition](capture-profiles.md). Sharing output selections resolve to actual action IDs before acceptance; several aliases never multiply a recipient grant or artifact count.

Syscall argument tracing requires the cumulative observed-event and pre-read byte limits in [syscalls](syscalls.md) before arming; missing limits cannot authorize it. Event reservations use the same reservation and settlement as observed bytes and never reset on a trace restart. Raw `syscall_query` and raw sharing need their own approvals. Metadata-only projections have a fixed no-argument schema and inherit artifact privacy and expiry.

## Approval timing by execution mode

Under [action lifecycles](action-lifecycle.md), ongoing HTTP/raw packet and syscall-argument recording requires reviewed acquisition authority before arming, covering every observation before the first trigger. A grant requested only when the incident fires cannot authorize earlier recording. OnTrigger dump, command and profile approvals authorize their bounded dispatches and never hold window preservation hostage. Previews and reviews show the two costs and activation times separately. Arming, observed bytes/events, source starts and incident saves keep separate counters; trigger cooldown and ring rotation reset none.

## Manual saves under reviewed policy authority

REQ-SAV-001–004 are a narrowly typed exception to requiring a detector occurrence for an existing policy snapshot. The policy must enable `recordingSaves` in its accepted scope. The caller's current `workload-maintainer` collection rights and the policy executor's current authority are both required; grants must cover the sensitive source and the save budget. The initiating human acquires neither that grant nor raw access. No grant can authorize a full ad hoc recipe through this route.

Manual saves have their own capture identity, digest and recorded source audience. No per-save approval is added when the reviewed capability and budgets cover it. Per-capture sharing may be requested by an eligible owner under the ordinary rules. Policy sharing instructions exclude recording-save captures.

## Live-source authorization

Approved live projections use [REQ-LIV-001](live-watch.md#req-liv-001--eligible-sources-and-current-authority): current maintainer/collection eligibility AND ordinary evidence-read entitlement under the recorded source audience, valid client and `evidence:read` scope, local live-read allowance, current source acquisition grant and no deny. A raw acquisition grant never becomes a viewer's raw-query grant. Shares, manager assignments and creator identity confer no live access. A view is authorized when it opens and reuses that authorization for at most the 60 s delivery-policy interval; revocation, a deny or the source's end reach it as a pushed event that ends the view and scrubs displayed rows. Disconnected copies are bounded by per-row expiry. There is no live sharing or raw-live approval; saving followed by artifact grants or shares is the deeper-analysis path.

Artifact raw grants also support `download_artifact` for exact existing digests under [REQ-DLD-002](artifact-downloads.md). A covering grant is reused and reserves the full native size, settled to the bytes sent. Ordinary approved artifacts need their normal reader or share entitlement and the download scope, without new approval. Collection and query-only grants never grant full raw export.

## Combined one-off investigations

[REQ-INV-001–003](investigation-approval.md) refine REQ-AUT-003/004: an adHocCapture review may carry bounded result access for selected output actions and explicitly reviewed clients of the same human. Unknown artifacts are never rawQuery targets. Exact child grants are created in the publication transaction of each matching artifact; all children spend one parent pool and include the parent's state and expiry in every effect. Capture-start exhaustion and result-access exhaustion are distinct; Denied, Revoked and Expired parents end every child. Entitlement, current clients, artifact expiry and per-operation ceilings still apply. Reviewers approve the execution digest and result-access digest together. Standalone raw and sharing reviews remain available.
