# Authorization, approvals, sharing and audit

Mechanisms follow [ADR-330](../docs/decisions/330-event-driven-system-design.md) and [ADR-335](../docs/decisions/335-usable-by-default.md): one authorization per operation reused for at most `identity.AuthorityRecheckInterval` (30 s; 60 s for the shared delivery-policy observation) and never past an original deadline ([ADR-311](../docs/decisions/311-operation-authority-recheck.md)); started streams run to their original bounds ([ADR-312](../docs/decisions/312-started-downloads-run-to-original-bounds.md)); audit is a database row; effects carry idempotency keys.

## REQ-AUT-001 — Identity and ordinary access

Human sessions use a qualified external OIDC provider or the [local identity alternative](deployment-profiles.md#req-dep-002--local-identity-without-a-second-permission-system). External sessions use OIDC code/PKCE and refresh; local identity preserves equivalent principal, assurance and revocation semantics and standard OAuth access for MCP/CLI. There is no mandatory directory-admin account or personal offline token for recurring team capture. IdP logout and external deprovisioning are distinct; login-only synchronization cannot guarantee immediate external revocation. Qualified back-channel logout may invalidate sessions; SCIM/security-event integrations are optional. Recurring execution follows [team policy automation](policy-automation.md).

Every user-facing operation resolves a principal `(issuer, subject, clientID, identityType)` from validated credentials: signature, issuer, audience, expiry/not-before and configured client binding. ID tokens are never access tokens; client-supplied groups or roles are never trusted. `azp`/`client_id` is normalized per issuer; ambiguous claims are refused. Tokens and backend errors never enter ordinary logs or responses.

Groups are the names the provider signs in the configured groups claim (`identity.groupsClaim`, default `groups`, the claim Kubernetes, Argo CD and Grafana read); Keycloak emits full group paths such as `/payments`. A group is identified by issuer and name; renaming a group in the provider changes its identity, as it does for Kubernetes OIDC. Membership is replaced on every token, including removals, and is valid until the access token expires. People are shown and selected by the username claim (`identity.usernameClaim`, default `preferred_username`); the stable `sub` stays the internal key and provenance.

The installation serves one organization. Any human who authenticates at the configured issuer through a registered client is eligible; `identity.requiredGroups` optionally restricts sign-in to members of named groups (for a realm shared with other organizations). Eligibility does not imply workload access. No tenant or organization ID exists on principals, grants, shares or artifacts. The [Keycloak profile](../docs/architecture/keycloak-profile.md) is the first supported provider.

Administrators are the groups and users named in `identity.administrators`. They enroll clusters, manage PermissionSources and ClusterAccessBindings through Kubernetes, use the configuration previews, administer shares, operate privacy workflows (REQ-PRV-006) and take ownership of retained evidence. Everyone else receives access only through AccessBindings, ClusterAccessBindings and PermissionSources ([permission management](permissions.md)); there are no further identity lists.

Each sign-in updates one row per principal in the known-principals table (issuer, subject, username, display name, groups seen). Console and MCP pickers for users and groups search it; the table is a display aid and never authorizes anything. It needs no directory credential.

Browser sessions ([ADR-060](../docs/decisions/060-bounded-browser-sessions.md)) are server-side session rows with an inactivity timeout and a maximum lifetime, encrypted server-held tokens, one-use refresh rotation and logout, following the oauth2-proxy and Grafana model. GET requests never refresh a session; `POST` refresh requires the exact origin and CSRF token. Session settings ([closed schema](contracts/browser-settings.schema.json)) come from a mounted ConfigMap, reloaded on file change or on a Helm rollout through a checksum annotation. Each session row stores the digest of the issuer, client and browser origin it was created under; a mismatch with the current settings invalidates it. A lower maximum lifetime shortens existing sessions (expiry is the minimum of the stored expiry and creation plus the current maximum); a higher one never extends them. Local sign-out and verified provider revocation work without the provider. A session-backed identity is valid until the earlier of token expiry and session expiry; downstream authorization keeps that bound. A started native download runs to its original bounds regardless of later token or session expiry ([ADR-312](../docs/decisions/312-started-downloads-run-to-original-bounds.md)).

Ordinary access is namespace/workload entitlement across enrolled clusters through [permission management](permissions.md). Clusters are named by administrators; the hub derives each cluster's internal ID from its name, so equal namespace names in different clusters confer nothing. RBAC is not inferred as an evidence ACL without a configured source. Unauthenticated errors reveal no artifact existence.

### SC-AUT-001

Given matching subject strings from two issuers or a token for another audience, when a case is queried, then the identities are not conflated and the wrong-audience token is refused before case discovery. A settings change of the issuer, client or origin invalidates existing sessions; lowering the maximum lifetime shortens them. A user removed from a group loses that group's access with the next token.

## REQ-AUT-002 — Authorization composition

A read must satisfy:

```text
valid, eligible identity AND artifact retained AND no deny
AND (ordinary evidence entitlement OR active EvidenceShare coverage)
AND required OAuth scope
AND (if raw: active raw grant OR equivalent Kubernetes right on the workload)
AND remaining query/output budget AND audit row writable
```

Ordinary entitlement uses the role and recorded-audience rules in [permission management](permissions.md); `evidence-reader` alone confers no raw eligibility. A scope alone is never a grant. A share is never a capture permission; a raw share carries the raw grants its approval created (REQ-SHR-002). Deny wins over all. Group shares use current membership; raw grants stay bound to the calling principal.

The equivalent Kubernetes right is decided by a SubjectAccessReview of the caller in the artifact's cluster, through the same identity mapping as exec inheritance ([REQ-PER-004](permissions.md#req-per-004--exec-based-and-generic-kubernetes-inheritance)): `create pods/exec` on a current Pod of the artifact's recorded workload covers raw packets, syscall arguments, cores and memory; `create pods/portforward` or `get pods/proxy` covers runtime profiles. A caller holding it reads and downloads that raw evidence without a review; budgets, deadlines, denies and audit still apply.

An operation authorizes once at its start, before any evidence lookup, and carries the result as an `Authority{validUntil}` value: the earliest of check time plus the recheck interval and every original hard end. SQL effect statements include `now() < validUntil` and the relevant revocation predicates (share, grant, restriction state) in their `WHERE` clause; there are no per-helper rechecks. The ordinary evaluator's success cannot substitute for accepted execution, local ceilings, grant/share conditions or the effect statement. Its matching bindings describe the caller, not the full audience of a capture.

### SC-AUT-002

Given a user with a valid raw grant but no ordinary entitlement or share, when memory is requested, then access is refused. An extract-only share does not permit raw access. A maintainer who holds `create pods/exec` on the workload downloads its core without a review; after the exec right is removed the next download is refused.

## REQ-AUT-003 — Individual and policy grants

`AccessGrant` distinguishes artifact queries, automatic policies and individual captures. Raw grants bind existing artifact digests and operations. Policy grants bind the policy, execution digest, workload/recipe scope and finite future budgets. Ad hoc grants bind one accepted capture UID and its execution digest. [Execution identity](execution.md) defines digest separation; unknown future artifacts are never raw-query targets.

Manual intrusive collection needs exactly one independent approval: a distinct authenticated human holding `action-approver` for the target. A raw-query request by a caller without the equivalent Kubernetes right (REQ-AUT-002) needs the same. No second person is needed for evidence collected by an accepted policy, for reads and downloads under the equivalent Kubernetes right, or for read-only diagnostics such as a pprof GET. An approval cannot widen the requester's entitlement.

Step-up re-authentication is optional and off by default. When an administrator sets `approvals.stepUp` (`acrValues`, `maxAgeSeconds`), approving additionally requires the access token's signed `acr` to be one of those values and `auth_time` at most `maxAgeSeconds` old; step-up is verified from IdP assurance or server-verified local authentication (REQ-DEP-002), never a UI checkbox.

Grant lifetimes: a review stays decidable while its request is unchanged, until the request's `notAfter` (default 24 hours). A raw-query grant and a capture's result access last until their `notAfter`, which defaults to the access end of the covered evidence. A policy grant lasts `approvals.policyGrantSeconds` (default 90 days); an approver renews it in place, which keeps the grant, its counters and its policy link and sets a new expiry. Administrators set the maxima (up to 365 days); narrower local maxima win; expiry beyond the effective maximum is refused and never self-renews. Lowering a maximum clamps existing grants from their original issue time; raising it never extends them. Grant ownership cannot be transferred.

A recurring-policy grant records the policy and its approver and separately binds `policyExecutor` and `policyAuthority`. Its approver is any current `action-approver` for the target; automation identities cannot approve. The grant confers no personal result access, raw query, download or sharing; an author's departure does not invalidate team authority.

The approval page shows exact scope and impact, supports approve/deny/revoke and renew, protects against CSRF and clickjacking, and records requester and approver issuer/subject/client, optional comment, authentication context and digest. A review request carries the requester's reason, which the approver sees; the approver's comment is optional.

Packet and syscall plans that need review (a raw-byte filter predicate, or every recording when `approvals.requireRecordingApproval` is set) are individual grants ([ADR-249](../docs/decisions/249-sensitive-acquisition-grants.md)). `request_capture` stores the exact plan and opens one review bound to its capture UID, execution digest, data class, reasons, requesting human and `notAfter`; it returns `ApprovalRequired` with the review link. `decide_review` requires a distinct human with a current, undenied `action-approver` allow for the target. Approval submits the stored request itself: the approval transaction admits the plan against its exact target under the requester's current entitlement, and the capture starts without further action from the requester. If the exact Pod no longer exists or no longer fits the plan, the request ends `TargetChanged` and the requester previews again. Denial and `revoke_grant` (requester or current approver) only restrict and never need step-up. `get_grant` shows the plan to the requester or a current approver only.

### SC-AUT-003

Given a raw or capture request, when its requester attempts approval through another client under the same identity, then self-approval is refused. When a distinct approver approves at 02:00, the capture starts at 02:00 without the requester returning. On a default installation without step-up settings an approver approves with an ordinary session. A policy grant renewed before its expiry keeps the same grant and policy link; an accepted policy runs approved automatic actions until its grant expires; a changed recipe requires review again.

## REQ-AUT-004 — Budgets, reservations and revocation

Each execution or query reserves its grant bytes and counts in one hub SQL transaction together with [capacity](capacity.md) before it starts. A reservation has a unique operation ID (idempotency key), bounds and state. A retry with the same ID returns the existing reservation; it never starts the action again. Counters are per grant and change with conditional updates. When the outcome is known (started or not, bytes and operations used), the reservation is settled to actual usage and the remainder is released. Connectors and collectors report outcomes when the work ends or, after a disconnect, when they reconnect; only a reservation with no report by the grant's hard end is charged in full ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D7).

`maxExecutions` counts individual authorized action starts for capture grants and individual query operations for raw-query grants. A recipe with three intrusive actions consumes three executions; extra process fanout adds one per actual start. Each action reserves its worst-case bytes before it starts; the UI shows action count and maximum bundle cost. Grant counters are independent of capacity reservations; both must succeed.

Query concurrency defaults to 4 per principal and 32 per installation (storm protection, a maintainer decision; each running query holds reader memory and CPU). At a limit, reject or queue within a bounded deadline.

Collection is admitted once per source start under one permission snapshot and bounded by every hard end (grant, policy, binding, local ceiling). A budget slice delegated to a connector lives in the connector's memory and is settled through the same outcome reports; Kubernetes objects are never counters. Work and its admission travel over the connector's authenticated hub connection (ADR-334) and need no signatures.

Revocation refuses new reservations, admissions, cursors and share-dependent reads as soon as it commits. Running sources receive a pushed stop over the connector connection; a source whose connector is disconnected runs to its admitted hard end, and the stop is delivered when the connection returns if that end has not passed. Started downloads run to their original bounds (ADR-312). A started upload may finish without new acquisition while the artifact's deadlines allow. A query is one operation: it is authorized at its start and refused at its next start after revocation.

### SC-AUT-004

Given two simultaneous raw requests sharing a 64 KiB remaining budget, when each asks for 64 KiB, then at most one reservation succeeds. A controller crash after dispatch cannot make the same intrusive action run twice: the retry with the same operation ID finds the existing reservation. When the connector reconnects and reports that the action never started, the reservation is released. Revocation refuses the next query and stops the running source.

## REQ-SHR-001 — Explicit evidence sharing within the organization

A user holding `evidence-owner` or `workload-maintainer` on the workload, with the `evidence:share` client scope (a default scope of the console and bundled MCP clients), may create an `EvidenceShare` that grants named users or groups access despite their ordinary ACL. Creation requires current access to each included artifact; receiving a share never confers sharing authority.

A share binds an explicit snapshot of artifact versions (each a published artifact at its verified version), one or more user or group recipients of the installation's issuer picked by name, allowed data classes and operations, optional reason, the immutable creator, its management (REQ-SHR-008) and expiry. Expiry defaults to, and never exceeds, the artifact's access end. Future recurrences, artifacts and extracts are excluded; extending a snapshot is a new decision. Capture-time and policy sharing instructions (REQ-SHR-004/005) create ordinary concrete shares at publication, never an open-ended subscription. No anonymous link capability exists; URLs are authenticated navigation links. A share also grants the recipient the native download of exactly the shared versions with the `evidence:download` scope ([ADR-233](../docs/decisions/233-recipient-native-download.md)), charged to the workload's transfer allocation.

Recipients are users or groups of the configured issuer; eligibility is enforced at every use. An identity of another issuer, one refused by `identity.requiredGroups`, or evidence of another installation is refused.

A share is evaluated after the ordinary evaluator refuses and before any evidence lookup; current denies win. State is derived at read time: Active, Expired, Revoked, Suspended.

### SC-SHR-001

Given a developer without the payments workload ACL, when an owner picks that user's group by name and shares two existing stack extracts with it, then the user can query those extracts. A later occurrence and an unshared file stay inaccessible. A recipient from another issuer is refused even if the creator is an administrator.

### SC-SHR-009

Given a published pod-status artifact and an eligible user named by no AccessBinding, when the user calls `get_case`, then it is refused exactly like an absent case. When an evidence owner shares that artifact with the user, the user's `get_case` returns only that artifact with access `shared` and the user can prepare and Range-download its native file. After revocation, the next `get_case`, `download_artifact(action=prepare)` and content request are refused; a started response runs to its original bounds. A current deny of the user or share expiry refuses as well. When every managing team loses its owner role the share is Suspended; when a managing team holds it again the share is Active again.

## REQ-SHR-002 — Shared view and raw access

Discovery projects a minimal shared case view: permitted case ID and title, authorized timeline entries, artifacts and available operations. Hidden artifact names or counts, other cases, workload inventory, labels and facets are never exposed through counts, pagination or error differences. Cursors bind principal, share IDs and query snapshot.

Sharing raw evidence needs one review by an independent `action-approver`. Its approval creates, for each recipient, raw grants bound to the shared artifact versions, the approved operations, the share's expiry and one disclosure pool; recipients need no review of their own. Extract shares need no review. The approval page shows the share and the raw operations together.

### SC-SHR-002

Given a shared case with one visible extract and three hidden artifacts, when the recipient lists, searches, paginates or guesses IDs, then no hidden count, name or existence is disclosed. A raw share awaiting review returns `ApprovalRequired`; once approved, the recipient runs exactly the approved raw operations on the shared versions and nothing else.

## REQ-SHR-003 — Revocation and group freshness

Current managers (REQ-SHR-008), the creator and administrators can revoke at once. Artifact expiry, loss of eligibility, an explicit deny and share expiry end access regardless of cached results. Group membership comes from the current access token; a stale token cannot extend it past its expiry.

Evidence already seen by a recipient or agent cannot be clawed back. Creation, approval, recipient access, scope changes, expiry and revocation write audit rows. No share operation sends chat or email notifications.

### SC-SHR-003

Given a recipient with a valid cursor, when the share is revoked, then the next page is refused. Removal from a shared group stops new disclosure when the recipient's current access token expires.

## REQ-SHR-004 — Share results when requesting collection

A user with sharing authority (REQ-SHR-001) may include `sharing` in a capture request (`preview_capture`/`request_capture`, DebugCapture `spec.sharing`). It names one or more recipients of the installation's issuer, optionally the outputs and an absolute `notAfter`. It applies only to that capture UID and its resolved plan. Omission means no sharing; the ordinary audience is unchanged. Collection still requires collection rights, approvals and capacity independently of sharing.

Default outputs are the recipe's administrator-approved metadata and extract outputs; raw outputs are never included by default. Explicit `outputs` name action IDs from the compiled plan; unknown actions fail validation, and raw outputs need raw-sharing review (REQ-SHR-006). The basic path asks only for recipients; the reason defaults to the capture reason.

Sharing authority is checked in the admission transaction; without it the whole request is refused before execution (`SharingNotPermitted`). The accepted capture carries one immutable sharing instruction: recipients, outputs, end, creator and management. There is no separate intent record. The browser's "Share results with…" section and MCP `request_capture` use the same evaluator; MCP needs `evidence:share` when sharing is present.

At publication, the catalog transaction creates one ordinary EvidenceShare for each published artifact whose recorded capture UID and action ID match the instruction ([ADR-235](../docs/decisions/235-capture-time-sharing.md)), provided a managing team or the personal creator still holds sharing authority and the end has not passed; the unique key (capture UID, artifact) makes replay create nothing more. Share expiry is the earlier of `notAfter` (default: the artifact's access end) and the artifact's access end. Full manager, deny and recipient checks run at every read. When no share can be created the capture still publishes; `get_capture` reports `sharing.state` (`Pending`, `Shared` with share IDs, `SharingUnavailable`) separately from collection.

### SC-SHR-004

Given an owner requests a capture with an incident-response group and no explicit outputs, when collection and the approved extract finish, then only metadata and extract outputs become shared. The group cannot see raw logs or another capture. A caller with collection permission but no sharing authority cannot attach the instruction.

### SC-SHR-010

Given a user with sharing authority and `evidence:share` who reviews a pod-status capture with one recipient, when the request is accepted and the capture publishes, then exactly one share of the published artifact exists, a replayed publication creates no other, `get_capture` reports `Shared`, and the recipient's `get_case` returns the artifact with access `shared`. A requester without sharing authority is refused before any capture exists. If the end passes before publication, the capture publishes without a share and reports `SharingUnavailable`.

## REQ-SHR-005 — Explicit sharing of recurring policy results

A DebugPolicy may include `spec.sharing` with an absolute `notAfter` (default 90 days after acceptance) and an optional `futureCaptures.maxCaptures` ([ADR-239](../docs/decisions/239-recurring-policy-sharing.md)). Recurring sharing is explicitly bounded because the maintainer requires it; there is no "all future evidence" option, no separate upper limit and no weekly renewal. The instruction takes effect when the policy generation is accepted ([team policy automation](policy-automation.md)) and a sponsoring group of its automation binding holds sharing authority on the workload; those groups are its management. The policy is recorded as the instruction's creator. Policy status shows recipients, maximum captures and end. A capture-action approval is not a sharing approval; raw outputs always need raw-sharing review.

The policy acceptance carries the instruction and a counter. Each admitted capture of that acceptance claims one slot in its admission transaction, while under both limits, the policy generation unchanged since acceptance and sharing not stopped or revoked; the capture receives a capture instruction that publication turns into ordinary shares (REQ-SHR-004). A capture admitted without a slot is unshared and never backfilled. Sharing never blocks an otherwise authorized capture and never overrides storm or resource limits. Each capture gets its own concrete shares; a shared case view never includes other occurrences merely because they correlate.

A new policy generation stops claims for the old acceptance; its own acceptance has its own counter and no backfill. `stop_future_sharing` (`sharing_intent_id` = the acceptance ID) stops further claims while already claimed captures still publish; existing shares stay. State is derived: active, limitReached, expired, stopped, policyChanged, revoked; `get_policy_status` reports it, its revision and the captures shared.

### SC-SHR-005

Given an accepted policy instruction limited to ten captures and ending at 18:00, when capture ten is admitted and its extract publishes at 17:50, then it is shared. Capture eleven, an old occurrence and a capture under a changed generation are excluded. An extract published after 18:00 is not shared, and a restart does not renew the end or the counter.

### SC-SHR-012

Given an accepted policy whose sharing allows three captures, when four captures are admitted, the last two by a restarted hub, then the first three are shared and the fourth is not, and the counter stays three. After an edit, captures are unshared until the new generation is accepted, whose acceptance shares only later captures. Revoke-all of the first acceptance revokes exactly its shares and leaves the new acceptance's shares active. After a manager stops a third acceptance's sharing, its already claimed capture still publishes a share and the next capture is unshared. A sharing instruction whose sponsoring groups hold no sharing authority never takes effect.

## REQ-SHR-006 — Concrete publication and approval boundaries

Publication shares an artifact only when its recorded capture UID matches the instruction's capture, its action ID is one of the selected outputs, its classification matches the selected output class and it is committed and verified. Provenance comes from the capture UID and action ID the producer recorded on the artifact, never from labels, client case IDs or graph traversal. Mixed-capture comparisons, recipient query results, newly requested analyses and changed projections never qualify. No eligible output gives `NoEligibleOutputs`, never a share of the raw fallback.

Shares created by publication are ordinary EvidenceShare rows with concrete artifact versions, their origin (acceptance or capture, artifact), creator, management, operations and expiry; they never include future artifacts or allow resharing. The unique key (origin, artifact) makes retries idempotent and prevents recreating a revoked share. Shares never copy evidence and never extend retention.

Raw outputs are approved separately from metadata and extract outputs: owner-selected extracts may publish while raw selections await review. The one raw-sharing approval binds the digest of the instruction (outputs, recipients, plan, limits, end); one reviewed recurring decision may cover those future outputs within its limits. At publication of each matching raw artifact, the same transaction creates the recipients' raw grants for that exact artifact version (REQ-SHR-002); none exists for an unpublished artifact. Approval must be valid at publication; its revocation ends dependent shares and grants.

### SC-SHR-006

Given a capture with an extract output and a pending raw-core output, when artifacts publish, then the extract becomes visible and the core stays unshared until raw-sharing approval. An artifact of another capture or action, or a publication after revocation, is not shared. Replaying a publication creates one share. A recipient of an approved raw core share runs only the approved operations on that core.

## REQ-SHR-007 — Stop, revoke and explain automatic sharing

Any current manager (REQ-SHR-008), the creator or an administrator can Stop future sharing or Revoke the instruction and its shares. Stop prevents new claims; already claimed captures still publish before the end; existing shares stay until their own expiry or revocation. Cancelling a single capture does not retract evidence already shared; the UI offers explicit revocation.

Revoke-all is `revoke_share` with `sharing_intent_id` (the acceptance or capture ID) and the expected revision: one update by origin revokes exactly that instruction's shares and stops its pending and future captures from being shared. Independently granted access and unrelated shares are unaffected. A revoked share is never recreated. Revocation is terminal; a GitOps reapply of the same generation cannot resurrect it. Policy suspension, deletion or a new generation stops claims without revoking earlier shares; the console and policy status say so and offer revoke-all.

The UI shows recipients, selected outputs, end, captures shared and remaining, outputs shared, pending or blocked, approval state and whether Stop or Revoke was chosen. Recipients discover a case only after a concrete artifact is shared. No outbound notifications or exports are added. `list_shares` shows owned instructions and share origins; received views stay concrete-artifact-only. `revoke_share` never changes capture authority or approves raw access.

### SC-SHR-007

Given an owner revokes an instruction while a late extract publishes, when publication retries or a recipient follows an old cursor, then nothing is disclosed. A revoked share is not recreated on replay. Stopping a recurring instruction lets already claimed captures publish while blocking new claims; revoking it ends every dependent share.

## REQ-AUT-005 — Durable audit

Every admitted authenticated `tools/call`, UI/API evidence access, grant/share mutation, intrusive action start and authorization denial writes one append-only audit row in the same PostgreSQL transaction as its effect ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D6). If the row cannot be written, the operation fails: no evidence is disclosed and no intrusive action starts. This follows Vault's fail-closed audit ([Vault audit devices](https://developer.hashicorp.com/vault/docs/audit)). Operations without a database effect (a read) write their row before returning output. A row records principal, normalized operation, keyed argument digest, case/artifact/share/grant IDs, decision and reason code, reservation ID, output size and digest and trace ID; never raw arguments, tokens, matched log contents, memory or packet fields. Predictable secret arguments use a keyed digest.

Invalid credentials and pre-admission overload do not get individual rows; bounded counters and security logs record them. After admission, a scope denial, invalid input or unknown tool is audited. If the client disconnects after the result was committed, the row records delivery unknown. Background capture may keep already observed encrypted data while recording an audit gap, but never manufactures an approval.

The audit table is partitioned by time. Rows are exported in sealed batches to the object store or a SIEM, optionally under Object Lock ([Kubernetes audit backends](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)). Retention drops whole partitions past the audit retention policy and expires exported batches by object-store lifecycle rules ([PostgreSQL partitioning](https://www.postgresql.org/docs/current/ddl-partitioning.html)). Ordinary object storage is not immutable against an administrator. Kubernetes audit records permission configuration changes.

### SC-AUT-005

Given a completed query result, when the audit insert fails, then no result is sent. Retrying a mutation with its idempotency key returns the original outcome and its audit row; each new invocation gets a new request ID. No user-managed idempotency key is required for ordinary reads.

## REQ-SHR-008 — Multiple owner teams and immutable creators

Several groups may hold `evidence-owner` or `workload-maintainer` for one workload through AccessBindings, ClusterAccessBindings or PermissionSources; both roles carry sharing authority. Owner is a sharing and reading role, not collection permission. A share or instruction records the immutable `createdBy` from authenticated submission (or the policy, REQ-SHR-005) and `management`: either the creator or 1–8 owner groups by name. No member list is copied. The creator is never replaced by a controller, a group or the last editor.

`management` defaults to the creator's groups that currently hold sharing authority covering the artifact inside its recorded audience ([ADR-232](../docs/decisions/232-concrete-evidence-share.md)); more than eight are refused with `ManagementTooBroad`, never truncated. A creator without such a group manages personally. `create_share` accepts `management: {mode: teams}` naming groups the creator belongs to that hold sharing authority inside the audience, or `mode: creator`; anything else is refused with `ManagementNotHeld` ([ADR-238](../docs/decisions/238-share-management-transfer.md)). An administrator who may share can name any group that currently holds an undenied sharing-authority allow covering the artifact inside its audience; the audience is never widened. An exec inheritance source supplies no ownership; an access-review source mapped to `evidence-owner` does.

A current manager is a human with `evidence:share` who belongs to a managing group that currently holds an undenied sharing-authority allow covering the artifact. Membership changes within that group keep management, so a share survives its creator's departure. Managers list (`list_shares(view=owned)`, with `revision`, `created_by`, `managed_by`; received rows stay minimal), stop and revoke without fresh approval. The creator can always revoke. A share is Suspended while no managing group holds such an allow and becomes Active again when one does. Management never supplies artifact-read or raw-query rights and never widens an audience or confers resharing. A management view shows names, expiry and controls, not hidden evidence, other recipients or team membership.

`transfer_share(share_id, expected_revision, idempotency_key, management)` lets a current manager replace the managing groups with groups they belong to under the same rules (`mode: creator` only for the creator); an administrator may assign current owner groups, which also resumes a share whose managing groups no longer exist. Transfers write an audit row, add one revision and never change creator, recipients, artifacts or expiry. Revoked or expired shares are never transferred. An administrator may `revoke_share` any share without evidence rights; it grants no read. `list_shares(view=administration, limit, cursor)` (pages of at most 100, so a page fits the 64 KiB MCP response bound) lists every share for administrators, newest first, with IDs, phase, expiry, revision, `created_by` and `managed_by`, never recipients or evidence. For recurring policies, managers of a new generation are set by its new acceptance.

Raw-sharing review always needs a human distinct from the requester or creator, even within one managing team or across clients. An `action-approver` of a managing team may approve another person's request; co-ownership is not approval. Grant requester bindings are not transferable.

UI and MCP `list_shares(view=owned)` include manageable personal and team shares and instructions, not everything the caller can read. "Created by" and "Managed by" are shown separately to managers. Selecting managing teams is optional. See the [two-team binding](../examples/access-binding-owners.yaml).

Policy grant details ([ADR-259](../docs/decisions/259-policy-grants-and-observation-spend.md)) let current members of a sponsoring group inspect the original workload and policy scope, effective expiry and reservation counters without becoming reviewers or gaining evidence access. Policy details omit capture, preview and Pod fields and personal result access. `can_revoke` reports current management or reviewer rights separately from `can_decide`. Policy counters are reported by policy status; a grant's remaining budget is not guaranteed collection capacity.

### SC-SHR-008

Given two managing owner teams, when the creator leaves and another current member revokes the share, then revocation succeeds and provenance still names the creator. Losing one team does not disable the other; losing both suspends dependent access. A recipient, a forged group reference or the creator on another client cannot self-approve raw sharing. Transfer does not change expiry.

### SC-SHR-011

Given a share managed by team A, when a member of A who also belongs to team B transfers management to B, then B's members manage it, A's members no longer do, creator, recipients and expiry are unchanged and the revision increases by one. A transfer to a team the caller does not belong to, or that lacks sharing authority for the artifact, is refused; a non-manager's transfer is refused before any catalog read. When B is deleted from the identity provider the share stays Suspended; an administrator assigns team C, which holds sharing authority inside the audience, and the share is Active again with the original creator and expiry. An administrator cannot assign a group without such an allow, a person, or a revoked share. An administrator without evidence rights lists every share without recipients and revokes another team's share; the recipient loses access at the next read and the administrator still cannot read the artifact.

## REQ-AUT-006 — Sensitive observation sessions

Raw packet rings, HTTP parsing and payload-sensitive predicates need authority before any sensitive observation, including discarded bytes; a frozen-output `maxBytes` is insufficient. Grants for these capabilities specify `observationLimits`: `maxBytesPerSecond`, `maxConcurrentSessions` and, for finite sessions, `maxSessionSeconds`. An always-on recorder admitted under an accepted policy is bounded by its rate and ring size, not by a lifetime byte total ([ADR-335](../docs/decisions/335-usable-by-default.md) D6); a manual or onTrigger session also carries a cumulative `maxObservedBytes`.

The collector enforces each session's rate and byte limits locally with a token bucket over the wire bytes entering the sensitive parser or predicate, including retransmissions. Admission of a finite session reserves its bound, the minimum of remaining grant and policy pools and `maxBytesPerSecond × (session seconds + 1)` (the extra second is the initial burst). The collector reports the observed bytes when the session ends or, after a disconnect, on reconnect, and the hub settles both pools to that report (REQ-AUT-004). A restart of the sensor or a changed grant cannot reuse settled bytes. At exhaustion the session stops with `ObservationBudgetExhausted`; independently authorized cheap monitoring continues. A finite session never renews itself into unbounded approval.

Ordinary sanitized network observation still consumes administrator CPU, rate and memory budgets. Sharing maxima, snapshot storage and action starts are separate limits. Reserved and settled observation counters and reserved executions are visible in the accounting model. A raw-filter predicate on otherwise sanitized output needs the same limits.

### SC-AUT-006

Given a 16 MiB raw ring with a 1 GiB observation grant for a manual session, when more than 1 GiB would enter the sensitive pipeline, then observation stops even if no snapshot was frozen. A fifteen-second session at 16 MiB/s reserves 256 MiB and, after observing 40 MiB, settles both pools to 40 MiB. Restarting the sensor cannot reuse spent bytes. Logs and other cheap context stay armed.

## Composition and syscall authorization

CaptureProfile publication grants no execution authority. Collection approval binds the resolved version and digest of every component, typed edits, expanded recipe, dependencies and aggregate budgets under [composition](capture-profiles.md). Sharing output selections resolve to actual action IDs before acceptance; several aliases never multiply a recipient grant or artifact count.

Syscall argument tracing requires the observed-event and pre-read byte limits in [syscalls](syscalls.md) before arming; missing limits cannot authorize it. Event reservations use the same reservation and settlement as observed bytes and never reset on a trace restart. Raw `query_artifact(operation=syscalls)` follows REQ-AUT-002 and raw sharing REQ-SHR-002. Metadata-only projections have a fixed no-argument schema and inherit artifact privacy and expiry.

## Approval timing by execution mode

Under [action lifecycles](action-lifecycle.md), ongoing HTTP/raw packet and syscall-argument recording requires reviewed acquisition authority before arming, covering every observation before the first trigger. A grant requested only when the incident fires cannot authorize earlier recording. OnTrigger dump, command and profile approvals authorize their bounded dispatches and never hold window preservation hostage. Previews and reviews show the two costs and activation times separately. Arming, observed bytes/events, source starts and incident saves keep separate counters; trigger cooldown and ring rotation reset none.

## Manual saves under reviewed policy authority

REQ-SAV-001–004 are a narrowly typed exception to requiring a detector occurrence for an existing policy snapshot. The policy must enable `recordingSaves` in its accepted scope. The caller's current `workload-maintainer` collection rights and the policy executor's current authority are both required; grants must cover the sensitive source and the save budget. The initiating human acquires neither that grant nor raw access. No grant can authorize a full ad hoc recipe through this route.

Manual saves have their own capture identity, digest and recorded source audience. No per-save approval is added when the reviewed capability and budgets cover it. Per-capture sharing may be requested by a user with sharing authority under the ordinary rules. Policy sharing instructions exclude recording-save captures.

## Live-source authorization

Approved live projections use [REQ-LIV-001](live-watch.md#req-liv-001--eligible-sources-and-current-authority): ordinary evidence-read entitlement under the recorded source audience, valid client and `evidence:read` scope and a CollectionCeiling that allows live reads; no collection entitlement is needed (ADR-335 D5). The source needs a current acquisition grant and no deny. A raw acquisition grant never becomes a viewer's raw-query grant. Shares, manager assignments and creator identity confer no live access. A view is authorized when it opens and reuses that authorization for at most the 60 s delivery-policy interval; revocation, a deny or the source's end reach it as a pushed event that ends the view and scrubs displayed rows. Disconnected copies are bounded by per-row expiry. There is no live sharing or raw-live approval; saving followed by artifact grants or shares is the deeper-analysis path.

Artifact raw grants and the equivalent Kubernetes right (REQ-AUT-002) also support `download_artifact` for exact existing digests under [REQ-DLD-002](artifact-downloads.md). A covering grant is reused and reserves the full native size, settled to the bytes sent. Ordinary approved artifacts need their normal reader or share entitlement and the download scope, without new approval. Collection and query-only grants never grant full raw export.

## Combined one-off investigations

[REQ-INV-001–003](investigation-approval.md) refine REQ-AUT-003/004: an adHocCapture review may carry bounded result access for selected output actions, usable from every client of the requesting human. Unknown artifacts are never rawQuery targets. Exact child grants are created in the publication transaction of each matching artifact; all children spend one parent pool and include the parent's state and expiry in every effect. Capture-start exhaustion and result-access exhaustion are distinct; Denied, Revoked and Expired parents end every child. Entitlement, artifact expiry and per-operation ceilings still apply. Reviewers approve the execution digest and result-access digest together. Standalone raw and sharing reviews remain available.
