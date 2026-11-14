# Authorization, approvals, sharing and audit

Mechanisms follow [ADR-330](../docs/decisions/330-event-driven-system-design.md) and [ADR-335](../docs/decisions/335-usable-by-default.md): one authorization per operation, reused for at most `identity.AuthorityRecheckInterval` (30 s; 60 s for the shared delivery-policy observation) and never past an original deadline ([ADR-311](../docs/decisions/311-operation-authority-recheck.md)); started streams run to their original bounds ([ADR-312](../docs/decisions/312-started-downloads-run-to-original-bounds.md)); audit is a database row; effects carry idempotency keys.

## REQ-AUT-001 — Identity and ordinary access

Human sessions use an external OIDC provider (code/PKCE and refresh) or the [local identity alternative](deployment-profiles.md#req-dep-002--local-identity-without-a-second-permission-system), which offers the same principal and revocation semantics and standard OAuth access for MCP/CLI. No directory-admin account or personal offline token is needed; recurring capture follows [team policy automation](policy-automation.md). Back-channel logout is optional.

Every operation resolves a principal `(issuer, subject, clientID, identityType)` from a validated access token: signature, issuer, audience, expiry and configured client. ID tokens are never access tokens; client-supplied groups or roles are never trusted; ambiguous `azp`/`client_id` claims are refused. Tokens never enter logs or responses.

Groups are the names in the configured groups claim (`identity.groupsClaim`, default `groups`), identified by issuer and name, as in Kubernetes OIDC. Membership comes from each token and holds until it expires. People are shown by `identity.usernameClaim` (default `preferred_username`); `sub` is the internal key.

The installation serves one organization; there is no tenant or organization ID. Any human who signs in through a registered client is eligible; `identity.requiredGroups` optionally restricts sign-in. Eligibility confers no workload access. The [Keycloak profile](../docs/architecture/keycloak-profile.md) is the first supported provider.

Administrators are the groups and users in `identity.administrators`. They manage PermissionSources and ClusterAccessBindings through Kubernetes, use the configuration previews, administer shares, operate privacy workflows (REQ-PRV-006) and take ownership of retained evidence. Everyone else gets access only through [permission management](permissions.md).

Each sign-in upserts one known-principals row (issuer, subject, username, display name, groups seen). Pickers search it; it authorizes nothing.

Browser sessions ([ADR-060](../docs/decisions/060-bounded-browser-sessions.md)) are server-side rows with an inactivity timeout, a maximum lifetime, server-held tokens, one-use refresh rotation and logout, as in oauth2-proxy and Grafana. GET never refreshes; `POST` refresh requires the exact origin and the CSRF token. Settings ([schema](contracts/browser-settings.schema.json)) come from a mounted ConfigMap. A session created under another issuer, client or origin is invalid; a lower maximum lifetime shortens existing sessions and a higher one never extends them. A session identity is valid until the earlier of token and session expiry; a started native download runs to its original bounds (ADR-312).

Ordinary access is namespace/workload entitlement across clusters through [permission management](permissions.md). Equal namespace names in different clusters confer nothing. Unauthenticated errors reveal no artifact existence.

### SC-AUT-001

Given matching subject strings from two issuers or a token for another audience, when a case is queried, then the identities are not conflated and the wrong-audience token is refused before case discovery. A settings change of the issuer, client or origin invalidates existing sessions; lowering the maximum lifetime shortens them. A user removed from a group loses that group's access with the next token.

## REQ-AUT-002 — Authorization composition

A read must satisfy:

```text
valid, eligible identity AND artifact retained AND no deny
AND (ordinary evidence entitlement OR active EvidenceShare coverage)
AND required OAuth scope
AND (if raw: raw grant OR approved raw share OR equivalent Kubernetes right on the workload)
AND remaining query/output budget AND audit row writable
```

Ordinary entitlement follows the roles and recorded audiences in [permission management](permissions.md); `evidence-reader` alone confers no raw access. A scope alone is never a grant and a share is never a capture permission. Deny wins over all. Raw grants are bound to one principal.

The equivalent Kubernetes right is a SubjectAccessReview of the caller in the artifact's cluster, with the identity mapping of [REQ-PER-004](permissions.md#req-per-004--exec-based-and-generic-kubernetes-inheritance): `create pods/exec` on a current Pod of the recorded workload covers raw packets, syscall arguments, cores and memory; `create pods/portforward` or `get pods/proxy` covers runtime profiles. Its holder reads and downloads that raw evidence without a review; budgets, denies and audit still apply.

An operation authorizes once, before any evidence lookup, and carries `Authority{validUntil}`: the earliest of check time plus the recheck interval and every original hard end. Effect statements include `now() < validUntil` and the share, grant and restriction predicates in their `WHERE` clause.

### SC-AUT-002

Given a user with a valid raw grant but no ordinary entitlement or share, when memory is requested, then access is refused. An extract-only share does not permit raw access. A maintainer who holds `create pods/exec` on the workload downloads its core without a review; after the exec right is removed the next download is refused.

## REQ-AUT-003 — Individual and policy grants

An `AccessGrant` is one of: `rawQuery` (existing artifact digests and operations), `adHocCapture` (one capture UID and its execution digest) or `policy` (one policy, its execution digest and workload/recipe scope). [Execution identity](execution.md) defines the digests; unknown future artifacts are never raw-query targets.

Manual intrusive collection needs exactly one independent approval: an authenticated human, distinct from the requester, holding `action-approver` for the target. A raw query by a caller without the equivalent Kubernetes right needs the same. No second person is needed for evidence collected by an accepted policy, for reads under the equivalent Kubernetes right, or for read-only diagnostics such as a pprof GET. An approval cannot widen the requester's entitlement; automation identities never approve.

Step-up is optional and off by default. When `approvals.stepUp` (`acrValues`, `maxAgeSeconds`) is set, approving requires the token's signed `acr` among those values and `auth_time` within `maxAgeSeconds`.

A review stays decidable until its request changes, the requester cancels it or an optional requester-set `notAfter` passes (ADR-335 D9). Raw-query and result access last until their `notAfter`, defaulting to the access end of the covered evidence. Policy grants and their renewal follow [team policy automation](policy-automation.md#approval-of-automatic-intrusive-actions). Lowering an administrator maximum clamps existing grants from their issue time; raising it never extends them. Grants are not transferable.

The approval page shows exact scope and impact, the requester's reason and the plan; it supports approve, deny, revoke and renew and is protected against CSRF and clickjacking. The grant records requester, approver, optional comment, authentication context and digest.

Packet and syscall plans with a raw-byte filter predicate, or every recording when `approvals.requireRecordingApproval` is set, need an individual grant ([ADR-249](../docs/decisions/249-sensitive-acquisition-grants.md)). `request_capture` stores the exact plan, opens one review and returns `ApprovalRequired` with its link. Approval submits the stored request itself: the approval transaction admits the plan against its exact target under the requester's current entitlement, and the capture starts without the requester. If the Pod is gone or no longer fits, the request ends `TargetChanged`. Deny and `revoke_grant` (requester or current approver) never need step-up. `get_grant` shows the plan to the requester or a current approver.

### SC-AUT-003

Given a raw or capture request, when its requester attempts approval through another client under the same identity, then self-approval is refused. When a distinct approver approves at 02:00, the capture starts at 02:00 without the requester returning. On a default installation without step-up settings an approver approves with an ordinary session. A policy grant renewed before its expiry keeps the same grant and policy link; an accepted policy runs approved automatic actions until its grant expires; a changed recipe requires review again.

## REQ-AUT-004 — Budgets, reservations and revocation

Each execution or query reserves its grant bytes and counts together with [capacity](capacity.md) in one SQL transaction before it starts. A reservation has an operation ID (idempotency key); a retry with the same ID returns it and never starts the action again. When the outcome is known, the reservation settles to actual usage. Connectors report outcomes when work ends or on reconnect; only a reservation with no report by the grant's hard end is charged in full ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D7).

An ad hoc capture grant covers the action starts of its approved plan (three intrusive actions allow three starts; process fanout adds one per actual start). A raw-query grant's `maxExecutions` counts query operations. Grant counters and capacity reservations must both succeed.

Query concurrency follows reader capacity: `readerReplicas × floor(readerMemoryRequest / perQueryScanBuffer)`, with a per-principal share defaulting to a quarter (ADR-335 D8). A query over a limit returns `status=pending`.

Collection is admitted once per source start under one permission snapshot and bounded by every hard end. Work travels over the connector's authenticated hub connection (ADR-334) without signatures; Kubernetes objects are never counters.

Revocation refuses new reservations, admissions, cursors and share-dependent reads when it commits. Running sources receive a pushed stop; a source whose connector is disconnected runs to its admitted hard end and receives the stop on reconnect. Started downloads run to their original bounds (ADR-312).

### SC-AUT-004

Given two simultaneous raw requests sharing a 64 KiB remaining budget, when each asks for 64 KiB, then at most one reservation succeeds. A controller crash after dispatch cannot make the same intrusive action run twice: the retry with the same operation ID finds the existing reservation. When the connector reconnects and reports that the action never started, the reservation is released. Revocation refuses the next query and stops the running source.

## REQ-SHR-001 — Explicit evidence sharing within the organization

A user holding `evidence-owner` or `workload-maintainer` on the workload, with the `evidence:share` scope (a default scope of the console and bundled MCP clients), may create an `EvidenceShare` for named users or groups of the installation's issuer. Creation requires current access to each included artifact; receiving a share confers no sharing authority.

A share binds a snapshot of published artifact versions, recipients, allowed data classes and operations, an optional reason, the immutable creator, its management (REQ-SHR-008) and an expiry that defaults to, and never exceeds, the artifacts' access end. Future artifacts are excluded; capture-time and policy instructions (REQ-SHR-004/005) create ordinary concrete shares at publication. No anonymous links exist. A share includes native download of the shared versions with the `evidence:download` scope ([ADR-233](../docs/decisions/233-recipient-native-download.md)), charged to the workload's transfer allocation.

A share is evaluated after the ordinary evaluator refuses and before any evidence lookup; denies win. Its state is Active, Expired or Revoked.

### SC-SHR-001

Given a developer without the payments workload ACL, when an owner picks that user's group by name and shares two existing stack extracts with it, then the user can query those extracts. A later occurrence and an unshared file stay inaccessible. A recipient from another issuer is refused even if the creator is an administrator.

### SC-SHR-009

Given a published pod-status artifact and an eligible user named by no AccessBinding, when the user calls `get_case`, then it is refused exactly like an absent case. When an evidence owner shares that artifact with the user, the user's `get_case` returns only that artifact with access `shared` and the user can prepare and Range-download its native file. After revocation, the next `get_case`, `download_artifact(action=prepare)` and content request are refused; a started response runs to its original bounds. A current deny of the user or share expiry refuses as well.

## REQ-SHR-002 — Shared view and raw access

A recipient sees a minimal case view: case ID and title, shared timeline entries, artifacts and operations. Hidden artifacts, other cases, inventory and labels never leak through counts, pagination or error differences.

Sharing raw evidence needs one review by an independent `action-approver`. The approved share itself authorizes its recipients' raw operations on the shared versions until the share ends; no separate grants are created. Extract shares need no review.

### SC-SHR-002

Given a shared case with one visible extract and three hidden artifacts, when the recipient lists, searches, paginates or guesses IDs, then no hidden count, name or existence is disclosed. A raw share awaiting review returns `ApprovalRequired`; once approved, the recipient runs exactly the approved raw operations on the shared versions and nothing else.

## REQ-SHR-003 — Revocation and group freshness

Managers (REQ-SHR-008), the creator and administrators can revoke at once. Artifact expiry, loss of eligibility, a deny and share expiry end access. Group membership comes from the current access token. Evidence already seen cannot be clawed back. Share changes write audit rows; no chat or email notifications are sent.

### SC-SHR-003

Given a recipient with a valid cursor, when the share is revoked, then the next page is refused. Removal from a shared group stops new disclosure when the recipient's current access token expires.

## REQ-SHR-004 — Share results when requesting collection

A user with sharing authority may add `sharing` to a capture request (`preview_capture`/`request_capture`, DebugCapture `spec.sharing`): recipients, optionally the outputs (action IDs of the compiled plan) and a `notAfter`. Default outputs are the recipe's metadata and extract outputs; raw outputs need raw-sharing review (REQ-SHR-006). Sharing authority is checked at admission; without it the request is refused (`SharingNotPermitted`). The capture carries one immutable instruction; MCP needs `evidence:share` for it.

At publication the catalog transaction creates one EvidenceShare per published artifact whose recorded capture UID and action ID match the instruction ([ADR-235](../docs/decisions/235-capture-time-sharing.md)), if the instruction is not revoked and its end has not passed. The unique key (origin, artifact) makes replay idempotent. A capture always publishes; `get_capture` reports `sharing.state` (`Pending`, `Shared`, `SharingUnavailable`).

### SC-SHR-004

Given an owner requests a capture with an incident-response group and no explicit outputs, when collection and the approved extract finish, then only metadata and extract outputs become shared. The group cannot see raw logs or another capture. A caller with collection permission but no sharing authority cannot attach the instruction.

### SC-SHR-010

Given a user with sharing authority and `evidence:share` who reviews a pod-status capture with one recipient, when the request is accepted and the capture publishes, then exactly one share of the published artifact exists, a replayed publication creates no other, `get_capture` reports `Shared`, and the recipient's `get_case` returns the artifact with access `shared`. A requester without sharing authority is refused before any capture exists. If the end passes before publication, the capture publishes without a share and reports `SharingUnavailable`.

## REQ-SHR-005 — Explicit sharing of recurring policy results

A DebugPolicy may include `spec.sharing` with an absolute `notAfter` (default 90 days after acceptance) and an optional `futureCaptures.maxCaptures` ([ADR-239](../docs/decisions/239-recurring-policy-sharing.md)). Recurring sharing is explicitly bounded (maintainer decision); there is no "all future evidence" option. The instruction takes effect when the generation is accepted ([team policy automation](policy-automation.md)) and a sponsoring group holds sharing authority on the workload; those groups manage it and the policy is its creator. A capture approval is not a sharing approval.

Each admitted capture of the acceptance takes one slot while both limits allow and the instruction is not stopped or revoked; publication then creates its shares as in REQ-SHR-004. A capture admitted without a slot is never backfilled. Sharing never blocks a capture or overrides capacity limits. A new generation has its own acceptance and counter. State is active, limitReached, expired, stopped, policyChanged or revoked; `get_policy_status` reports it.

### SC-SHR-005

Given an accepted policy instruction limited to ten captures and ending at 18:00, when capture ten is admitted and its extract publishes at 17:50, then it is shared. Capture eleven, an old occurrence and a capture under a changed generation are excluded. An extract published after 18:00 is not shared, and a restart does not renew the end or the counter.

### SC-SHR-012

Given an accepted policy whose sharing allows three captures, when four captures are admitted, the last two by a restarted hub, then the first three are shared and the fourth is not, and the counter stays three. After an edit, captures are unshared until the new generation is accepted, whose acceptance shares only later captures. Revoke-all of the first acceptance revokes exactly its shares and leaves the new acceptance's shares active. After a manager stops a third acceptance's sharing, its already claimed capture still publishes a share and the next capture is unshared. A sharing instruction whose sponsoring groups hold no sharing authority never takes effect.

## REQ-SHR-006 — Concrete publication and approval boundaries

Publication shares an artifact only when its recorded capture UID and action ID match the instruction, its class matches the selected output and it is committed and verified. Provenance comes from what the producer recorded, never from labels, case IDs or graph traversal. No eligible output gives `NoEligibleOutputs`. Shares never copy evidence, extend retention or allow resharing; a revoked share is never recreated.

Raw outputs are reviewed separately: extracts may publish while raw selections await review. One raw-sharing approval binds the instruction's digest (outputs, recipients, plan, limits, end) and covers its matching raw artifacts as they publish (REQ-SHR-002). Its revocation ends the dependent shares.

### SC-SHR-006

Given a capture with an extract output and a pending raw-core output, when artifacts publish, then the extract becomes visible and the core stays unshared until raw-sharing approval. An artifact of another capture or action, or a publication after revocation, is not shared. Replaying a publication creates one share. A recipient of an approved raw core share runs only the approved operations on that core.

## REQ-SHR-007 — Stop, revoke and explain automatic sharing

A manager, the creator or an administrator can Stop or Revoke an instruction. Stop ends new slots; already claimed captures still publish and existing shares stay. Revoke-all is `revoke_share` with `sharing_intent_id` (the acceptance or capture ID) and the expected revision: it revokes that instruction's shares and stops it. Revocation is terminal; reapplying the same generation cannot resurrect it. Suspension, deletion or a new generation stops slots without revoking earlier shares.

The UI shows recipients, outputs, end, captures shared and remaining, approval state and Stop/Revoke. `list_shares` shows owned instructions and their shares; recipients see only concrete artifacts. `revoke_share` never changes capture authority.

### SC-SHR-007

Given an owner revokes an instruction while a late extract publishes, when publication retries or a recipient follows an old cursor, then nothing is disclosed. A revoked share is not recreated on replay. Stopping a recurring instruction lets already claimed captures publish while blocking new claims; revoking it ends every dependent share.

## REQ-AUT-005 — Durable audit

Every admitted authenticated `tools/call`, evidence access, grant/share mutation, intrusive action start and authorization denial writes one append-only audit row in the same transaction as its effect ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D6). If the row cannot be written, the operation fails (as Vault's [audit devices](https://developer.hashicorp.com/vault/docs/audit)). A read writes its row before returning output. A row records principal, operation, keyed argument digest, case/artifact/share/grant IDs, decision, reason code, reservation ID, output size and digest and trace ID; never raw arguments, tokens or evidence content.

Invalid credentials and pre-admission overload are counted in metrics and security logs, not rows. A client that disconnects after commit is recorded as delivery unknown.

The audit table is partitioned by time; batches are exported to the object store or a SIEM, optionally under Object Lock, and retention drops whole partitions ([PostgreSQL partitioning](https://www.postgresql.org/docs/current/ddl-partitioning.html)). Kubernetes audit records permission configuration changes.

### SC-AUT-005

Given a completed query result, when the audit insert fails, then no result is sent. Retrying a mutation with its idempotency key returns the original outcome and its audit row; each new invocation gets a new request ID. No user-managed idempotency key is required for ordinary reads.

## REQ-SHR-008 — Multiple owner teams and immutable creators

Several groups may hold `evidence-owner` or `workload-maintainer` on one workload; both carry sharing authority. A share or instruction records the immutable `createdBy` (or the policy, REQ-SHR-005) and `management`: the creator, or one or more owner groups by name. No member list is copied.

`management` defaults to the creator's groups that hold sharing authority on the artifact inside its recorded audience ([ADR-232](../docs/decisions/232-concrete-evidence-share.md)); a creator without such a group manages personally. `create_share` accepts `management: {mode: teams}` naming such groups the creator belongs to, or `mode: creator`; otherwise `ManagementNotHeld` ([ADR-238](../docs/decisions/238-share-management-transfer.md)). Administrators may name any group that holds sharing authority inside the audience.

A manager is a human with `evidence:share` in a managing group, so a share survives its creator's departure. Managers list (`list_shares(view=owned)`), stop and revoke; the creator can always revoke. Management confers no read, raw or resharing rights and shows no hidden evidence or other recipients.

`transfer_share(share_id, expected_revision, idempotency_key, management)` lets a manager replace the managing groups with groups they belong to; an administrator may assign any group with sharing authority. Transfers never change creator, recipients, artifacts or expiry. Administrators list every share (`list_shares(view=administration)`, paged by the [MCP result bound](mcp.md#req-mcp-002--bounded-result-contract), without recipients or evidence) and revoke any share without gaining read access.

Raw-sharing review always needs a human distinct from the requester or creator; co-ownership is not approval. See the [two-team binding](../examples/access-binding-owners.yaml).

### SC-SHR-008

Given two managing owner teams, when the creator leaves and another current member revokes the share, then revocation succeeds and provenance still names the creator. Losing one team does not disable the other. A recipient, a forged group reference or the creator on another client cannot self-approve raw sharing. Transfer does not change expiry.

### SC-SHR-011

Given a share managed by team A, when a member of A who also belongs to team B transfers management to B, then B's members manage it, A's members no longer do, creator, recipients and expiry are unchanged and the revision increases by one. A transfer to a team the caller does not belong to, or that lacks sharing authority for the artifact, is refused; a non-manager's transfer is refused before any catalog read. When B is deleted from the identity provider an administrator assigns team C, which holds sharing authority inside the audience, with the original creator and expiry. An administrator cannot assign a group without such an allow, a person, or a revoked share. An administrator without evidence rights lists every share without recipients and revokes another team's share; the recipient loses access at the next read and the administrator still cannot read the artifact.

## REQ-AUT-006 — Sensitive observation sessions

Raw packet rings, HTTP parsing and payload-sensitive predicates need authority before any sensitive observation. Their grants set `observationLimits`: `maxBytesPerSecond`, `maxConcurrentSessions` and, for finite sessions, `maxSessionSeconds`. An always-on recorder under an accepted policy is bounded by its rate and ring size ([ADR-335](../docs/decisions/335-usable-by-default.md) D6); a manual or onTrigger session by its rate times its duration.

The collector enforces each session's rate with a token bucket over the bytes entering the sensitive parser or predicate, so a finite session observes at most `maxBytesPerSecond × (maxSessionSeconds + 1)` (one second of initial burst). A sensor restart continues within the original session end and cannot exceed `maxConcurrentSessions`. A raw-filter predicate on sanitized output needs the same limits.

### SC-AUT-006

Given a 16 MiB raw ring and a manual session approved for 16 MiB/s over 60 seconds, when traffic exceeds 16 MiB/s, then the token bucket drops the excess, and the session stops at its 60-second end even if no snapshot was frozen, having observed at most 976 MiB (16 MiB/s × 61 s). Restarting the sensor does not extend the session end. Logs and other cheap context stay armed.

## Related authorization rules

- **Composition and syscalls.** Approval binds the resolved [composition](capture-profiles.md) (every component version, edit and the expanded recipe); publishing a CaptureProfile grants nothing. Syscall argument tracing needs its event rate, argument bytes and session length ([syscalls](syscalls.md)) before arming.
- **Execution modes.** Ongoing raw packet and syscall-argument recording needs its grant before arming ([action lifecycles](action-lifecycle.md)); a grant requested when an incident fires cannot cover earlier recording.
- **Recording saves.** [REQ-SAV-001–004](recording-saves.md) let a caller with `workload-maintainer` save from a policy's existing recording when the accepted policy enables `recordingSaves`; no per-save approval is added and the caller gains no raw access.
- **Live views.** [REQ-LIV-001](live-watch.md#req-liv-001--eligible-sources-and-current-authority) defines live authority; shares and grants confer no live access.
- **Downloads.** Raw grants, approved raw shares and the equivalent Kubernetes right cover `download_artifact` for exact existing digests ([REQ-DLD-002](artifact-downloads.md)).
- **One-off investigations.** [REQ-INV-001–003](investigation-approval.md) add bounded result access to an ad hoc capture review.
