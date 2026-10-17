# SSO, unattended policies and permission freshness

Research checked: 2026-10-10. Related work: REQ-AUT-001/003, REQ-PER-006/007/008, REQ-EXE-001, TASK-07 and C-02/C-03/C-09. **Research with the design accepted by the maintainer; runtime qualification remains separate.** [ADR-059](../decisions/059-unattended-policy-authority.md) records the consequential choice. The [normative refinement](../../specs/policy-automation.md) and [component implementation](../architecture/policy-automation.md) distinguish the accepted contract from runtime qualification.

## Finding

Normal OIDC sign-in does not require an application to have directory-administration privileges. Synchronizing identity and groups from validated login/refresh results is an established pattern. The earlier recommendation of a mandatory Keycloak directory reader, with personal offline tokens as the only alternative, was incomplete and is withdrawn.

Three questions need separate answers: who is using Asservat now; what permits a saved policy to execute later; and how Asservat learns that an external identity or membership changed. OIDC handles authentication and claims exchange. It does not prescribe the ownership or lifetime of an application's saved jobs.

## Established practice and its limits

| Evidence | What it establishes | Implication for Asservat |
| --- | --- | --- |
| [Grafana Team Sync](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-team-sync/) synchronizes on login, with a separate active LDAP synchronization option. | Login synchronization is a real product pattern; it is not continuous directory synchronization. | Use validated claims for people, without pretending stored membership stays current indefinitely. |
| [Grafana SSO session handling](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/#session-handling-with-sso) documents that sessions without refresh can survive loss of IdP access; refresh enables revalidation. | Application-session lifetime and IdP authorization lifetime are different. | A browser cookie cannot extend an expired identity assertion. Do not copy another product's long stale-session defaults for evidence access. |
| [Argo Workflow RBAC](https://argo-workflows.readthedocs.io/en/latest/workflow-rbac/) executes workflow pods using their configured Kubernetes service account. | A job can have an execution identity distinct from a logged-in person. | Recurring capture can use explicit automation authority. A Kubernetes workload identity is not a Keycloak directory-reader account. |
| [GitLab schedules](https://docs.gitlab.com/ci/pipelines/schedules/) run with their owner's permissions and may become inactive if the owner is blocked or removed. | User-bound execution is also an established choice, with ownership-transfer consequences. | There is no universal rule that unattended jobs must survive or stop on employee departure. State the product's choice. |
| [GitHub SCIM deprovisioning](https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/provisioning-user-accounts-with-scim/deprovisioning-and-reinstating-users) suspends managed users upon deprovisioning. | An application can receive lifecycle changes independently of login. | Prompt external offboarding needs an additional signal, not merely a previously verified JWT. |

These are documented behaviors, not experiments we ran against Grafana, Argo or GitLab. The recommendation below is an engineering inference for Asservat, not a requirement imposed by those products or an OAuth standard.

## What the standards provide

- **Sign-in and session refresh:** use authorization code with PKCE, strict issuer/audience/client validation, and short-lived access assertions. Store browser credentials on the server; refresh while servicing an active session rather than requiring another login every few minutes. Confidential-client authentication at the token endpoint is ordinary OAuth client authentication, not directory-read authority. Protect refresh tokens and serialize rotation; public clients require rotation or sender constraint under [OAuth Security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.2.2). The BCP also recommends scope/resource restriction and discusses expiry and revocation in section 4.14.
- **Offline user delegation:** OIDC's [`offline_access`](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess) requests refresh capability while the user is absent, with the specified consent conditions. Refresh tokens can also be issued for ordinary session use; they are not all offline grants. This is a portable mechanism for deliberately acting for a person after logout, but introduces durable credentials and revocation/renewal work. It is unnecessary just to execute a separately authorized team job.
- **Token introspection:** [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2) can report whether a presented token is active. Its standard response does not require a fresh complete group directory. It neither renews an expired token nor, by itself, supplies indefinite user authority.
- **Logout:** [OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCLogout) invalidates identified application sessions. It is not a general membership-change feed. The specification explicitly distinguishes ordinary session refresh from offline grants, which normally survive logout. Logging out is not employee offboarding.
- **Provisioning and lifecycle synchronization:** [SCIM's user/group schema](https://www.rfc-editor.org/rfc/rfc7643.html) and [update protocol](https://www.rfc-editor.org/rfc/rfc7644.html) support account status and group membership updates. They do not promise a universal delivery deadline. A supported integration still needs authenticated updates, complete membership semantics, ordering/reconciliation and measured offboarding latency.
- **Continuous security signals:** [CAEP 1.0](https://openid.net/specs/openid-caep-1_0.html) defines session-revoked and token-claims-change events. This is an optional interoperability direction, not a claim that the selected Keycloak deployment already supplies the required events. Provider support and delivery/recovery guarantees need qualification before relying on it.

OIDC does not standardize every provider's group-claim shape or guarantee that upstream federated groups are freshly recomputed on every refresh. Keep provider claim mapping and freshness qualification, but separate them from provider-specific directory administration. Key an account by issuer and stable subject, not email. Never merge identities because their display names match.

## Accepted recommendation for Asservat

### Human access

Use ordinary OIDC login and session refresh for console users and appropriately scoped access tokens for MCP. Synchronize complete verified group assertions by replacement, including removals; do not union them with old membership. An incomplete or unsupported assertion is not a successful refresh. Preserve original assertion deadlines and the existing maximum five-minute group age; do not re-stamp persisted claims on reads.

Store minimal profile information for display/audit separately from time-bounded authorization observations. Neither a local user row, being a policy creator, nor a long-lived session cookie confers current workload or evidence access. Current Kubernetes bindings/sources, explicit denies, raw-operation grants and retention remain additional checks. A qualified provider must account for upstream membership caching; token issuance time alone is not proof of a five-minute end-to-end directory-change guarantee.

Ordinary refresh failure blocks dependent new actions/output after the current valid assertion/permit ends. Use normal SSO reauthentication with a preserved safe draft when needed. Do not add periodic manual login prompts while standard refresh succeeds, retain a human's credentials solely to keep team jobs alive, or poll every inactive user.

### Recurring team policies

Prefer explicitly delegated, finite **team/workload automation authority**. A human creates or edits a policy using current rights; the accepted generation records that actor permanently. Execution uses the exact approved automation identity and scope, authenticated through the platform's workload/role trust. Team owners manage the policy; they are not a shared login account. This does not require a Keycloak client or directory-reader Secret per team or policy.

Administrators configure a reusable delegation envelope through the existing Kubernetes permission-configuration plane: eligible owner assignments, targets, allowed mechanisms, maximum duration and budgets. The normal capture review shows the effective executor and includes applicable intrusive approval. Authorized maintainers reuse that envelope without provisioning credentials or obtaining an extra administrative review for every policy. A policy without an applicable envelope cannot silently fall back to the controller's broad privileges.

The execution authority is bounded by the submitter's rights at acceptance, current delegated workload authority, exact policy scope and applicable approval. Every start or recorder renewal still checks accepted configuration, assignment continuity, denies, expiry, quotas, retention and local ceilings. Changing executor or scope requires new acceptance and applicable review. Do not manufacture a Kubernetes SAR using a past human's groups: inherited human exec permission alone cannot confer indefinite machine authority.

**Consequential behavior:** removing the creator from a team stops that person's management and evidence access under the human freshness rules, but does not automatically stop an independently authorized team policy. Revoking the policy/delegation, retiring its owner/workload assignment or expiring its approval does stop new work. Deleting a group only in the external IdP is not automatically observable with login-only integration; decommissioning its automation also needs a local authority change or an optional lifecycle integration.

Observation, collection, evidence audiences and disclosure remain separate. An automation executor does not gain interactive download privileges or become a raw-share recipient. Evidence goes to the accepted audience assignments, not automatically to the former creator. Multiple owner teams retain their established assignment and historical-access rules. A recurring policy must not reuse the manual combined approval's personal result-access authorization.

### Deliberately user-bound policies

If execution must stop when the original human loses membership, retain that identity as executor and require a qualified source of current authority. Standard offline refresh is an available option; a separately provisioned lifecycle/membership feed is another. Without either, execution must stop when the last valid identity assertion expires. A days-long grant is not permission to reuse days-old groups.

Do not implement personal offline credentials or directory polling by default. Treat this as an optional later mode if the maintainer requires it. It needs its own reviewed credential purpose, finite lifetime, encrypted storage, serialized refresh, explicit cancellation/revocation behavior and recovery tests. It does not need a new public permission CRUD API.

## Expected behavior under the accepted default

| Event | Human interaction | Independently authorized recurring team policy |
| --- | --- | --- |
| Browser closes or user logs out | Closing a tab need not end the server session; logout invalidates the applicable session. | Continues within its existing authority and budgets. |
| Creator loses group membership | Refreshed assertions remove rights; old assertions have their original bounded lifetime. | Continues; the departing user cannot manage it or read its results through former membership. |
| Policy/delegation is revoked or owner assignment retired | Current authority reflects the change. | No new starts/renewals after connected invalidation or the original disconnected permit deadline; no instant-stop claim for irreversible actions. |
| IdP is unavailable | No new login/refresh; existing assertions expire normally. | Can continue only if its independent workload trust and local authorization sources remain current. |
| Required Kubernetes/SQL authority is unavailable | Deny dependent operations when their existing validity ends. | Cannot renew authority from cached stale observations. |
| Approval expires or workload quota is exhausted | Show the specific remedy and preserve existing evidence. | Stops admission; no automatic expiry extension or budget reset. |

With login synchronization alone, there is no immediate external deprovisioning guarantee. Keep a protected local subject/client deny and policy/delegation revocation path for urgent response. SCIM or security-event integration can later reduce external-change latency, but must not create a second workload-permission editor or be a mandatory installation dependency. Identity lifecycle input and Kubernetes-owned application permission configuration are different contracts.

## Required design changes and qualification

The accepted default changes the meaning of future execution for human-authored recurring policies in REQ-PER-007. It is not just a different Keycloak adapter. Implementation must align REQ-PER-006/007/008, REQ-EXE-001, grants/approval schemas, executor identity, ownership and audience derivation, saved-recording authorization, UI/MCP preview, CRD delegation and signed acceptance. Preserve a separate immutable creator. Migrate no existing human-bound policy silently, copy no personal grant to a new executor, and mark no new scope accepted before review.

Test creator departure with continued authorized team capture and denied personal read; policy/delegation revocation; multiple owner teams and assignment replacement; delegated target narrowing; forged executor and copied grants; human-only SAR without automation delegation; IdP/source outages; exact grant expiry after locks; recorder renewal; current viewer permissions; and preserved budgets across retries. For sessions, test concurrent refresh, group removal, missing/incomplete claims, refresh revocation, disabled users, back-channel logout and upstream-staleness limits. Optional push sources additionally need authenticated replay/out-of-order/gap handling; receipt of one event is not proof of complete membership freshness.

Existing measured evidence is narrower: the real Keycloak fixture verifies access-token/PKCE/refresh behavior, disabled-user refresh denial, stable group updates and self-assignment protection. The hierarchy extension passed ancestor inheritance, deduplication, parent rename, slash-containing names and membership removal (`test/results/identity-hierarchy.log`, 2.904 seconds, unchanged source and complete cleanup). No directory reader, personal offline credential store, production browser session, SCIM/CAEP integration or team-policy execution change has been implemented by this research.
