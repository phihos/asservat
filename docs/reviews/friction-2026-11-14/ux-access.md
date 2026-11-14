# UX audit: identity, sign-in, permissions, team access, approvals, administration

Worktree `/home/phil/Projekte/asservat-ux` at `5d4667715` (ADR-330). Read-only audit.
ADR-334 items (join Secrets, bootstrap records, connector endpoints, digest pinning) are excluded.
"Maintainer" means the decision appears in AGENTS.md "Authority and invariants" or one of
its later maintainer-selected notes. "Agent-added" means it comes only from an ADR or spec.

## The four journeys in numbers

### A. Let a team investigate its own namespace (external Keycloak, ordinary collection)

| # | Who | Action | Opaque IDs handled |
|---|-----|--------|--------------------|
| 1 | IdP admin | Create the Keycloak group | – |
| 2 | IdP admin | Set the group attribute `asservat_group_id` to the group's UUID, copied by hand from the Keycloak UI | 1 UUID |
| 3 | Platform admin | Add that UUID to `identity.eligibleGroups` and run `helm upgrade`, unless the group is nested under an eligible parent | same UUID again |
| 4 | Namespace admin | Write an AccessBinding with the full issuer URL, the group UUID, a role list and a mandatory `reason` | issuer URL + UUID |
| 5 | (if workload-narrowed) | Look up and paste each Deployment's `metadata.uid` | 1 UID per workload |
| 6 | Team | Discover with `explain_access` that capture is allowed but sharing and approving are not; add `evidence-owner` and `action-approver` to the roles | – |

Minimum: **2 objects** (an IdP group plus 1 AccessBinding), plus **1 Helm upgrade** in the common case, **2–3 hand-copied IDs** and **4–6 steps across 2–3 different admins**. Comparable tools:
- Argo CD: one line in `policy.csv` naming the IdP group by name.
- Grafana: a team synced from the group name.
- Kubernetes: one RoleBinding with `name: payments-team`.

Recurring team policies add:
- an administrator RoleBinding for `bind` on `automation` in each namespace;
- an envelope with 5 numeric ceilings;
- a DebugPolicy that must live in the admin-only hub namespace;
- `activate_policy`, then `request_policy_grant`, then a second human's step-up approval, then `activate_policy --grant_id`.

That is **about 8 steps, 4 objects and 2 people**. The policy grant defaults to 7 days, so the last 3 steps come back every week.

### B. Approve an intrusive capture

1. Requester runs `preview_capture`. The preview expires after `previewSeconds: 120`.
2. Requester runs `request_capture`, which returns `ApprovalRequired` and opens a review.
3. A **different** human holding `action-approver` *in that namespace* opens the review.
4. The approver does a step-up re-login (`max_age=0`, a configured `acr`).
5. The approver approves. The approval expires 1 h after the decision.
6. The **requester** must come back and resubmit within that hour, from a listed client.
7. The capture then has a ≤5 min start window.

That is **7 steps and 2 people**, and the requester has to act twice. On a default install it is **impossible**: `identity.approvals` is commented out, and "without configured step-up nothing can be approved". The bundled realm also configures no step-up flow.

### C. Share a result

The sharer needs the `evidence-owner` role (`workload-maintainer` does not include it) and the `evidence:share` scope. They type **1–8 recipient IDs**, which are Keycloak `sub` UUIDs or group UUIDs, because there is no user search. Expiry defaults to 24 h and is capped at 7 days.

A raw share needs 3 humans and 2 approvals:
- the owner;
- an independent approver for raw sharing;
- each recipient's own raw-query grant review.

### D. Add a new user

- **Bundled Keycloak:**
  1. `kubectl get secret …-keycloak-state` to read the bootstrap admin password.
  2. Open the Keycloak admin console.
  3. Create the user and set a password. Self-service reset and registration are disabled, and there is no email.
  4. Add the user to `asservat-users`.
  5. Add the user to the team group.

  That is **5 steps in 2 tools**.
- **External IdP with `eligibleSubjects`:** you also edit Helm values with the user's `sub` UUID and run **`helm upgrade` for every user**.
- **Sharing with them:** the colleague has to find and pass on that user's `sub` UUID.

## Findings

### ACC-01: Two-pass Helm install to copy generated Keycloak group UUIDs (high)

- **Where:** docs/installation/helm.md:136-163; values.yaml:51-53, 436-441; charts/asservat/templates/_hubapi.tpl:179 (fails without `processingOperators`); internal/bootstrap/small_keycloak_prepare.go:72, 157-163.
- **Today:** install with a placeholder operator entry, then run `kubectl … | jq` to extract `users-group-id` and the operators group UUID, paste them into `identity.eligibleGroups`, `fleet.groups` and `processingOperators`, and `helm upgrade` again.
- **Why it is friction:** no comparable chart needs a second pass to learn its own generated IDs. Grafana, Argo CD and the Keycloak operator reference bundled groups by name.
- **Origin:** agent-added. The maintainer chose bundled Keycloak; the ID plumbing is ours.
- **Fix:** when `provider: keycloak`, default `eligibleGroups`, `fleet.groups` and `processingOperators` to the bundled groups. Resolve them at runtime from `<name>-keycloak-state`, which hub-api already mounts for the client secret, or derive the UUIDs deterministically from the installation name. Drop the template `fail`.

### ACC-02: Docs tell operators to make every user a fleet operator (high, unsafe default)

- **Where:** docs/installation/helm.md:160 ("Set `identity.eligibleGroups` and `fleet.groups` to `[$USERS]`"); values.yaml:96-100.
- **Today:** following the guide gives every console user installation-administrator powers: cluster enrollment, `preview_access_change`, administrative share revocation and share management assignment (authorization.md:185-189).
- **Why it is friction:** Argo CD and Grafana default users to viewer or `policy.default: role:readonly`, never to admin.
- **Origin:** agent-added doc error.
- **Fix:** point `fleet.groups` at the operators group. Better, merge it into one admin list (ACC-03).

### ACC-03: Five overlapping administrator concepts (high)

- **Where:**
  - values.yaml:51-53 `identity.processingOperators` (privacy/processing operator);
  - values.yaml:96-100 `fleet.issuer`, `fleet.clients`, `fleet.subjects`, `fleet.groups` (fleet operator, which also acts as "installation administrator", authorization.md:185);
  - "evidence administrator" (permissions.md:152);
  - Kubernetes admin of the release namespace (PermissionSources, retention, DebugPolicies);
  - the bundled Keycloak `processingOperators: true` toggle.
- **Today:** the operator configures three Helm identity lists with separate issuer and client fields, plus Kubernetes RBAC. `processingOperators` is mandatory even when nobody uses the privacy console.
- **Why it is friction:** Argo CD has one admin role mapping; Grafana has `role_attribute_path` → Admin; Sentry has an Owner role.
- **Origin:**
  - Agent-added: the split.
  - Maintainer decisions it must honour: "administrator-enforced maximum evidence retention" and "Kubernetes-only permission configuration".
- **Fix:**
  - Add one `identity.admins` (groups/subjects) list covering fleet, processing and evidence administration.
  - Make a separate privacy-operator list optional, defaulting to admins.
  - Inherit `fleet.issuer` and `fleet.clients` from `identity`.
  - Make processing operators optional.

### ACC-04: Groups are UUIDs copied into a hand-set attribute, never names (high)

- **Where:** keycloak-profile.md:20-33; helm.md:181-196; authorization.md:79, 103; permissions.md:58; CRD accessbindings.yaml subjects (`id` required).
- **Today:** for every team group, an IdP admin creates a custom `asservat_group_id` attribute holding the group's own UUID. Everyone copies that UUID into AccessBindings, Helm values and shares. Keycloak's standard Group Membership mapper (names or paths) is refused. It is unverified whether LDAP-federated groups (read-only LDAP) can carry this attribute cleanly.
- **Why it is friction:** Argo CD, Grafana, oauth2-proxy, Kubernetes OIDC (`--oidc-groups-claim`) and Kyverno all match group names. Rename and recycle risk is accepted there and handled by IdP governance.
- **Origin:** agent-added (ADR-053 note, "administrator-controlled stable group IDs"). Not in the maintainer's invariants.
- **Fix:**
  - Accept the standard group claim (full path, issuer-qualified) as the stable ID by default.
  - Keep the ID attribute as an opt-in hardened profile.
  - Show names in the UI.

### ACC-05: Default install cannot approve anything (high)

- **Where:**
  - values.yaml:47-50 (`approvals` commented out);
  - authorization.md:51 ("Without configured step-up nothing can be approved");
  - browser-sessions.md:82-87;
  - small_keycloak_prepare.go:141 (an `acr` scope, but no LoA/OTP flow in the realm).
- **Today:** every packet/syscall plan with a raw filter, every recording under `requireRecordingApproval`, and every intrusive action (dumps, commands, policy grants) is permanently `ApprovalRequired`. To fix it, an operator configures a Keycloak step-up flow and ACR-to-LoA mapping and sets `acrValues` and `maxAgeSeconds`.
- **Why it is friction:**
  - Teleport access requests and GitHub environment approvals work out of the box with an ordinary session.
  - MFA re-prompting is optional hardening there.
- **Origin:**
  - Maintainer decision: one independent approval (investigation-approval.md).
  - Agent-added: step-up (ADR-253).
- **Fix:**
  - Default to the "distinct authenticated human with `action-approver`" check only.
  - Make step-up opt-in.
  - Have the bundled realm ship a working configuration (e.g. `max_age` re-authentication accepted as assurance) so approval works on first install.

### ACC-06: Requester must resubmit after approval within 1 h, then start within 5 min (medium-high)

- **Where:** investigation-approval.md:35 (file line; "After approval the same human submits it… start window of at most five minutes"); authorization.md:51 ("approval lasts one hour from the decision"); values.yaml `previewSeconds: 120`.
- **Today:** if the approver decides at 02:00 and the requester returns at 09:00, the approval is expired and the requester redoes preview and review.
- **Why it is friction:** GitHub deployment approvals auto-continue. Argo Rollouts' manual promotion proceeds when promoted.
- **Origin:**
  - Maintainer decision: the bounded approval itself.
  - Agent-added: the second submit and the 1 h / 5 min windows.
- **Fix:**
  - The reviewed plan is already stored (ADR-252), so start it automatically on approval when the exact Pod still exists.
  - Otherwise keep the approval until the requester's chosen `notAfter` (≤8 h) and offer "start now" from a notification badge.

### ACC-07: `action-approver` must be bound in every namespace; there is no cluster- or fleet-wide binding (medium-high)

- **Where:** permissions.md:11, 13, 58; helm.md:391-396 ("Cluster-wide or multi-namespace grants are PermissionSources").
- **Today:** a central SRE or approver group needs an AccessBinding in each application namespace of each cluster, or a `namespaceMetadata` PermissionSource. That source works only if every namespace carries a label whose value maps to that group, and it has "one value is one group".
- **Why it is friction:** Kubernetes has ClusterRoleBinding, Argo CD has global policies, Kyverno has ClusterPolicy.
- **Origin:** agent-added (ADR-329 chose namespace-scoped bindings).
- **Fix:** add a `ClusterAccessBinding` (or a PermissionSource kind `static`) in the hub namespace that grants named groups a role over a namespace selector in selected clusters, administrator-only.

### ACC-08: Recurring team policies need about 8 steps across 2 humans, repeated weekly (medium-high)

- **Where:**
  - policy-automation.md:7-11 (file lines): automation envelope and `bind` on `automation`;
  - policy-automation.md:25 (file line): DebugPolicy lives in the hub control namespace, which is admin-only (ADR-328);
  - policy-automation.md:55-57 (file lines): `request_policy_grant`, then step-up review, then `activate_policy` with `grant_id`;
  - authorization.md:45: policy grants default to 7 days;
  - helm.md:437-442: per-namespace administrator RoleBinding.
- **Today:**
  1. An admin creates the automation RoleBinding in each namespace.
  2. The namespace admin adds an envelope (5 numbers) to a binding.
  3. Someone creates the DebugPolicy in the admin-only hub namespace. Teams cannot GitOps their own policies.
  4. The team activates it.
  5. The team requests a grant.
  6. A second person approves with step-up.
  7. The team attaches the grant.
  8. Steps 5–7 repeat when the grant expires.
- **Why it is friction:** Prometheus Operator lets teams own PrometheusRules in their own namespace. Kyverno policies are namespaced.
- **Origin:**
  - Maintainer decision: "expiring policy grants for automatic intrusive actions" (honour by keeping a finite grant).
  - Agent-added: the envelope RoleBinding, hub-namespace placement, separate attach step and 7-day default.
- **Fix:**
  - Allow a namespaced DebugPolicy in the application namespace, scoped like AccessBinding.
  - Make activation request the grant in the same call and auto-attach on approval.
  - Default the policy grant to the envelope's `maxLifetimeSeconds`.
  - Let `admin` aggregate `automation` bind optionally (a values flag).

### ACC-09: Workload narrowing requires pasting Deployment UIDs (medium-high)

- **Where:** charts/asservat/crds/accessbindings.yaml:~137-155 (`workloads[]` requires `kind`, `name`, `uid`); helm.md:412 (`uid: replace-with-the-uid`).
- **Today:** look up `metadata.uid`. Deleting and recreating the Deployment (common with Helm uninstall/reinstall or Argo CD replace) silently makes the binding match nothing.
- **Why it is friction:** RoleBinding `resourceNames` and Kyverno `match` use names. No tool keys user configuration on UIDs.
- **Origin:** agent-added.
- **Fix:** name only. The hub resolves the current UID at decision time and records it in provenance. Keep `uid` optional for pinning.

### ACC-10: Mandatory `reason` and full issuer URL in every binding subject (medium)

- **Where:** CRD accessbindings.yaml:230-234 (`reason` required), 92-96 (`issuer` required per subject); examples/access-binding*.yaml.
- **Today:** every subject repeats `issuer: https://…/realms/company`, although an installation has one human issuer. Every binding needs prose.
- **Why it is friction:** RoleBinding has neither. Argo CD `policy.csv` has neither.
- **Origin:** agent-added. "One organization per installation" is the maintainer decision, and it makes the field redundant.
- **Fix:** default `issuer` to `identity.issuer`. Make `reason` optional (use an annotation).

### ACC-11: Two eligibility gates to maintain (medium)

- **Where:** authorization.md:11; values.yaml:39-40; _hubapi.tpl:152 (fails if both are empty for an external IdP); helm.md:191-196.
- **Today:** a user named by an AccessBinding is still refused unless they are also in `identity.eligibleGroups` or `eligibleSubjects`. Adding a team or user often means editing Helm values and running `helm upgrade` (with `eligibleSubjects`, once per user).
- **Why it is friction:** in Argo CD and Grafana, IdP login plus an RBAC mapping is enough.
- **Origin:**
  - Maintainer decision: one organization.
  - Agent-added: separate allowlist maintenance.
- **Fix:** make eligibility optional, defaulting to "any authenticated user of the configured issuer and client". An organization realm already defines the organization. Keep the allowlist for shared realms.

### ACC-12: No user directory, so shares and bindings take raw `sub` and group UUIDs (high)

- **Where:** authorization.md:77-79, 113, 185-193; keycloak-profile.md:45-47 (no Admin API); permissions.md:38 ("never enumerate group members").
- **Today:** to share with a colleague you obtain their Keycloak `sub` UUID or a group UUID and type it in.
- **Why it is friction:**
  - Sentry, Grafana and GitLab offer a member picker built from users who have signed in.
  - Grafana keeps a user table populated at login without directory credentials.
- **Origin:**
  - Maintainer decision: sharing within the organization.
  - Agent-added: no picker.
- **Fix:** keep a minimal "known principals" table (issuer, sub, `preferred_username`, display name, group IDs or paths seen) updated at login. Offer search over it to eligible users. It needs no new credentials.

### ACC-13: Share expiry capped at 7 days, 8 recipients, extra role and scope (medium)

- **Where:** authorization.md:75-77 (default 24 h, max 7 d, 1–8 recipients), 113, 131; permissions.md:21.
- **Today:**
  - Postmortems and vendor escalations run weeks, so shares need re-creating.
  - A maintainer who captured cannot share their own result without a separate `evidence-owner` binding and the `evidence:share` scope.
- **Why it is friction:** Grafana snapshots and Sentry issue links have no 7-day cap; owners share by default.
- **Origin:**
  - Maintainer decisions: sharing within the organization; artifact shares are concrete snapshots.
  - Agent-added: the caps and the role split.
- **Fix:**
  - Default the maximum to the artifact access end.
  - Raise recipients to e.g. 32.
  - Let `workload-maintainer` imply owner, keeping owner as a role for owner-only teams.

### ACC-14: Raw sharing needs 3 humans and 2 reviews (medium)

- **Where:** authorization.md:95, 151, 191.
- **Today:** the owner shares, a distinct approver approves raw sharing, and each recipient still files a separate raw-query grant review.
- **Why it is friction:** this is double review of the same disclosure decision.
- **Origin:**
  - Maintainer decision: one independent approval for manual collection plus the same human's result access.
  - Agent-added: extending that to two reviews for sharing.
- **Fix:** one review whose approval creates the recipients' bounded raw children, as investigation-approval already does for the requester.

### ACC-15: Installation-wide session caps (medium-high)

- **Where:**
  - values.yaml:42-44 (`maxLogins: 64`, `maxSessions: 256`), against examples/browser-settings.json (2000);
  - browser-sessions.md:99-103 (10 per subject; "a further login is refused without evicting another session"; 24 h hard ceiling).
- **Today:**
  - A 300-person organization hits 256 concurrent sessions.
  - A morning login burst exceeds 64 pending logins.
  - The 11th browser or profile of one user is refused until old sessions age out (8 h).
- **Why it is friction:** Grafana and oauth2-proxy have no global session cap. Grafana evicts the oldest session (`login_maximum_inactive_lifetime`).
- **Origin:** agent-added.
- **Fix:**
  - Remove the global caps or size them at ≥10k, since rows are small.
  - On the per-subject limit, evict the oldest session instead of refusing.

### ACC-16: MCP clients need three separate configuration places (medium)

- **Where:**
  - values.yaml:441 (`mcpRedirectURIs: []`; without it no MCP client exists);
  - small_keycloak_prepare.go:38-46, 145-148 (exact URIs, `*` refused);
  - _hubapi.tpl:155 (`identity.clients` defaults to the console client only, so MCP tokens are an unregistered client);
  - investigation-approval.md:7 (file line; each agent client must be named in the review).
- **Today:** list exact redirect URIs, add the MCP client to `identity.clients`, and `helm upgrade`. MCP tools with random loopback ports (RFC 8252 §7.3) need exact URIs.
- **Why it is friction:** RFC 8252 loopback with any port is standard; Grafana's and GitHub's OAuth apps accept it.
- **Origin:** agent-added.
- **Fix:**
  - Create the MCP public client by default with loopback any-port redirects.
  - Register it in `identity.clients` automatically when bundled.

### ACC-17: Exec-inherited teams can collect but not share or approve (medium)

- **Where:** permissions.md:75-94 (`kubernetesExec` maps only to `workload-maintainer`; review sources give no team ownership, authorization.md:185); helm.md:377-380.
- **Today:** a team that uses the zero-object exec path still needs AccessBindings with explicit group UUIDs for `evidence-owner` and `action-approver`. Its evidence audience is the individual capturing principal (permissions.md:150), so teammates cannot read each other's captures.
- **Why it is friction:** a team mapped through Kubernetes RBAC expects team-level visibility.
- **Origin:**
  - Maintainer decision: inheritance including pod exec rights (honour that).
  - Agent-added: individual-only audience.
- **Fix:** let the exec source record the principal's current mapped groups that also hold exec as the audience. Allow an `action-approver` mapping from a second SubjectAccessReview check (e.g. `update deployments`).

### ACC-18: 1,024 bindings and 4,096 rows per cluster, shared by all teams (medium)

- **Where:** helm.md:447-450; permissions.md:67 (4,096 namespaces with keys), 94 (4 review sources per cluster), 122 (32 audience groups per artifact, refused at planning).
- **Today:** one team can exhaust the bound for the whole cluster unless the admin adds ResourceQuotas. A namespace with more than 32 role-holding groups cannot capture at all.
- **Why it is friction:** Kubernetes RBAC and Argo CD have no product cap at this scale.
- **Origin:** agent-added.
- **Fix:**
  - Make the bounds per namespace or raise them by 10–100×.
  - On audience overflow, record the bindings (not the expanded groups) as the audience, or truncate approver-only entries, instead of refusing.

### ACC-19: Undocumented "initial review ConfigMap" when bindings predate the hub (medium)

- **Where:** values.yaml:283-285 (`permission.review`); internal/contracts/hub_worker_permission.go:12-14; internal/bootstrap/hub_worker_permission_child.go:273-283.
- **Today:** if AccessBindings exist before first acceptance, the case for GitOps that syncs bindings before the hub, an administrator must hand-create a review ConfigMap whose format helm.md never describes.
- **Why it is friction:** no comparable controller needs a bootstrap approval document for pre-existing CRs.
- **Origin:** agent-added. Behaviour without it was not traced to the end; it is likely a refused first acceptance.
- **Fix:** accept existing bindings as observed. Kubernetes RBAC and admission already authorized their writers ("trust the platform").

### ACC-20: `CollectionCeiling` namespace opt-in is specified but has no CRD or values (medium)

- **Where:** specs/apis.md:15; targets.md:23 ("administrator-enabled namespace"); permissions.md:15, 60. The chart has no CRD and no values key for it.
- **Today:** it is unclear whether a team's namespace must also be opted in, and how. It is either a hidden extra step or a dead concept.
- **Why it is friction:** users meet a concept with no way to configure it.
- **Origin:** agent-added.
- **Fix:** either drop it (AccessBinding plus local values already gate collection) or make it a chart value defaulting to "all namespaces except system ones".

### ACC-21: Bundled realm has no self-service (low-medium)

- **Where:** small_keycloak_prepare.go:165 (`registrationAllowed: false`, `resetPasswordAllowed: false`, `users: []`, no SMTP).
- **Today:** every password reset or new user goes through the bootstrap admin, whose password is read from a Secret with kubectl.
- **Why it is friction:** Grafana and Gitea offer invites.
- **Origin:**
  - Maintainer decision: "No default password, anonymous enrollment or mandatory email" (REQ-DEP-002 invite/recovery). Honour it with invite links.
  - Agent-added: no invite path.
- **Fix:** document or create an initial named admin user via values (existingSecret). Enable Keycloak "required action: update password" invite links, which work without SMTP when copied.

### ACC-22: Narrow AccessBinding writers need hand-written YAML Roles (low)

- **Where:** helm.md:424-436.
- **Today:** `kubectl create role` cannot express `bind` on the virtual `accessroles` resource, so delegated writers need hand-written YAML.
- **Why it is friction:** small, but every GitOps setup hits it.
- **Origin:** agent-added (mirrors RBAC `bind`).
- **Fix:** ship 4 aggregatable ClusterRoles (`asservat-bind-<role>`) that admins bind with `kubectl create rolebinding`.

### ACC-23: Fixed 8 h / 24 h session with no sliding renewal (low)

- **Where:** browser-sessions.md:99-100; values.yaml:43.
- **Today:** users re-login daily. A native download interrupted after expiry resumes only after an explicit console refresh (authorization.md:13).
- **Why it is friction:** Grafana defaults to a 30-day maximum with 7-day inactivity.
- **Origin:** agent-added (ADR-060).
- **Fix:** sliding inactivity timeout within a configurable maximum (default 7 d), bounded by IdP refresh validity.

## Counts

23 findings: 6 high (ACC-01, 02, 03, 04, 05, 12), 5 medium-high (06, 07, 08, 09, 15), 9 medium (10, 11, 13, 14, 16, 17, 18, 19, 20), 3 low or low-medium (21, 22, 23).
Maintainer-traced, where only the mechanism is agent-added: ACC-03 (partly), 05, 06, 08, 11, 12, 13, 14, 17, 21. The rest are agent-added.
