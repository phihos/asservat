# Team policy automation

Accepted ADR-059 refines REQ-AUT-001/003, REQ-PER-001/006/007/008 and REQ-EXE-001. It separates the current rights of people from finite recurring execution. The [research](../docs/research/background-identity.md) records the standards and alternatives; the [implementation boundary](../docs/architecture/policy-automation.md) identifies unfinished runtime work.

## Operator configuration and low-effort authoring

`AccessBinding.spec.automation` is an optional reusable **per-policy** ceiling. It is allowed only on an Allow binding whose subjects are stable groups and whose roles include workload-maintainer. It uses the binding's exact cluster/namespace/workload scope and optional notAfter. Existing installation permission administrators manage this field through Kubernetes; ordinary delegated AccessBinding writers cannot create, alter or delete an automation-bearing binding. This prevents an existing permission-writing delegation from acquiring a stronger power on upgrade. Future delegated automation administration requires its own reviewed bounds.

The [typed envelope](contracts/policy-authority.schema.json) pins allowed action kinds, maximum policy lifetime in seconds (1–31536000), maximum executions (1–10000), aggregate collected bytes (1–1 TiB) and observed bytes (0–1 TiB). Zero observation bytes permits no continuing acquisition of bytes; it does not turn an ongoing recorder into an on-trigger action. Counts/bytes are prospective reservation ceilings, not throughput or overhead estimates. Existing node/workload limits, observation event/session/rate ceilings, protected storage and grant rules remain mandatory. Several policies cannot multiply a workload's aggregate allowance. Restrict actions to the expanded recipe's exact kinds; allowed kinds never waive intrusive review or local safety rules.

See [an administrator binding](../examples/access-binding-automation.yaml). An operator normally configures one binding per team/workload envelope once. A maintainer with current personal rights selects an authorized workload and recipe. A sole qualifying binding is resolved automatically; ambiguity requires a visible choice. No matching binding produces DelegationRequired with an actionable Kubernetes/GitOps proposal, preserving the draft. Human-only exec inheritance is not a delegation: do not copy remembered groups into a machine SAR or let a maintainer name a powerful service account.

## Identity and acceptance

Keep the authenticated creator/submitter, policy execution principal and authenticated worker distinct. The first remains audit provenance, the second identifies the bounded policy, and the third authenticates dispatch through existing workload/role trust. The policy principal is deterministically `issuer=urn:asservat:installation:<installation UUID>`, `subject=policy:<policy UID>`, `clientID=policy-executor`, `identityType=workload`. This issuer is internal to accepted execution; it is not an OIDC issuer accepted by public endpoints. These strings are not credentials and cannot authorize work without protected acceptance and current checks.

The current authenticated submitter must have whole-pod collection entitlement and belong to a sponsoring group at acceptance; the first acceptance pins the immutable creator, and later team editors are recorded separately as submitters. For every acceptance, all resolved scope must fit both that authority and the administrator envelope. Pin the binding UID/generation/digest and 1–8 exact sponsoring workload-maintainer group assignments. The delegation revision is current; an unchanged ordinary assignment retains its original basis digest so historical evidence access remains continuous. Pin both independently and require the exact assignment in the current projection; comparing its historical digest to the latest delegation digest is incorrect. These are execution authority, distinct from evidence-owner management assignments. They may not be sourced from human-only SAR or guessed catalog ownership. Pin installation, policy UID, workload UID, action kinds, original issue/expiry and cumulative limits in the collection scope. No caller supplies a trusted executor, protected digest or accepted assignment by writing CRD status.

`collection-scope/v1.policyAuthority` is required for a new DebugPolicy scope and forbidden for DebugCapture. Ongoing sources, trigger incidents and existing-recording saves use the same policy identity. Authored policies contain configuration intent, not `policyAuthority`; resolution belongs to protected acceptance. An implementation may offer an optional configuration reference to disambiguate eligible bindings, but must resolve and pin it before hashing. No user-computed digest is required.

Changing executor, sponsorship, envelope definition, authority expiry or limits changes execution scope and requires authenticated acceptance and applicable independent review. Ordinary login, reapplied unchanged YAML, retries, restarts and grant-reference edits cannot reset counters or extend authority. Existing human-bound policy scopes require explicit migration/new acceptance; do not reinterpret historical digests or persisted grants.

## Hub-held policies and in-process activation (ADR-228)

The first implemented policies are hub-held: a DebugPolicy in the hub control namespace (like
AccessBindings) names its workload cluster in `spec.target.cluster`. The policy object's own
location (submission/source) and its target (accepted authority) therefore differ; the target is
bound by the accepted authority alone. The authenticated human activates the current revision with
the MCP/browser operation `activate_policy`; hub-api reads the source, compiles it, resolves the
sole automation-bearing binding and the human's sponsoring assignments, takes the envelope's
per-policy maxima as limits and accepts it in-process. Because hub-api authenticates the human
itself, it builds the submission check in-process; the ADR-062 signed submission is required only
for a separate GitOps or admission submitter. An unchanged source revision cannot be accepted
twice, and a retry under the same idempotency key returns the original acceptance. Captures run
under the policy executor; `get_policy_status` explains the policy without content.

`deactivate_policy` (ADR-229) stops an accepted hub-held policy. It requires the same team authority
that sponsors activation — a current, undenied workload-maintainer group assignment of the
delegating AccessBinding — not the creator identity; administrators stop policies through
Kubernetes (suspend/delete the DebugPolicy or remove the envelope). Deactivation clears the current
acceptance, so polling stops at the next cycle and every later capture eligibility check refuses
the executor. It refunds no spend and deletes no occurrence, capture or evidence, is idempotent,
and is recorded by the encrypted operation audit. Reactivation is a fresh acceptance of a changed
scope: an unchanged revision is never accepted again.

## Continued execution and revocation

Protected acceptance must atomically consume the authenticated submission nonce and freeze the exact scope. Replacing an accepted scope explicitly pins its predecessor; retries return the original receipt and cannot reset expiry or counters. Require durable encrypted acceptance audit before eligibility. Keep a current protected policy-source observation as well as current delegation. Source deletion, suspension or unavailable observation stops eligibility. Separate normalized collection intent from the control fields excluded by specs/execution.md: pause/resume and grant attachment never reset authority, while a collection-intent change cannot revive an earlier acceptance by reverting the YAML.

Before arming, renewing, collecting or saving, check the accepted scope against current protected delegation and assignment history. For the policy-only finite sensitive admission in [ADR-261](../docs/decisions/261-finite-policy-observation-admission.md), new admission/permit issuance and renewal perform these checks with their original fresh facts. A committed active lease is distinct: already-issued work may start within its original shortened latestStart and continue only to the original finite lease, at most twenty seconds after issuance and never past a review/action/session/grant/capture hard expiry. All pinned sponsoring assignments must remain valid for that exact target; a replaced assignment cannot be revived by restoring the old group name. A deny of the policy executor or any pinned sponsoring team prevents dependent execution. An unrelated personal deny does not revoke team delegation. Additional evidence-owner managers do not lend execution authority; losing one manager follows the existing independent management rules.

Current source authorization retains the 30-second default/60-second maximum and complete deny-state maximum of five seconds. Intersect all deadlines with original policy expiry, binding expiry, applicable action/observation grant, local ceiling, current trust and admission leases. Unknown/stale authority fails closed. Fetch external proofs before SQL locks and recheck deadlines/revisions after all blocking work. Atomic grant/quota reservation and signed local permits remain necessary; a successful eligibility query is not a permit.

Creator logout, access-token expiry, team departure or disabled personal account does not revoke independent team-policy authority. The creator immediately loses dependent personal actions when a local deny is observed, or loses them within the qualified identity freshness bound after refreshed external membership. Login-only synchronization does not promise instant external offboarding. Deleting an IdP group alone is not a local delegation revocation; operators must retire its automation through Kubernetes or a later qualified lifecycle integration. Suspension/revocation stops new admission/permit issuance/renewal once authoritative, within existing observation bounds; already-issued finite work may still start before its original latestStart and ends at its fixed active-lease deadline. No immediate connected packet stop is implemented. Other already irreversible effects cannot be undone.

## Approval, evidence and reuse

A policy AccessGrant keeps requester and reviewer provenance and separately binds `policyExecutor` and the exact `policyAuthority`. Self-approval uses the authenticated human requester, not the machine executor. Effective scope/lifetime is the intersection of delegation and review. Automation/workload identities cannot review themselves. Existing personal manual collection plus result-access approval remains unchanged and cannot be transferred to recurring automation.

Policy-grant requester metadata is also subject to current authorization: get and
requested-list require current whole-workload collection rights on the exact
approved workload, as request/replay already do. A former requester without those
rights receives no grant detail and no requested-list row. Independent current
approvers retain their review/inbox access. Direct get_grant also permits an
exact current pinned sponsoring workload-maintainer to inspect the existing
policy configuration, finite original/effective dates and grant reservations,
so team management remains usable after requester departure. It does not grant
independent decision authority, a broader inbox, evidence/history access or
personal capture continuation. The existing can_revoke flag reflects actual
current reviewer or pinned-manager eligibility, not requester provenance;
a requester retaining general collection rights but losing that management
basis may inspect their grant but cannot revoke it. Service requester matching includes
issuer, subject, client and principal kind; same-human metadata access across
clients does not transfer a request journal or policy execution authority. Check
identity/permission validity after blocking reads. Losing personal metadata access
does not revoke or renew independently accepted team authority, expiry or spend.
Ad hoc requester metadata behavior is unchanged.


The policy principal supplies no human download, raw-query, live-view or sharing rights. Evidence retains its real audience assignments and source acquisition deadlines; do not add the creator or machine merely because it created the capture. A current viewer or recording-save initiator is authorized separately from the source's policy. Creator departure can leave collection running while their personal SharingIntent is suspended; team-managed sharing follows its own pinned-manager rules. Both outcomes must be visible without broadening access.

## User-facing explanation and acceptance cases

Policy editor/review shows the team, finite expiry, cumulative budgets and continuation after creator departure. Configuration preview and source discovery share the typed execution-authority summary; it has no authorization value. MCP `list_recordings` and policy-owned `list_live_sources` expose the same bounded fields as the browser. Manual sources cannot claim team automation. Missing/expired/revoked delegation explains the remedy without prompting developers to provision SSO credentials.

SC-PER-007 and SC-EXE-001 now include: creator leaves but team policy remains eligible; former creator cannot read/manage; binding removal, replacement, expiry and scoped denies stop renewal; repeated requests cannot reset spend; user-only exec cannot create an automation principal; ordinary delegated permission writers cannot add or remove the envelope; source and viewer authorization diverge correctly; multiple pinned sponsors must all remain valid; approval still rejects requester self-review. Check wrong policy/installation/workload, stale complete-deny observations and expiry after blocking reads as negative cases.

Personal offline-user execution and SCIM/CAEP integrations remain optional future modes. Normal browser session refresh is required for ergonomic human access; it is not a personal credential retained indefinitely for recurring jobs.

REQ-AUT-001 browser configuration follows [ADR-061](../docs/decisions/061-current-browser-configuration.md). Administrators manage the [closed session settings](contracts/browser-settings.schema.json) through a pinned protected ConfigMap, separately from issuer/group eligibility and credentials. Current source observations expire within five seconds; login, identity and refresh fail closed on suspension or stale configuration. Lower lifetime limits shorten existing sessions irreversibly; raising a maximum never renews them. Source replacement/rollback and reused epochs are rejected. Issuer, client or browser-origin changes invalidate prior sessions through a new epoch. A settings outage must still permit authenticated local sign-out and verified provider revocation without granting identity or evidence access. Bootstrap protection and post-restore epoch qualification remain separate prerequisites.


The existing get_policy_status browser/MCP workflow reports the current accepted
policy's shared execution, native-output reservation and pre-filter observation
charge counters with their original accepted ceilings and expiry. These pools
are distinct from each grant's reservations and remain shared after attachment
replacement, pause/resume and sharing controls. Conservative legacy/uncertain
charges are never described as measured gathered user data. The existing current
viewer/workload metadata authorization and final freshness checks remain required;
status confers no acquisition, evidence/history or personal continuation rights.


`request_policy_grant` uses one canonical browser/MCP input: the hub policy name
and exact UID, finite limits, optional observation limits/period and original
caller key. The server resolves protected source, accepted policy and compiled
review; no requester, authority, scope, Pod, capture or personal resultAccess is
accepted from this body. The immutable original actor/client/key lookup precedes
new source/settings reads. The request returns the existing grant detail and
review link. A different current human action-approver uses the existing review
and real IdP step-up flow; original reviewer/identity/step-up bounds govern the
SQL mutation after waits, including its database-clock predicate. Replays need
current metadata rights without demanding a new step-up for historical success.

`activate_policy` with `grant_id` is an explicit current-manager control of an
already accepted policy. It never reaccepts collection intent, renews original
expiry or resets shared/grant spend. Its immutable control receipt and replay do
not restore a pointer cleared by later authored-reference/control changes. The
existing encrypted public operation intent is acknowledged before source/control
mutations; unknown intent cannot dispatch, unknown outcome retains uncertainty.
`get_policy_status` reports the accepted collection kind and exact current attached
grant pointer for review, which does not itself assert collection readiness.
The source-first request observes one actual protected name/UID read before
current acceptance lookup, so a source observation expired during an outage can
recover without reauthorization. Healthy source observations last 30s with 15s
trigger polls; no ordinary five-versus-15 freshness gap is assumed.
The review reason `policyCollection` identifies this finite recurring-policy
approval. It is distinct from sensitive action reasons such as a raw-byte filter
or the installation's recording-approval setting; ordinary header collection is
not mislabeled as either. The existing grant detail/list and request result carry
this reason consistently in the browser and MCP contracts.

Finite onTrigger/before-zero policy network-header recording uses the actual
triggering Pod and original admitted occurrence key through the existing recorder
preview/request pipeline. Preview eligibility is not a permit: atomic admission
must match the actual recorder/snapshot action to accepted authority and preserve
the original charged grant and budgets. An internal policy principal never opens
a personal ad hoc review. Protected recording settings use the accepted pinned
issuer namespace without reauthenticating the creator; missing/changed settings
refuse new work, while creator departure alone does not revoke team execution.
Sensitive raw predicates remain unavailable until live observation authority and
the pre-filter node boundary are composed and qualified; ongoing arming remains
a separate required mode.

ADR-261's short finite increment prepays one original policy observation session;
there is no three-second renewal loop, credit stream, refund or automatic rearm.
Current five-second admission facts never become twenty-second observations.
Up to fifteen seconds of recording needs no renewal only when dispatch slack and
all original bounds fit. Longer finite/ongoing renewals and manual raw authority
remain separate unfinished first-release work, without fake policy/capture IDs.
