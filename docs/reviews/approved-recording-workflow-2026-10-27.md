# Complete the approved recording workflow

Scope: REQ-INV-001–003, REQ-AUT-003, REQ-UI-001/003/005, S-04 increment 12a.
Follow-up to ADR-249/252/253; no new capture profile editor. ADR-257 and migration 00100 correct authored packet custody funding.

## Observed gaps and changes

The capture controller refuses every approval-required review, and its page says
requests are unavailable. The approval page can decide/revoke but cannot resume
the original capture. The installer discards the existing protected identity
approval settings. Existing collector-packet uses an in-memory delivery sink;
the installed native journey collects pod-status, not approved packet evidence.

1. Add advisory `can_resume` and passive `can_resolve` to the detailed grant view, computed by the server
   for the exact current original issuer/subject/OAuth client, current capture
   scope, undenied collection eligibility and intact live approved grant. Do not
   compute authority from browser identity labels. Admission stays authoritative.
2. Allow a verified approval-required review to request approval. A pending
   review is a known state, distinct from uncertain collection. Use one stable
   preview-bound submission key through request, retry, pending review and the
   approval page, including remount/lost replies. Resume only the original
   preview; never refresh its selection or transfer a grant to another client.
   Show original-client guidance when browser resume is unavailable.
3. Render recorder assessment values and correct manual recorder retention to
   submission preparation, with a new rules digest; preserve the earlier-source
   rule for actual typed existing-source snapshots.
4. Pass through the already-defined optional `IdentityApprovals` installer
   settings into the protected identity source. Keep absent/default byte/digest
   compatibility and canonical validation; expose it through official Helm input.
5. Add a distinct `continuation-approved-recording` focus using the actual
   product installer/guards, connector collector endpoint and chart DaemonSet.
   MCP requests a metadata packet plan requiring administrator-configured
   approval; a second real Keycloak user with current action-approver binding
   signs in with fresh configured assurance and decides through the public
   browser API; submit the same preview after its real returned expiry, record
   through the published pinned Gadget, publish and download native PCAPNG.
   No grant SQL writes, preview-row changes or fixture authorization overrides.

The full browser packet authoring editor is outside this correction; reviews
already returned by supported server paths can request approval, and the original
browser requester can resume its reviewed plan. Native MCP collection plus
browser review is not described as complete browser packet authoring.

## Complexity gate

| # | Answer |
|---|---|
| 1 | Reproduced/UI-inspected: every approval-required browser review is blocked and no requester resume action exists. Actual independent-approved packet collection is unqualified. |
| 2 | Yes: accepted independent one-review workflow, same requester/client, first-release features; no new security requirement. |
| 3 | All deployments requiring recording approval; ordinary captures unchanged. |
| 4 | Reuse existing grant/preview/request/resolve APIs, existing client-bound idempotency and established approval-inbox controls; no novel authority mechanism. |
| 5 | Zero roles, credentials, Kubernetes permissions or production endpoints. Existing approval settings gain an installer passthrough. The native fixture enables the existing isolated collector with its already-reviewed privileges on a disposable runner only. |
| 6 | One additional UI state (awaiting approval); zero persisted product phases or fallback paths. |
| 7 | Zero machinery tuning/disable knobs. Existing administrator approval policy becomes installable. |
| 8 | Existing Keycloak/PostgreSQL/object store/Kubernetes/Gadget only. |
| 9 | At most one permission projection read for an approved same-client requester detail view; no additional grant lookup, watches, per-step rechecks or new polling. Resume uses existing API calls. One collector per enabled node remains the existing cost. |
| 10 | Additive optional settings/output fields; no migration. Hiding the UI still leaves MCP request and browser review intact. Absence/default config byte/digest compatibility is checked. |
| 11 | Removing a disabled button alone loses pending-state/idempotency and original-client safety. New public start endpoints, another grant store or fixture authorization would cost more and are unnecessary. |

Proceed: demonstrated product benefit with bounded existing mechanisms.

## Qualification and runner budget

Keep local Go/React/API/schema/Helm checks privilege-free. All collector execution
is confined to the guarded disposable GitHub runner; never run it on this host.
Preserve the existing collector and journey focuses; the new focus omits their
unrelated repeated scenarios and runs exactly its named approved-recording path.

Measured baselines: journey run 40496803811 used 674.5 seconds of Go execution;
installed focus began at harness second 470.8 and finished at 684.9, including
revoke/expiry/deletion cases irrelevant to this new focus. Collector-packet run
40493219201 built the published-gadget collector in 68.5 seconds. The product
preview default is 120 seconds (`owner_promotion.go`), not a test setting.

Budget estimate only: retain full installer/guard setup, replace the unrelated
journey cases with independent review + actual 120-second expiry wait + one
short recording/native download and required negatives, and add the existing
collector build. Expected to fit the 20-minute runner limit; measure the first
actual candidate before claiming this. Do not shorten the product default,
mutate a preview or split one oversized test to evade the bound.

Freeze all relevant sources for qualification. Record actual selected tests,
exits, original identities/deadlines, native hashes, cleanup and uncertainty.


## Candidate fixture details

`continuation-approved-recording` retains the installed fast feature fixture and
adds an exact `approved-recording` child test. The collector image is built with
`gadget,netgo,osusergo`; fetched OCI blobs are individually digest-checked. The
regional installer provisions its real node endpoint and attestation RBAC; the
official chart renders the DaemonSet. Guard absence refuses before any harness
setup. Go execution is bounded to 18 minutes inside the existing 20-minute job.
All collector-related sources, gadget fetch script and workflow are hashed.

The distinct reviewer is a real member of the existing eligible group, whose
focus-only operator AccessBinding includes `action-approver`. Self-approval and
same-human cross-client continuation are refused. The real provider's built-in
`acr` scope supplies signed assurance; this reference flow selects fresh password
LoA1 and does not claim MFA. The same reviewer's existing browser session follows
`/auth/step-up`, sees a fresh provider form, completes PKCE and replaces its CSRF
before deciding. Approval/readback use public operations, not SQL grant fixtures.

The existing Restricted signal workload supplies HTTP traffic on port 8080;
only its exact reviewed Pod receives synthetic requests through Kubernetes' Pod
proxy. The operator reserves actual packet ciphertext bytes while retaining the
existing four-record/16-object root ceiling. The output SHA-256 and length must
match authenticated native-download metadata and tshark must read nonempty TCP
port-8080 packets. The report records actual original identities, review expiry,
submit time, remaining real wait and native bytes; the installed end-to-end flow remains unqualified; failed runs are recorded
below.


Download preparation is an effect, so its initial call receives one attempt.
An uncertain reply or acknowledged failure ends this qualification; only a
returned `continue_preparation` acknowledgement permits another exact same-key
prepare. Passive download status reads can retry. This matches the original
installed journey's uncertainty contract.


Review correction: approval-detail resolution is offered only after an approved
decision, with the close-if-unstarted effect named on its button. Pending and
denied review show no such control. A server-computed original-client guidance
hint is restricted to the same original human on another client while the marked
plan is Approved; it costs no additional read or persisted state. Passive outcome
recovery needs current read scope, independently of permission to start a capture.
The public deterministic key is tested against actor/client/preview changes and
closed-preview resubmission; a new intent always requires a new preview. The
native focus also exercises wrong-client/wrong-human submission before and after
acceptance and a closed preview under a new key, without another capture or wait.

## Collector-enabled executor input correction

Exact frozen-head native attempt 40518896278/2 ended FAIL in 14m29s (Go
583.567s). The collector enrolled/was Available, but the regional API executor
rejected `workload/inputs` before any input metadata reads. The pure reproduction
shows three mounted objects (`regional-inputs`, `regional-evidence`,
`connector-nodes`) versus two executor input pins. Consequently preview returned
NotAvailable and no approved capture/native-download outcome was qualified.

The installer now carries the listener Secret's exact UID/resourceVersion from
its existing acknowledged create/exact read into the executor settings. It adds
GET of only that Secret to the existing connector namespace Role; Kubernetes RBAC
cannot enforce metadata-only GET, but this same process already mounts the entire
listener key. Runtime reads explicitly request PartialObjectMetadata. The complete
input-set equality, live UID/version checks and all other attestation remain.

Incremental cost: one metadata GET per existing input-proof rebuild, zero new
credentials, watches, listeners, background tasks or exposure to another process.
The collector-disabled settings bytes and startup digest match the original
builder's captured baselines. Pure tests reject omitted/replaced/changed-version
inputs and verify exact named GET without list/watch/update. The installed focus
also checks actual connector-account permission reviews for the exact Secret,
unrelated names, list/watch/update and another namespace. Those native assertions
remain unqualified until the next agreed frozen-candidate run.


## Audited grant outcome correction

Frozen native run 40531588743 passed regional executor composition and reached
preview/request, then failed at the first browser decide_review (the self-review
refusal), before the independent review. The Go suite exited FAIL in 473.797s;
that subtest took 9.73s. No complete approval/packet/publication/download result
is qualified by that run.

The public audited wrapper already treats decide_review/revoke_grant as mutations,
but the audit domain's closed effect-operation list omitted them. Building either
an acknowledged or uncertain outcome therefore failed and the browser returned
503. Production GrantOperations plus AuditedOperations with a synthetic use case
and audit gate reproduces that failure. Separate application-service tests cover
the self-refusal's pending/no-decision backing ledger state; the presentation fake
is not SQL or mutation-safety proof.

The correction adds only those two existing mutation names to the closed list.
A schema-validated returned grant ID classifies an acknowledged decision/revocation,
including idempotent replay, as accepted. Malformed output is suppressed and stays
unknown. Immutable self-approval refusal is denied with no mutation effect: that requester
cannot have an accepted prior decision through any client. A retry whose reviewer
lost rights can still have an earlier committed same-key attempt, so uncertainty
is retained. Reads remain effect none; unknown operation/effect pairs still refuse.
Encrypted intent acknowledgement remains before dispatch and failed outcome audit
suppresses a response without erasing an acknowledged effect. No migration, API
request, credential, watch, background task or deadline change is introduced.
Future browser-operation failures also collect the existing bounded diagnostics.

## Installed capacity correction and compatibility

Run 40538171521 on c5db1e11 reached self-approval refusal, independent fresh
approval and the real 120-second preview wait, then refused submission with
CapacityUnavailable. A failing pure regression reproduced the exact 39,714,816
source bytes becoming a 6,176,768-byte child while one packet reservation needs
9,928,704 bytes. This is not evidence of a physically exhausted administrator
quota. ADR-257 records the bounded formula, atomic legacy backfill, exact
pre/post graph checks, unchanged IDs/spend/deadlines and rollback refusal.
Migration 00100 belongs to this correction; history moves to 00101 and policy
grants to 00102. No installed packet result has passed yet.

Run 40546623947 on 79694a43 refused facts/current before admission; explicit
resolution then closed the unstarted intent. Preserve the original failure,
record the initial public code and closed resolution state, and distinguish
existing fact/bound predicates with private fixed labels. A pure retained-plan
regression covers identity/recovery/target/capability/retention refusal followed
by explicit closure. No replacement preview, grant retry, longer operation or
per-step authority refresh is introduced. Assess the aggregate current reads
against the actual expired bound before proposing an efficiency change.

Diagnostic run 40551543601 on cdcbb4fe was cancelled at the existing 20-minute
job limit without a terminal Go result or environment report. Package setup
took 10m17s (17:34:49–17:45:06 UTC), leaving less time than the preceding
585-second native suite needed. This is an incomplete infrastructure run, not
another facts/current result or cleanup pass. Its available logs remain archived.

The same existing tshark setup now has a three-minute step bound and a single
170-second apt bound with five seconds of termination grace. Acquisition retries
are disabled, network and lock waits are bounded, partial index failures fail,
and package errors remain visible. Working preinstalled tshark/capinfos skip apt;
both versions are recorded. capinfos is supplied by tshark's existing required
wireshark-common dependency. No package cache, extra image, test retry, product
deadline change or longer job is introduced. A setup failure cannot start the
native suite. The diagnostic capture result remains pending.
