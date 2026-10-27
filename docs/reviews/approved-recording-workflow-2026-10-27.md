# Complete the approved recording workflow

Scope: REQ-INV-001–003, REQ-AUT-003, REQ-UI-001/003/005, S-04 increment 12a.
Follow-up to ADR-249/252/253; no new capture profile editor or migration.

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
