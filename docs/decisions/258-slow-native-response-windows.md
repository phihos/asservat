# ADR-258 — Native response windows under slow delivery

Date: 2026-10-27. Status: draft; gate regression qualified, composed implementation pending.
Requirements: REQ-DLD-002/003/004. Maintainer clarification: AGENTS.md, 2026-10-20.

## Observed problem

ADR-220 already reconstructs ordinary download entitlement every 30 seconds.
Changing that constant does not remove the current transfer limit. ADR-248's
remote source opens one conversation for an entire prepaid 8 MiB window and
requires its original delivery lease for every chunk and acknowledgement.
The native operation, original peer proof, SQL owner, frame gate and HTTP
conversation also end at the first short observation. A fresh observation
cannot keep that window open after five seconds. The resulting 1.6 MiB/s
floor is arithmetic from the window and deadline, not measured throughput.

The regression `TestNativeResponseGateRechecksBeyondInitialObservation`
reproduced an immediate refusal after twelve simulated seconds, before a
second current check was called. The operation itself and its processing
proof were still within their original bounds. This is a component result,
not a slow-client or installed transfer measurement.

## Proposed implementation and qualification

Separate finite conversation ownership from each short disclosure observation.
The response gate prototype uses the existing twenty-second evidence-read
window as a fixed conversation ceiling and returns each new observation with
its own five-second cutoff. Revocation still closes it, and no observation
renews the original operation deadline. Preparation and observation operations
keep their existing behavior.

That gate change alone does **not** fix downloads. Before this decision can be
implemented or qualified:

- Compose renewed delivery leases within the same exact prepaid window and
  source cursor, preserving source/version, range, owner, generation, original
  operation and final-sink acknowledgement. An expired value cannot become
  current merely by rewriting a timestamp.
- Reuse the existing `RenewNativeOwner` SQL transition and its monotonic
  sequence constraints rather than adding another owner journal. The current
  adapter does not expose that transition. Fresh authority and peer checks
  must still guard renewal, with no replay of uncertain effects.
- Carry fresh caller observations between completed chunks without reviving
  a closed identity batch. Refresh an expired peer observation for the exact
  original worker when required; no replacement Pod, certificate or process.
  Preserve caller cancellation and actual token/certificate/worker/access
  cutoffs. Receiving bytes is separate from permission to disclose them.
- Keep keys/cursor open once per prepaid window; no per-chunk KMS calls,
  artificial smaller accounting windows, whole-file buffering or new retry.
- Measure real two-hop mTLS and final HTTPS delivery with slow final writes,
  exact bytes/resume, current-check counts and original-deadline/revocation
  negatives. Measure the composed SQL/S3/KMS path before claiming the selected
  interval is practical. A synthetic clock alone cannot establish throughput.

The final interval and protocol changes remain subject to those measurements.
The twenty-second prototype is an engineering candidate using an existing
bounded request interval, not a maintainer-selected number.

## Complexity gate for the proposed reuse

| Item | Answer |
|---|---|
| 1 | Source proves a whole 8 MiB window is confined to one five-second lease; component regression reproduces refusal despite a fresh callback. Installed slow-client rates remain unmeasured. |
| 2 | Yes: relaxed bounded download rechecks are explicitly authorized. The original five-second whole-window restriction is an agent choice. |
| 3 | Larger native files over slower links; the 4 KiB pod-status path rarely reaches this limit. |
| 4 | Reuse the local framed source's existing renewal and the native SQL owner's already-defined renewal transition; no external-project claim. |
| 5 | Target: zero new roles, credentials, endpoints or root keys. Any retained proof reader/token lifetime must be explicitly bounded and reviewed; it cannot gain another scope. |
| 6 | Target: zero new durable phases; the existing response/window/owner sequences account for renewal. More transient ownership states require reassessment. |
| 7 | Zero new configuration knobs; choose a documented finite bound from measurements. |
| 8 | Existing TLS, SQL, object-store and key adapters only. |
| 9 | One existing owner-row update per renewed lease; exact frequency and combined authorization/API cost must be measured. Keep one key opening and the existing read charge per 8 MiB window, not per delivery chunk. No added watcher or background poll. |
| 10 | No new schema anticipated: the SQL renewal query/guard already exist. Confirm rolling behavior before changing wire interpretation. Older/current sources still use their short bounds until composed. |
| 11 | Raising only the permission cache does not address the refusal. Smaller accounting windows would multiply audit/key/control cost; buffering would move the bottleneck and add memory. Reuse existing renewal before adding either mechanism. |

## Evidence so far

The gate regression failed with actual exit 1. After separating its conversation
ceiling from short observations it passes, including current revocation and
original-operation expiry. Complete authorization-domain, evidence and native
transport race packages pass. Logs are retained under the local recovery cache.
No installed or end-to-end slow-transfer success is claimed, and this work does
not complete the download requirement or change unrelated authority deadlines.
