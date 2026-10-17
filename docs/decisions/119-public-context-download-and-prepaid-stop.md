# ADR-119: Public ordinary context downloads and prepaid Stop

Status: accepted implementation direction; runtime enablement remains gated.

The ordinary context case must lead to a native attachment, with the same shared
prepare/get operations through the console and MCP. Status reads cannot acquire
workers, refresh owners or byte authority. An explicit browser preparation POST
also attaches the existing SQL43-backed browser refresh owner synchronously;
neither a status GET nor MCP receives browser credentials. The original POST's
identity and shortest metadata deadline survive every blocking call.

An acknowledged Preparing result from explicit preparation may include
`continue_preparation: true`. This permits finite same-key POST continuation under
the original download/session deadlines. Passive status never includes it;
unknown replies stop automatic continuation. A normal same-origin attachment is
the native byte path; JavaScript does not buffer the file.

Cancellation is a restrictive operation. The currently authenticated original
actor/client can stop their own download after losing evidence scopes. Returning
ordinary artifact metadata would be inappropriate in that case. The implemented
response is the minimal download ID, `Cancelled` or `AlreadyTerminal`, and the
cancellation audit state. `AlreadyTerminal` does not distinguish successful,
failed or denied prior work; it never rewrites its previous terminal state.

Normal operation-audit exhaustion must not prevent Stop. Every newly admitted
public download therefore reserves one independent Stop obligation atomically
before native acquisition. The installation reserves finite slots, ciphertext,
provider attempts, minimized SQL and supported backup/WAL capacity. Stop fixes one
actor, request key, server request ID and timestamp; replay uses that exact
record. It cannot obtain new allowance with another key or extend the original
write opportunity. Transfer reservations and uncertain spend stay charged.

The restrictive SQL fence commits before encryption/provider I/O. One bounded
separately encrypted decision and independent acknowledgement follow. An
uncertain write is never repeated; only prepaid exact-object recovery is allowed.
A missed write opportunity is overdue, never an indefinite privacy exception.
Independent execution slots keep blocked normal business calls from occupying
Stop capacity; authentication/invalid-input admission remains bounded and does
not promise availability against arbitrary ingress denial of service.

Migration 00046 adds the three purpose-specific Stop tables and immutable public
session protocol marker, and admits prepare/get to the normal operation-audit
names. Historical component sessions are not silently backfilled with prepaid
capacity. Preparation refuses to advertise those sessions as the new public
protocol. Current read-only status remains available under existing metadata
rights.

This increment does not enable a public listener or the chart. Protected backing
producers, actual provider/SQL qualification and a finite independently verified
Stop object/SQL/backup retirement implementation are still required. A budget
number is not proof of physical storage/backend qualification. Retirement must
keep uncertain or overdue records charged and must not infer writer quiescence,
process death or backup absence from timeout alone. That follow-up reuses the
existing control-audit lifecycle mechanisms rather than introducing a generic
retry scheduler.

The reservation freezes its independently configured installation and accepted
issuer epoch. Restrictive Stop does not need acquisition/recovery authority.
Audit provider claims and acknowledgements separately lock the current
`fleet_current_trust` view before the Stop row and preserve its original short
observation after waits. A blocked or mismatched incarnation permits a pending
restriction receipt but no new audit attempt. A separately accepted normal
restart is not rejected merely because admission used an older postmaster;
restore still requires the independent reconciliation/epoch protocol.
