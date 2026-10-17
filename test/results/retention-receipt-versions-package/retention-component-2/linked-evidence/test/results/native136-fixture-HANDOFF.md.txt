# Native content fixture authentication and joined completion

Two test paths only. No product behavior, budgets, schema, role or deadline changes.

`nativeContentSessions` maps only the exact HTTP-shaped synthetic cookie to its
existing synthetic session record. Refresh, other cookies and cancellation deny;
ordinary `workerBrowserSession` remains unchanged. The actual C02 request remains
in the path. The first regression failed against live before the correction.

The existing HTTPS fixture now joins actual handler return before reading final
SQL/audit state. A focused actual TLS test completes the Content-Length body while
the handler remains blocked, then proves the barrier resolves only after return.
This barrier is test-owned, no public protocol acknowledgement or local-save proof.

Evidence: before handle74290 exit1 (expected cookie denial); after race44016 exit0
(integration1.123s); integration vet19811 exit0. Original compiled external fixture
selector remains UNRUN: `python3 scripts/test-custody.py --run
'^TestContextAdmissionWithRealServices$/^download-worker-native-content$'`.
No external services were run here; the parent owns native qualification.

Both Go checks used GOMAXPROCS=2 GOFLAGS=-p=2, dedicated stage/tmp and the retained
JSON overlays; logs and actual results are in evidence/. No active build remains.
The pending resume fixture is a separate stage and is not part of this payload.

Guard integration with manifest base hashes and dependencies; copy only changes/.
Then qualify the original native selector under the repository source/cleanup gate.
