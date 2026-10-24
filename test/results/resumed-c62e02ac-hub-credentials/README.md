# Hub process credential consolidation checks

ADR-222 reduces the public physical inventory from 79 to 43 credentials and the
owner inventory from six to one. The ten openable pools keep 32 physical hub
connections. This isolated component still requires ADR-219/221 integration
before public startup; no installed success is claimed.

Focused contract/bootstrap/PostgreSQL checks pass in check-04 (4.109 seconds).
Integration compilation passes there and again after the aggregate-role fixture
correction in check-06 (11.494 seconds). Kubernetes adapter checks pass in
check-05 (595.418 seconds). All recorded Go checks preserve 2,610 source hashes.
The spec/architecture/design/import gates pass in design-01 (11.142 seconds),
with 3,791 recorded sources unchanged. Commands and actual exits are retained.

Earlier failing attempts are preserved. Check-01 was manually interrupted during
normal client-go rate limiting; its stack is not evidence of a deadlock. Check-02
and check-03 exposed obsolete role-count expectations. Check-04's Kubernetes run
failed stale fixture call counts and an old second-owner-role index, then stopped
at the panic. Check-05 is the completed corrected Kubernetes run.

The independent review verifies the exact previous grant unions and unchanged
connection budget. Its fixture findings were corrected; the removed worker-owner
composition remains dependent on ADR-221. A later review caught the fixture's
attempt to open 81 aggregate-role connections against its 48-connection server.
The test now asserts PostgreSQL's installed limit and refusal of a changed limit;
existing 18+2 pool tests retain actual saturation, cancellation and reuse coverage.
These real SQL test bodies remain unrun on this candidate. No server limit changed.

Real scoped SQL role/pool operations and the complete installed workflow remain
pending on integrated sources. No external fixture was created by these checks.
The enclosing commit records the implementation, decision and contract tests;
the archive records per-run source hashes and actual results.
