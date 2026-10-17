# Initial process-owned connector key checkpoint

Five hash-guarded files, independent of pending migration49/ADR126 renewal work. No live files, modules, SQL, public wire or issuer configuration changed. The new key owner uses existing private audited initial enrollment, historical original-claim lookup and separately current peer registration. It is not a complete deployed connector or a renewal/server producer.

Actual regression: NativeConnectorIdentity previously requested a certificate with TLS1.3 Version but no SignatureSchemes. A process-owned GetClientCertificate callback correctly rejected that request, unlike earlier static fixture callbacks. initial-before.log exits1 only at the new production callback composition case. The fixed preflight lists accepted TLS1.3 signing schemes; actual connection negotiation, certificate validation and current registry checks remain mandatory.

New ConnectorCredentials generates one process-local P-256 key/CSR; preserves exact original bootstrap and five-minute deadline across unknown replies; verifies historical exact key/claim and fixed claim-derived thirty-minute leaf end; independently checks current activation; bounds one attempt with a one-second spacing; binds caller work to owning context; copies public snapshots; cancels/joins active enrollment and disables retained signers on Close. Protected startup must suppress core dumps before construction. No private key is imported/exported. The bootstrap digest is discarded after positive installation, never sent as a public bearer. Enroll after successful installation checks current registry and does not sign again.

Checks (TMPDIR=/home/phil/.cache/asservat-build/tmp, GOMAXPROCS=2, -p2, sparse overlay):
- initial-before.log: expected failing callback composition, exit1.
- initial-after.log: focused ownership/claim/current/close regressions race exit0,1.068s.
- initial-race.log: full mtls/fleet race suites exit0,8.559s/2.038s.
- initial-tls-final.log: additional actual loopback TLS with process-owned key/callback and same-client current revocation, plus all new regressions, race exit0,1.081s.
- initial-vet-final.log: both affected packages vet exit0 after final TLS test.

Tests use synthetic initial bootstrap/issuer/registry services. They do not qualify real SQL/OpenBao/bootstrap delivery, deployment or renewal. Parent can integrate this checkpoint while49 remains staged, then include it in combined gates. No migration/schema inventory change is needed for these five files.

Remaining full126 task: actual independent serverAuth issuance/activation, current client renewal, process/restart admission and protected provisioning/runtime supervision. Audit pair/lifecycle reuse is approved subject to exact48 compatibility and independent footprint/history backing for credential business rows/high-watermarks/active references. ROLE-BOUNDARY.md replaces the earlier RLS idea: complete-history/no-RLS installation invariant remains; writes use actual session-role checks, narrow definer transitions and separate grants. No49 source/SQL extension is included in this checkpoint.
