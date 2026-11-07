package postgres

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-311: an operation's recovery observation lasts the recheck interval but
// never past the trust row's own fresh_until; internal configuration facets
// keep five seconds; a blocked row is never current.
func TestRecoveryObservationUsesRecheckIntervalWithinTrustRow(t *testing.T) {
	n := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	uid := "11111111-1111-4111-8111-111111111111"
	row := custodydb.FleetCurrentTrust{InstallationID: id(uid), IssuerEpoch: id(uid), SourceUid: uid, SourceGeneration: 1, SourceDigest: make([]byte, 32), ObservedAt: ts(n.Add(-time.Second)), FreshUntil: ts(n.Add(29 * time.Second))}
	row.SourceDigest[0] = 1
	r, err := recoveryStateWithin(row, n, n, identity.AuthorityRecheckInterval)
	if err != nil || !r.FreshUntil.Equal(row.FreshUntil.Time) {
		t.Fatal("operation recovery observation not bounded by the trust row", err, r.FreshUntil)
	}
	row.FreshUntil = ts(n.Add(29*time.Second + 500*time.Millisecond))
	row.ObservedAt = ts(n)
	if r, err = recoveryStateWithin(row, n.Add(-time.Second), n, identity.AuthorityRecheckInterval); err != nil || !r.FreshUntil.Equal(n.Add(29*time.Second)) {
		t.Fatal("operation recovery observation exceeded the recheck interval", err, r.FreshUntil)
	}
	if r, err = recoveryState(row, n, n); err != nil || !r.FreshUntil.Equal(n.Add(5*time.Second)) {
		t.Fatal("internal recovery facet changed its five-second interval", err, r.FreshUntil)
	}
	row.RecoveryBlocked = true
	if _, err = recoveryStateWithin(row, n, n, identity.AuthorityRecheckInterval); err == nil {
		t.Fatal("blocked recovery observed as current")
	}
}
