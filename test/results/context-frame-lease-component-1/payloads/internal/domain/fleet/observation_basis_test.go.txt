package fleet

import (
	"testing"
	"time"
)

func TestObservationBasisRetainsExpiredIdentityForRestrictiveFence(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	b := ObservationBasis{InstallationID: "11111111-1111-4111-8111-111111111111", Database: DatabaseIncarnation{StartedAt: n.Add(-time.Hour), DatabaseOID: 42, SchemaVersion: 59}, SemanticVersion: 2, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	if !b.Valid() || !b.Current(n) || b.Current(b.FreshUntil) || !b.Valid() {
		t.Fatal("positive expiry changed structural fence identity")
	}
	missing := b
	missing.SemanticVersion = 0
	if !missing.Current(n) {
		t.Fatal("original absent root cannot be represented")
	}
	for _, change := range []func(*ObservationBasis){
		func(x *ObservationBasis) { x.SemanticVersion = -1 },
		func(x *ObservationBasis) { x.FreshUntil = x.FreshUntil.Add(time.Microsecond) },
		func(x *ObservationBasis) { x.Database.DatabaseOID = 0 },
		func(x *ObservationBasis) { x.InstallationID = "foreign" },
	} {
		bad := b
		change(&bad)
		if bad.Valid() || bad.Current(n) {
			t.Fatal("invalid original basis accepted")
		}
	}
}
