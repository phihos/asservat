package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
	"time"
)

func fleetContentionValues() (value.Administration, custodydb.FleetCurrentTrust, time.Time) {
	n := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	const uid = "11111111-1111-4111-8111-111111111111"
	a := value.Administration{InstallationID: uid, IssuerEpoch: uid, Issuer: "https://issuer.example", Revision: identity.Revision{UID: uid, Generation: 1, Digest: [32]byte{1}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Clients: []string{"client"}, DeliveryProfiles: []string{"context"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 2, MaxClusters: 1}
	r := custodydb.FleetCurrentTrust{InstallationID: id(uid), IssuerEpoch: id(uid), SourceUid: uid, SourceGeneration: 1, SourceDigest: append([]byte(nil), a.Revision.Digest[:]...), ObservedAt: ts(n.Add(-time.Second)), FreshUntil: ts(n.Add(4 * time.Second))}
	return a, r, n
}
func TestFleetObservationContentionRequiresCurrentExactPositiveSource(t *testing.T) {
	for _, mode := range []string{"same", "missing", "new-uid", "generation", "digest", "long-digest", "epoch", "installation", "source-suspended", "stored-suspended", "recovery", "stored-expired", "source-expired", "future", "older", "equal-time-extension", "missing-date", "infinite-date", "long-interval"} {
		t.Run(mode, func(t *testing.T) {
			a, r, n := fleetContentionValues()
			switch mode {
			case "missing":
				r = custodydb.FleetCurrentTrust{}
			case "new-uid":
				r.SourceUid = "22222222-2222-4222-8222-222222222222"
			case "generation":
				r.SourceGeneration++
			case "digest":
				r.SourceDigest[0]++
			case "long-digest":
				r.SourceDigest = append(r.SourceDigest, 0)
			case "epoch":
				r.IssuerEpoch = id("22222222-2222-4222-8222-222222222222")
			case "installation":
				r.InstallationID = id("22222222-2222-4222-8222-222222222222")
			case "source-suspended":
				a.Suspended = true
			case "stored-suspended":
				r.Suspended = true
			case "recovery":
				r.RecoveryBlocked = true
			case "stored-expired":
				r.FreshUntil = ts(n)
			case "source-expired":
				n = a.FreshUntil
			case "future":
				n = a.ObservedAt.Add(-time.Nanosecond)
			case "older":
				a.ObservedAt = r.ObservedAt.Time.Add(-time.Second)
				a.FreshUntil = n.Add(3 * time.Second)
			case "equal-time-extension":
				r.FreshUntil = ts(n.Add(3 * time.Second))
				a.ObservedAt = r.ObservedAt.Time
				a.FreshUntil = r.FreshUntil.Time.Add(time.Microsecond)
			case "missing-date":
				r.FreshUntil.Valid = false
			case "infinite-date":
				r.FreshUntil.InfinityModifier = 1
			case "long-interval":
				r.FreshUntil = ts(r.ObservedAt.Time.Add(31 * time.Second))
			}
			if unchangedFleetObservation(a, r, n) != (mode == "same") {
				t.Fatal("classification admitted changed/unavailable source")
			}
		})
	}
}
func TestFleetObservationContentionFinalRowCannotRefreshOrReplace(t *testing.T) {
	_, original, _ := fleetContentionValues()
	for _, mode := range []string{"same-instant", "observation", "expiry", "suspension", "recovery", "source", "digest", "generation", "epoch", "installation"} {
		t.Run(mode, func(t *testing.T) {
			current := original
			current.SourceDigest = append([]byte(nil), original.SourceDigest...)
			switch mode {
			case "same-instant":
				current.FreshUntil.Time = current.FreshUntil.Time.In(time.FixedZone("fixture", 3600))
			case "observation":
				current.ObservedAt.Time = current.ObservedAt.Time.Add(time.Microsecond)
			case "expiry":
				current.FreshUntil.Time = current.FreshUntil.Time.Add(time.Microsecond)
			case "suspension":
				current.Suspended = true
			case "recovery":
				current.RecoveryBlocked = true
			case "source":
				current.SourceUid = "other"
			case "digest":
				current.SourceDigest[0]++
			case "generation":
				current.SourceGeneration++
			case "epoch":
				current.IssuerEpoch = id("22222222-2222-4222-8222-222222222222")
			case "installation":
				current.InstallationID = id("22222222-2222-4222-8222-222222222222")
			}
			if sameFleetObservationRow(original, current) != (mode == "same-instant") {
				t.Fatal("final row adopted changed facts")
			}
		})
	}
}
func TestFleetObservationContentionOnlyExactServerLockAbort(t *testing.T) {
	for _, code := range []string{"55P03", "57014", "40001", "40P01", "08006", "08007", "23505"} {
		if fleetObservationLockTimeout(&pgconn.PgError{Code: code}) != (code == "55P03") {
			t.Fatal("non-lock failure classified", code)
		}
	}
	if fleetObservationLockTimeout(errors.New("55P03")) || fleetObservationLockTimeout(value.ErrUnavailable) || fleetObservationLockTimeout(nil) {
		t.Fatal("message or generic error supplied server abort")
	}
}

func TestFleetObservationContentionRejectsIndependentlyReactivatedIncarnation(t *testing.T) {
	_, _, n := fleetContentionValues()
	original := fleetObservationIncarnation{postmaster: n.Add(-time.Hour), database: 42, primary: true, at: n}
	for _, mode := range []string{"same", "postmaster", "database", "standby", "zero"} {
		current := original
		switch mode {
		case "postmaster":
			current.postmaster = current.postmaster.Add(time.Second)
		case "database":
			current.database++
		case "standby":
			current.primary = false
		case "zero":
			current = fleetObservationIncarnation{}
		}
		// Even if independently accepted activation makes both public rows match
		// with recovery=false, a changed actual incarnation cannot classify this call.
		if sameFleetObservationIncarnation(original, current) != (mode == "same") {
			t.Fatal("changed incarnation classified", mode)
		}
	}
}
