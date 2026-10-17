package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func ownerBridgeTupleFixture() (initialRuntimeOwnerFleet, custodydb.FleetCurrentTrust, time.Time, time.Time) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	source := initialRuntimeOwnerFleet{installation: "00000000-0000-4000-8000-000000000001", issuer: "00000000-0000-4000-8000-000000000002", revision: identity.Revision{UID: "original-source", Generation: 7, Digest: [32]byte{3}}, observed: now.Add(-time.Second), until: now.Add(4 * time.Second)}
	row := custodydb.FleetCurrentTrust{InstallationID: id(source.installation), IssuerEpoch: id(source.issuer), SourceUid: source.revision.UID, SourceGeneration: source.revision.Generation, SourceDigest: append([]byte(nil), source.revision.Digest[:]...), ObservedAt: ts(now.Add(-2 * time.Second)), FreshUntil: ts(now.Add(3 * time.Second))}
	return source, row, now.Add(2 * time.Second), now
}

func TestInitialRuntimeOwnerBridgeExactFleetAndOriginalIntervals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   error
		change func(*initialRuntimeOwnerFleet, *custodydb.FleetCurrentTrust, *time.Time, *time.Time)
	}{
		{name: "positive-independent-observation-dates"},
		{name: "installation", want: cfg.ErrChanged, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			r.InstallationID = id("00000000-0000-4000-8000-000000000003")
		}},
		{name: "issuer", want: cfg.ErrChanged, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			r.IssuerEpoch = id("00000000-0000-4000-8000-000000000003")
		}},
		{name: "source-uid", want: cfg.ErrChanged, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			r.SourceUid = "replacement"
		}},
		{name: "same-uid-generation", want: cfg.ErrChanged, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			r.SourceGeneration++
		}},
		{name: "same-uid-digest", want: cfg.ErrChanged, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			r.SourceDigest[31]++
		}},
		{name: "truncated-digest", want: cfg.ErrChanged, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			r.SourceDigest = r.SourceDigest[:31]
		}},
		{name: "suspended", want: cfg.ErrUnavailable, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, _ *time.Time) { r.Suspended = true }},
		{name: "effective-recovery-blocked", want: cfg.ErrUnavailable, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			r.RecoveryBlocked = true
		}},
		{name: "preflight-expired-even-with-new-row", want: cfg.ErrUnavailable, change: func(s *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, u, n *time.Time) {
			*n = s.until
			r.ObservedAt = ts(*n)
			r.FreshUntil = ts(n.Add(5 * time.Second))
			*u = r.FreshUntil.Time
		}},
		{name: "original-caller-expired", want: cfg.ErrUnavailable, change: func(_ *initialRuntimeOwnerFleet, _ *custodydb.FleetCurrentTrust, u, n *time.Time) { *n = *u }},
		{name: "locked-row-expired", want: cfg.ErrUnavailable, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, u, n *time.Time) {
			*n = r.FreshUntil.Time
			*u = n.Add(time.Second)
		}},
		{name: "preflight-future", want: cfg.ErrUnavailable, change: func(s *initialRuntimeOwnerFleet, _ *custodydb.FleetCurrentTrust, _, n *time.Time) {
			s.observed = n.Add(time.Second)
		}},
		{name: "row-future", want: cfg.ErrUnavailable, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, n *time.Time) {
			r.ObservedAt = ts(n.Add(time.Second))
		}},
		{name: "source-interval-too-wide", want: cfg.ErrUnavailable, change: func(s *initialRuntimeOwnerFleet, _ *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			s.observed = s.until.Add(-5*time.Second - time.Nanosecond)
		}},
		{name: "row-interval-too-wide", want: cfg.ErrUnavailable, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			r.ObservedAt = ts(r.FreshUntil.Time.Add(-30*time.Second - time.Nanosecond))
		}},
		{name: "callback-cannot-exceed-source", want: cfg.ErrUnavailable, change: func(s *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, u, _ *time.Time) {
			r.FreshUntil = ts(s.until.Add(time.Second))
			*u = s.until.Add(time.Nanosecond)
		}},
		{name: "callback-cannot-exceed-row", want: cfg.ErrUnavailable, change: func(_ *initialRuntimeOwnerFleet, r *custodydb.FleetCurrentTrust, u, _ *time.Time) {
			*u = r.FreshUntil.Time.Add(time.Nanosecond)
		}},
		{name: "closed-source-interval", want: cfg.ErrUnavailable, change: func(s *initialRuntimeOwnerFleet, _ *custodydb.FleetCurrentTrust, _, _ *time.Time) {
			s.until = s.observed
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, row, until, now := ownerBridgeTupleFixture()
			if tc.change != nil {
				tc.change(&s, &row, &until, &now)
			}
			err := s.check(row, until, now)
			if !errors.Is(err, tc.want) {
				t.Fatal("incorrect exact source admission", err, tc.want)
			}
		})
	}
}

func TestInitialRuntimeOwnerBridgeMinimumBoundCannotRenew(t *testing.T) {
	s, row, caller, now := ownerBridgeTupleFixture()
	inputs := []time.Time{caller, s.until, row.FreshUntil.Time, now.Add(time.Second)}
	for shift := range len(inputs) {
		var reordered []time.Time
		for i := range len(inputs) {
			reordered = append(reordered, inputs[(i+shift)%len(inputs)])
		}
		actual := ownerBridgeEarlier(reordered[0], reordered[1:]...)
		if !actual.Equal(inputs[3]) {
			t.Fatal("reordering widened original minimum", actual)
		}
	}
	// Observing the same revision again does not replace the first preflight's
	// original cutoff, even if the locked SQL row has a later positive interval.
	row.ObservedAt = ts(now)
	row.FreshUntil = ts(now.Add(5 * time.Second))
	end := ownerBridgeEarlier(s.until, row.FreshUntil.Time)
	if !end.Equal(s.until) || s.check(row, end, s.until) == nil {
		t.Fatal("new observation revived expired preflight")
	}
}

func TestInitialRuntimeOwnerBridgeRejectsUnavailablePreflightBeforeSQL(t *testing.T) {
	now := time.Now().UTC()
	a := fleet.Administration{InstallationID: "00000000-0000-4000-8000-000000000001", IssuerEpoch: "00000000-0000-4000-8000-000000000002", Issuer: "https://synthetic.invalid", Revision: identity.Revision{UID: "source", Generation: 1, Digest: [32]byte{1}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Clients: []string{"installer"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 1, MaxClusters: 1}
	for _, name := range []string{"suspended", "invalid", "expired", "canceled"} {
		t.Run(name, func(t *testing.T) {
			v := a
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "suspended":
				v.Suspended = true
			case "invalid":
				v.Clients = nil
			case "expired":
				v.FreshUntil = v.ObservedAt
			case "canceled":
				cancel()
			}
			// No pool/credentials: failure must occur before SQL or callback access.
			s := &InitialRuntimeBridgeSQL{}
			called := false
			err := s.WithInitialRuntimeOwnerBridge(ctx, v, func(context.Context) error { called = true; return nil })
			if !errors.Is(err, cfg.ErrUnavailable) || called {
				t.Fatal("invalid preflight reached SQL/effect", err, called)
			}
		})
	}
}
