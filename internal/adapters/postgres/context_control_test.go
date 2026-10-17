package postgres

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	capture "asservat.local/asservat/internal/domain/capture"
)

func TestControlCapacitySeparatesFullAndRetainedReplayBacking(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	root, allocation := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	pool := custodydb.ContextControlPool{RootID: id(root), Configured: true, Revision: 1, ValidUntil: ts(now.Add(time.Minute)), FullLimit: 100, ReplayLimit: 200, BackedFull: 10, BackedReplay: 20}
	account := custodydb.ContextControlAccount{RootID: id(root), AllocationID: id(allocation), Configured: true, Revision: 1, ValidUntil: ts(now.Add(30 * time.Second)), FullLimit: 10, ReplayLimit: 20, ChargedFull: 9, ChargedReplay: 19}
	until, err := controlCapacityDeadline(pool, account, root, allocation, now)
	if err != nil || !until.Equal(account.ValidUntil.Time) {
		t.Fatal("original account deadline lost", until, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*custodydb.ContextControlPool, *custodydb.ContextControlAccount)
		want   error
	}{
		{"full exhausted", func(_ *custodydb.ContextControlPool, a *custodydb.ContextControlAccount) { a.ChargedFull = 10 }, capture.ErrCapacity},
		{"replay exhausted", func(_ *custodydb.ContextControlPool, a *custodydb.ContextControlAccount) { a.ChargedReplay = 20 }, capture.ErrCapacity},
		{"unbacked account", func(p *custodydb.ContextControlPool, _ *custodydb.ContextControlAccount) { p.BackedFull = 9 }, capture.ErrCapacity},
		{"legacy pool is not current capacity", func(p *custodydb.ContextControlPool, _ *custodydb.ContextControlAccount) { p.Configured = false }, capture.ErrChanged},
		{"legacy account is not current capacity", func(_ *custodydb.ContextControlPool, a *custodydb.ContextControlAccount) { a.Configured = false }, capture.ErrChanged},
		{"different workload allocation", func(_ *custodydb.ContextControlPool, a *custodydb.ContextControlAccount) { a.AllocationID = id(root) }, capture.ErrChanged},
		{"different installation", func(p *custodydb.ContextControlPool, _ *custodydb.ContextControlAccount) { p.RootID = id(allocation) }, capture.ErrChanged},
		{"expired original account", func(_ *custodydb.ContextControlPool, a *custodydb.ContextControlAccount) { a.ValidUntil = ts(now) }, capture.ErrChanged},
		{"pool paused", func(p *custodydb.ContextControlPool, _ *custodydb.ContextControlAccount) { p.Paused = true }, capture.ErrChanged},
		{"account paused", func(_ *custodydb.ContextControlPool, a *custodydb.ContextControlAccount) { a.Paused = true }, capture.ErrChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, a := pool, account
			tc.change(&p, &a)
			if _, err := controlCapacityDeadline(p, a, root, allocation, now); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
	// No later check renews the initially selected bound, even when it waited.
	if _, err := controlCapacityDeadline(pool, account, root, allocation, until); !errors.Is(err, capture.ErrChanged) {
		t.Fatal("expired capacity accepted", err)
	}
}

func TestControlConfigurationObservationCannotRenewAfterBlockingWork(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	root := "11111111-1111-4111-8111-111111111111"
	if !validControlBounds(root, 1, 2, 10, 20, now.Add(time.Hour), now, now.Add(5*time.Second)) {
		t.Fatal("valid update rejected")
	}
	if validControlBounds(root, 1, 3, 10, 20, now.Add(time.Hour), now, now.Add(5*time.Second)) {
		t.Fatal("revision skipped")
	}
	if validControlBounds(root, 1, 2, 10, 20, now.Add(time.Hour), now, now.Add(6*time.Second)) {
		t.Fatal("overlong source accepted")
	}
	if controlConfigurationCurrent(now.Add(5*time.Second), now.Add(time.Hour), now, now.Add(5*time.Second)) {
		t.Fatal("source deadline renewed")
	}
}
