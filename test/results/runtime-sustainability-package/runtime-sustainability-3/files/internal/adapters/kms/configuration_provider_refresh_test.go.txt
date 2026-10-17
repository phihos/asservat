package kms

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func TestConfigurationProviderRefreshNeverFallsBackToLegacyProof(t *testing.T) {
	s, f := configurationJoinFixture(t)
	admission, err := fleetapp.NewWorkerRuntimeAdmission(s.root)
	if err != nil {
		t.Fatal(err)
	}
	s.admission = admission
	t.Cleanup(admission.Close)
	var oldProof atomic.Int32
	s.effects.wrap.currentProof = func(context.Context) (time.Time, error) { oldProof.Add(1); return time.Now().Add(5 * time.Second), nil }
	call, end := context.WithTimeout(t.Context(), 5*time.Second)
	defer end()
	// The fixture deliberately has no concrete current reader/recovery. A
	// synthetic old callback must not fill those missing installed predecessors.
	if err := s.effects.wrap.refreshConfiguration(call, s); err == nil {
		t.Fatal("missing native/SQL runtime accepted legacy callback")
	}
	if oldProof.Load() != 0 {
		t.Fatal("installed runtime called legacy authority callback")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 0 || f.lookups != 0 || f.renewCalls != 0 || f.revokes != 0 {
		t.Fatal("missing native/SQL proof dispatched provider I/O")
	}
}

func TestConfigurationProviderRefreshRejectsAnotherWorkersSlot(t *testing.T) {
	s, f := configurationJoinFixture(t)
	other, _ := configurationJoinFixture(t)
	if err := s.effects.wrap.refreshConfiguration(t.Context(), other); err == nil {
		t.Fatal("cross-worker credential slot admitted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 0 || f.lookups != 0 || f.renewCalls != 0 || f.revokes != 0 {
		t.Fatal("foreign worker triggered provider I/O")
	}
	s.effects.wrap.mu.Lock()
	defer s.effects.wrap.mu.Unlock()
	if s.effects.wrap.active || s.effects.wrap.failures != 0 || s.effects.wrap.uncertain {
		t.Fatal("foreign worker altered original slot")
	}
}

func TestConfigurationProviderRecoveryComparisonKeepsOriginalAge(t *testing.T) {
	now := time.Now().UTC()
	original := fleet.RecoveryState{InstallationID: "fbe5a178-1e6d-48cc-9b9f-146db12c2e73", IssuerEpoch: "1a989cc4-e436-454d-b922-88c4bc72a0de", Revision: identity.Revision{UID: "2c031c76-fc46-442e-b815-e855493c1cc1", Generation: 1, Digest: [32]byte{1}}, ObservedAt: now.Add(-time.Second), FreshUntil: now.Add(2 * time.Second)}
	current := original
	current.ObservedAt = now
	current.FreshUntil = now.Add(5 * time.Second)
	if !configurationProviderSameRecovery(original, current, now) {
		t.Fatal("same independently current original revision rejected")
	}
	if configurationProviderSameRecovery(original, current, original.FreshUntil) {
		t.Fatal("new read refreshed the original recovery end")
	}
	for _, change := range []func(*fleet.RecoveryState){func(v *fleet.RecoveryState) { v.Revision.Generation++ }, func(v *fleet.RecoveryState) { v.Revision.Digest[0]++ }, func(v *fleet.RecoveryState) { v.IssuerEpoch = "bbafbe54-c18f-40d9-ac5d-a330f25d2482" }, func(v *fleet.RecoveryState) { v.InstallationID = "bbafbe54-c18f-40d9-ac5d-a330f25d2482" }} {
		v := current
		change(&v)
		if configurationProviderSameRecovery(original, v, now) {
			t.Fatal("changed recovery identity adopted")
		}
	}
}

func TestConfigurationProviderHealthyHintDoesNotEnterExpensiveQueue(t *testing.T) {
	s, f := configurationJoinFixture(t)
	fixtureNow := time.Now().UTC()
	s.effects.wrap.control.now = func() time.Time { return fixtureNow }
	// Test-only independent setup of an already healthy finite credential; no
	// installed authority is supplied by this existing lifetime fixture.
	if err := s.effects.wrap.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	gate, err := fleetapp.NewWorkerRuntimeAdmission(s.root)
	if err != nil {
		t.Fatal(err)
	}
	s.admission = gate
	defer gate.Close()
	f.mu.Lock()
	originalLogin, originalLookup, originalRenew, originalRevoke := f.loginCalls, f.lookups, f.renewCalls, f.revokes
	f.mu.Unlock()
	// A successful refresh retains its original one-second anti-spin end.
	// Calling before that end is unavailable, even if the local token is
	// healthy. This is scheduling, not a queued native/provider operation.
	if err := s.effects.wrap.refreshConfiguration(t.Context(), s); err == nil {
		t.Fatal("successful refresh anti-spin interval was bypassed")
	}
	f.mu.Lock()
	unchanged := f.loginCalls == originalLogin && f.lookups == originalLookup && f.renewCalls == originalRenew && f.revokes == originalRevoke
	f.mu.Unlock()
	if !unchanged {
		t.Fatal("local backoff hint dispatched provider work")
	}
	s.effects.wrap.mu.Lock()
	next := s.effects.wrap.next
	current := s.effects.wrap.current
	healthyAtNext := current != nil && next.Before(current.value.until) && next.Before(current.value.reauthenticateAt()) && next.Before(current.value.renewAt())
	s.effects.wrap.mu.Unlock()
	if !healthyAtNext {
		t.Fatal("fixture credential is not healthy at its original next scheduling instant")
	}
	// No background owner runs in this fixture. Advance only its local clock,
	// preserving every original credential/backoff date and the real FIFO.
	fixtureNow = next
	busy, err := gate.WaitCapacity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Release()
	call, end := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer end()
	if err := s.effects.wrap.refreshConfiguration(call, s); err != nil {
		t.Fatal("healthy local hint queued behind unrelated work", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 1 || f.renewCalls != 0 || f.revokes != 0 {
		t.Fatal("healthy hint dispatched provider work")
	}
}

func TestConfigurationProviderQueuedRefreshKeepsCallerEndAndNeverUsesLegacyProof(t *testing.T) {
	s, f := configurationJoinFixture(t)
	gate, err := fleetapp.NewWorkerRuntimeAdmission(s.root)
	if err != nil {
		t.Fatal(err)
	}
	s.admission = gate
	defer gate.Close()
	busy, err := gate.WaitCleanup(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Release()
	var proof atomic.Int32
	s.effects.wrap.currentProof = func(context.Context) (time.Time, error) { proof.Add(1); return time.Now().Add(5 * time.Second), nil }
	call, end := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer end()
	if err := s.effects.wrap.refreshConfiguration(call, s); err == nil {
		t.Fatal("expired queued caller reported refresh")
	}
	if call.Err() == nil || proof.Load() != 0 {
		t.Fatal("queued refresh renewed caller or used legacy proof")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 0 || f.lookups != 0 || f.renewCalls != 0 || f.revokes != 0 {
		t.Fatal("expired waiting operation dispatched provider work")
	}
}
