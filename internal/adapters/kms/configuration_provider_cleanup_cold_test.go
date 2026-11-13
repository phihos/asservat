package kms

import (
	"context"
	"errors"
	"testing"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Cold maintenance must use real cleanup admission before selecting native/SQL
// proof. This component deliberately lacks that proof: it must reach its refusal
// without borrowing seeded credentials, requesting a JWT or calling the provider.
func TestConfigurationCleanupColdRefreshReachesRequiredNativeProof(t *testing.T) {
	f, in := configurationControlFixture(t, "cleanup-wrap", withConfigurationCleanup)
	gate, err := fleetapp.NewWorkerRuntimeAdmission(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	effects, err := newConfigurationProviderEffects(t.Context(), in, func(context.Context) ([]byte, error) {
		t.Error("cold refresh requested JWT before native proof")
		return nil, ErrKeyService
	}, func(context.Context) (time.Time, error) {
		t.Error("cold refresh bypassed installed native proof")
		return time.Time{}, ErrKeyService
	}, f.server.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = effects.close(context.Background()); effects.joinClosed() })
	worker := &InstalledConfigurationProviderEffects{input: in, effects: effects, admission: gate, root: t.Context()}
	call, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	notified := make(chan struct{})
	go func() {
		defer close(notified)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-call.Done():
				return
			case <-ticker.C:
				now := time.Now().UTC()
				notice := fleetvalue.Administration{InstallationID: in.InstallationID, IssuerEpoch: in.ClusterID, Issuer: "https://issuer.example", Revision: identity.Revision{UID: in.ClusterID, Generation: 1, Digest: [32]byte{1}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Clients: []string{"client"}, DeliveryProfiles: []string{"context"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 2, MaxClusters: 1}
				gate.NoteFleetObservation(notice)
				gate.NoteFleetCommitted(call, notice)
			}
		}
	}()
	err = worker.RefreshCleanup(call)
	cancel()
	<-notified
	var step interface{ FixedStep() string }
	if !errors.Is(err, ErrKeyService) || !errors.As(err, &step) || step.FixedStep() != "proof" {
		t.Fatal("cold cleanup failed before mandatory native proof", err)
	}
	for _, slot := range effects.cleanup {
		slot.mu.Lock()
		seeded := slot.current != nil
		slot.mu.Unlock()
		if seeded {
			t.Fatal("cold path adopted a credential without native proof")
		}
	}
	f.mu.Lock()
	logins, lookups := f.loginCalls, f.lookups
	f.mu.Unlock()
	if logins != 0 || lookups != 0 {
		t.Fatal("provider reached before native proof", logins, lookups)
	}
}
