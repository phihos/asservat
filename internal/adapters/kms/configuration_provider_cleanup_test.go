package kms

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
)

func TestConfigurationCleanupHealthyReuseDoesNotEnterNativeQueueOrRenew(t *testing.T) {
	admission, err := fleetapp.NewWorkerRuntimeAdmission(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Close()
	now := time.Now()
	s := &InstalledConfigurationProviderEffects{admission: admission, effects: &configurationProviderEffects{}, input: contracts.HubWorkerDeployment{ProviderAuthentication: &contracts.ConfigurationProviderAuthentication{CleanupAudit: contracts.OwnerPublicTransit{Mount: "audit", Key: "original"}}}}
	for i := range s.effects.cleanup {
		s.effects.cleanup[i] = &ownerProviderLifetime{root: t.Context(), control: &ownerProviderControl{now: func() time.Time { return now }}, next: now.Add(time.Second), current: &ownerProviderHeldCredential{value: &ownerProviderCredential{until: now.Add(300 * time.Second), hardUntil: now.Add(900 * time.Second), jwtUntil: now.Add(600 * time.Second), observed: now}}}
	}
	// A post-login scheduling floor limits new control calls, not existing
	// healthy credential use for the next row in the same bounded page.
	if err := s.RefreshCleanup(t.Context()); err != nil {
		t.Fatal("healthy reuse entered refresh admission or refused", err)
	}
	s.effects.cleanup[2].uncertain = true
	if err := s.RefreshCleanup(t.Context()); err == nil {
		t.Fatal("uncertain verifier reused during control backoff")
	}
}

// The real pinned HTTP control is exercised; native/SQL facts are absent and
// the explicit component proof below never qualifies installed composition.
func TestConfigurationProviderCleanupUsesFourClosedIndependentLifetimes(t *testing.T) {
	for n, purpose := range []string{"cleanup-wrap", "cleanup-open", "cleanup-verify", "cleanup-sign"} {
		t.Run(purpose, func(t *testing.T) {
			f, in, profile := configurationControlFixture(t, purpose, func(in contracts.HubWorkerDeployment, p *contracts.ConfigurationProviderSelection) {
				p.CleanupAudit = contracts.OwnerPublicTransit{Mount: in.KeyService.AuditMount, Key: in.KeyService.AuditKey}
				p.ContextDeletionSigning = contracts.OwnerPublicTransit{Mount: in.KeyService.AuditMount, Key: contracts.ContextDeletionSigningKeyName(in.InstallationID)}
			})
			effects, err := newConfigurationProviderEffects(t.Context(), in, profile,
				func(context.Context) ([]byte, error) {
					return ownerProviderTestJWT(time.Now().Add(600 * time.Second)), nil
				},
				func(context.Context) (time.Time, error) { return time.Now().Add(5 * time.Second), nil }, f.server.Client(), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = effects.close(context.Background()); effects.joinClosed() })
			seen := map[*ownerProviderLifetime]bool{effects.wrap: true, effects.unwrap: true}
			for _, slot := range effects.cleanup {
				if slot == nil || seen[slot] {
					t.Fatal("cleanup shares credential ownership")
				}
				seen[slot] = true
			}
			if err := effects.cleanup[n].refresh(t.Context()); err != nil {
				t.Fatal("exact cleanup login", err)
			}
			f.mu.Lock()
			logins, lookups := f.loginCalls, f.lookups
			f.mu.Unlock()
			if logins != 1 || lookups != 1 {
				t.Fatal("cleanup login repeated or lacked readback", logins, lookups)
			}
			in.ProviderAuthentication = &profile
			s := &InstalledConfigurationProviderEffects{input: in, effects: effects}
			seal, open, verify, sign, err := s.CleanupKeys(profile.CleanupAudit.Mount, profile.CleanupAudit.Key, profile.ContextDeletionSigning.Mount, profile.ContextDeletionSigning.Key, 1, make(ed25519.PublicKey, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer seal.Close()
			defer open.Close()
			defer verify.Close()
			defer sign.Close()
			// Local transport confinement rejects alternate paths without emitting
			// another provider request, even with an otherwise live credential.
			for _, c := range []*Opener{open, verify} {
				if _, err := c.client.Logical().Write("audit/decrypt/alternative", map[string]any{}); err == nil {
					t.Fatal("alternate audit key reached")
				}
			}
			if _, _, _, _, err := s.CleanupKeys("audit", "historical", profile.ContextDeletionSigning.Mount, profile.ContextDeletionSigning.Key, 1, make(ed25519.PublicKey, 32)); err == nil {
				t.Fatal("unselected key accepted")
			}
		})
	}
}
