package kms

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
)

// The concrete reader has no public constructor for diagnostic values. Its zero
// diagnostic is the closed transaction/unspecified case; PostgreSQL's own tests
// exercise actual predicates, query errors and blocked connection acquisition.
func TestOwnerProviderConfigurationDiagnosticMapping(t *testing.T) {
	failure := new(postgres.OwnerConfigurationReadFailure)
	for _, step := range []string{"configuration", "final"} {
		err := auditCredentialStepFrom(step, failure)
		var fixed interface{ FixedStep() string }
		if !errors.Is(err, ErrKeyService) || !errors.As(err, &fixed) || fixed.FixedStep() != "credentials-"+step+"/transaction/unspecified" {
			t.Fatalf("audit configuration detail was lost: %v", err)
		}
	}
	for _, step := range []string{"configuration", "configuration-final"} {
		err := ownerProviderConfigurationFailure(step, failure)
		var fixed interface{ FixedStep() string }
		if !errors.Is(err, ErrKeyService) || !errors.As(err, &fixed) || fixed.FixedStep() != step+"/transaction/unspecified" {
			t.Fatalf("provider configuration detail was lost: %v", err)
		}
		if errors.Is(err, failure) || strings.Contains(err.Error(), "transaction") {
			t.Fatal("configuration error escaped key-service normalization")
		}
	}
	for _, cause := range []error{nil, errors.New("private-token"), ownerProviderUntrustedStep{}} {
		if ownerProviderConfigurationFailure("configuration", cause) != ErrKeyService {
			t.Fatal("untyped dependency detail became a configuration diagnostic")
		}
	}
}

type ownerProviderUntrustedStep struct{}

func (ownerProviderUntrustedStep) Error() string     { return "private-token" }
func (ownerProviderUntrustedStep) FixedStep() string { return "private-token" }

func TestOwnerProviderConfigurationDiagnosticRefreshAndReport(t *testing.T) {
	for _, tc := range []struct {
		name, configuration, want string
		failAt                    int
		diagnostic                bool
	}{
		{"initial", "configuration", "proof/configuration/transaction/unspecified", 1, true},
		{"final", "configuration-final", "final-proof/configuration-final/transaction/unspecified", 2, true},
		{"untrusted-initial", "", "proof", 1, false},
		{"untrusted-final", "", "final-proof", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOwnerProviderControlFixture(t)
			parent, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			original, _ := parent.Deadline()
			var checks int
			proof := func(ctx context.Context) (time.Time, error) {
				until, ok := ctx.Deadline()
				if !ok || until.After(original) {
					t.Error("configuration diagnostic extended original operation deadline")
				}
				checks++
				if checks == tc.failAt {
					if tc.diagnostic {
						return time.Time{}, ownerProviderConfigurationFailure(tc.configuration, new(postgres.OwnerConfigurationReadFailure))
					}
					return time.Time{}, ownerProviderUntrustedStep{}
				}
				return until, ctx.Err()
			}
			slot := newOwnerProviderLifetimeFixture(t, f, nil, proof, 1)
			err := slot.refresh(parent)
			var fixed interface{ FixedStep() string }
			if !errors.Is(err, ErrKeyService) || !errors.As(err, &fixed) || fixed.FixedStep() != tc.want {
				t.Fatalf("refresh discarded its closed configuration cause: %v", err)
			}
			var reports []string
			s := InstalledOwnerProviderEffects{Report: func(v string) { reports = append(reports, v) }}
			s.reportRefresh(slot, err)
			if len(reports) != 1 || reports[0] != slot.control.purpose+" "+tc.want {
				t.Fatal("supervisor discarded refresh detail", reports)
			}
			if checks != tc.failAt || !slot.uncertain || slot.current != nil {
				t.Fatal("failed configuration check adopted credentials or repeated proof")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.loginCalls != tc.failAt-1 {
				t.Fatal("diagnostic changed the number of provider effects", f.loginCalls)
			}
		})
	}
}
