package kubernetes

import (
	"context"
	"errors"
	"testing"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

type hostileOwnerProtectionDetail struct{}

func (hostileOwnerProtectionDetail) Error() string     { panic("raw native error inspected") }
func (hostileOwnerProtectionDetail) FixedStep() string { panic("foreign diagnostic inspected") }

func TestOwnerProtectionDiagnosticKeepsNormalizedClassAndPrivateDetails(t *testing.T) {
	for _, tc := range []struct {
		detail error
		want   string
	}{
		{hostileOwnerProtectionDetail{}, "protection.guard-last"},
		{configurationSourceError(configurationSourceGuardPolicyRead, hostileOwnerProtectionDetail{}), "protection.guard-last/source.guard-policy-read"},
		{context.Canceled, "protection.guard-last/canceled"},
		{context.DeadlineExceeded, "protection.guard-last/deadline"},
	} {
		err := ownerProtectionError("guard-last", cfg.ErrChanged, tc.detail)
		var fixed interface{ FixedStep() string }
		if !errors.Is(err, cfg.ErrChanged) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &fixed) || fixed.FixedStep() != tc.want || err.Error() != cfg.ErrUnavailable.Error() {
			t.Fatal("diagnostic changed original normalization or copied private detail")
		}
	}
}
