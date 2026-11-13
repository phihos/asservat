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
		{hostileOwnerProtectionDetail{}, "protection.result"},
		{configurationSourceError(configurationSourceGuardPolicyRead, hostileOwnerProtectionDetail{}), "protection.result"},
		{context.Canceled, "protection.result/canceled"},
		{context.DeadlineExceeded, "protection.result/deadline"},
	} {
		err := ownerProtectionError("result", cfg.ErrChanged, tc.detail)
		var fixed interface{ FixedStep() string }
		if !errors.Is(err, cfg.ErrChanged) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &fixed) || fixed.FixedStep() != tc.want || err.Error() != cfg.ErrUnavailable.Error() {
			t.Fatal("diagnostic changed original normalization or copied private detail")
		}
	}
}
