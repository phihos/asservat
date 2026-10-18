package postgres

import (
	"errors"
	"fmt"
	"testing"

	"asservat.local/asservat/internal/application/privacy"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The ledger's cause word survives the permission mapping as a fixed step,
// and both keep matching their sentinels.
func TestLedgerCauseKeepsTheSentinelAndNamesTheCause(t *testing.T) {
	err := unavailableCause("begin-deadline")
	if !errors.Is(err, privacy.ErrUnavailable) {
		t.Fatal("ledger cause lost the custody sentinel")
	}
	mapped := permissionError(fmt.Errorf("wrapped: %w", err))
	var step interface{ FixedStep() string }
	if !errors.Is(mapped, cfg.ErrUnavailable) || !errors.As(mapped, &step) || step.FixedStep() != "begin-deadline" {
		t.Fatal("permission mapping lost the cause", mapped)
	}
	if permissionError(errors.New("other")) != cfg.ErrUnavailable {
		t.Fatal("an error without a cause changed")
	}
}
