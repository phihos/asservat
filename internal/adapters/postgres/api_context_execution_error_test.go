package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"

	privacyapp "asservat.local/asservat/internal/application/privacy"
	value "asservat.local/asservat/internal/domain/execution"
)

func TestAPIPreparationRefusalPreservesRollbackDeadline(t *testing.T) {
	// Ledger normalizes an ordinary callback refusal as client. If the
	// original context expires during its bounded rollback, it instead
	// reports deadline; both match the custody unavailable sentinel.
	for _, tc := range []struct {
		name    string
		refused bool
		input   error
		restore bool
		step    string
	}{
		{"headroom-client", true, unavailableCause("client"), true, "effect/headroom"},
		{"headroom-wrapped-client", true, fmt.Errorf("wrapped: %w", unavailableCause("client")), true, "effect/headroom"},
		{"deadline-during-rollback", true, unavailableCause("deadline"), false, "effect/headroom/deadline"},
		{"wrapped-deadline-during-rollback", true, fmt.Errorf("wrapped: %w", unavailableCause("deadline")), false, "effect/headroom/deadline"},
		{"ordinary-client-failure", false, unavailableCause("client"), false, "effect/headroom/client"},
		{"begin-failure", false, unavailableCause("begin-deadline"), false, "effect/headroom/begin-deadline"},
		{"sql-failure", false, unavailableCause("sql-42501"), false, "effect/headroom/sql-42501"},
		{"bare-custody-sentinel", true, privacyapp.ErrUnavailable, false, "effect/headroom"},
		{"original-cancellation", true, context.Canceled, false, "effect/headroom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := apiPreparationRefusalError(tc.input, tc.refused)
			if tc.restore {
				if !errors.Is(got, value.ErrUnavailable) || !errors.Is(got, value.ErrNotStarted) {
					t.Fatal("known headroom refusal lost its execution domain or pre-effect class", got)
				}
			} else if errors.Is(got, value.ErrNotStarted) {
				t.Fatal("an unknown rollback was classified as before any start effect", got)
			} else if got != tc.input {
				t.Fatal("normalization replaced the original cause or error chain", got)
			}
			wrapped := sqlStep{"effect/headroom", got}
			if errors.Is(wrapped, value.ErrUnavailable) != tc.restore {
				t.Fatal("execution unavailable classification changed", wrapped)
			}
			if wrapped.FixedStep() != tc.step {
				t.Fatal("normalization lost the closed cause", wrapped.FixedStep(), tc.step)
			}
		})
	}
}
