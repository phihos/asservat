package execution

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

func TestTemporarilyUnavailableKeepsDefiniteRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"nil":                {nil, false},
		"unavailable":        {value.ErrUnavailable, true},
		"target-unavailable": {fmt.Errorf("check: %w", targets.ErrUnavailable), true},
		"identity-down":      {identity.ErrUnavailable, true},
		"headroom":           {errors.Join(value.ErrUnavailable, value.ErrNotStarted), true},
		"denied":             {value.ErrDenied, false},
		"revoked":            {identity.ErrDenied, false},
		"target-denied":      {targets.ErrDenied, false},
		"expired":            {value.ErrExpired, false},
		"deadline":           {fmt.Errorf("read: %w", context.DeadlineExceeded), false},
		"target-changed":     {targets.ErrChanged, false},
		"conflict":           {value.ErrConflict, false},
		"invalid":            {value.ErrInvalid, false},
		"closed":             {capture.ErrAcquisitionClosed, false},
		"uncertain":          {value.ErrPreparationUncertain, false},
		"denied-and-down":    {errors.Join(value.ErrUnavailable, value.ErrDenied), false},
	} {
		if got := TemporarilyUnavailable(tc.err); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
