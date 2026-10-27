package bootstrap

import (
	"context"
	"errors"
	"testing"

	executionapp "asservat.local/asservat/internal/application/execution"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type gateProbePreparer struct {
	executionapp.APIExecutionPreparer
	err   error
	calls int
}

func (p *gateProbePreparer) PrepareAPIExecution(context.Context, executionapp.APIExecutionCheck) (execution.APIExecution, bool, error) {
	p.calls++
	return execution.APIExecution{}, false, p.err
}

// Only a run that never entered preparation (or whose preparation rolled back
// before its insert) and failed as temporarily unavailable, or was abandoned
// when its exchange ended, is not started. A denied, expired, changed or
// otherwise definite run keeps its class; after the attachment ended no
// preparation can begin.
func TestRegionalStartGateClassifiesOnlyUnavailableUnpreparedRuns(t *testing.T) {
	unavailable := errors.Join(execution.ErrUnavailable, execution.ErrNotStarted)
	for name, tc := range map[string]struct {
		prepareErr error
		prepare    bool
		finish     bool
		runErr     error
		want       bool
	}{
		"abandoned-before-preparation": {want: true},
		"check-unavailable":            {finish: true, runErr: targets.ErrUnavailable, want: true},
		"headroom":                     {prepare: true, prepareErr: unavailable, finish: true, runErr: unavailable, want: true},
		"check-denied":                 {finish: true, runErr: execution.ErrDenied},
		"identity-revoked":             {finish: true, runErr: identity.ErrDenied},
		"expired":                      {finish: true, runErr: execution.ErrExpired},
		"deadline":                     {finish: true, runErr: context.DeadlineExceeded},
		"target-replaced":              {finish: true, runErr: targets.ErrChanged},
		"acquisition-closed":           {finish: true, runErr: capturevalue.ErrAcquisitionClosed},
		"finished-without-error":       {finish: true},
		"lost-preparation-reply":       {prepare: true, prepareErr: execution.ErrUnavailable, finish: true, runErr: execution.ErrUnavailable},
		"prepared":                     {prepare: true, finish: true, runErr: execution.ErrExpired},
	} {
		t.Run(name, func(t *testing.T) {
			gate := &preparationGate{}
			inner := &gateProbePreparer{err: tc.prepareErr}
			p := gatedPreparer{inner, gate}
			if tc.prepare {
				_, _, _ = p.PrepareAPIExecution(t.Context(), executionapp.APIExecutionCheck{})
			}
			if tc.finish {
				gate.finish(tc.runErr)
			}
			gate.close()
			if got := gate.notStarted(); got != tc.want {
				t.Fatal("not started", got, tc.want)
			}
			if _, _, err := p.PrepareAPIExecution(t.Context(), executionapp.APIExecutionCheck{}); !errors.Is(err, execution.ErrNotStarted) || inner.calls > 1 {
				t.Fatal("preparation began after the attachment ended", err, inner.calls)
			}
		})
	}
}
