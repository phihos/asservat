package bootstrap

import (
	"context"
	"errors"
	"testing"

	executionapp "asservat.local/asservat/internal/application/execution"
	execution "asservat.local/asservat/internal/domain/execution"
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

// Only a run that never entered preparation, or whose preparation rolled back
// before its insert, may be reported as not started; after the attachment
// ended no preparation can begin.
func TestRegionalStartGateClassifiesOnlyUnpreparedRuns(t *testing.T) {
	for name, tc := range map[string]struct {
		err       error
		call      bool
		wantEntry bool
	}{
		"never-prepared":   {},
		"headroom":         {err: errors.Join(execution.ErrUnavailable, execution.ErrNotStarted), call: true},
		"lost-reply":       {err: execution.ErrUnavailable, call: true, wantEntry: true},
		"prepared-success": {call: true, wantEntry: true},
	} {
		t.Run(name, func(t *testing.T) {
			gate := &preparationGate{}
			inner := &gateProbePreparer{err: tc.err}
			p := gatedPreparer{inner, gate}
			if tc.call {
				_, _, _ = p.PrepareAPIExecution(t.Context(), executionapp.APIExecutionCheck{})
			}
			if entered := gate.close(); entered != tc.wantEntry {
				t.Fatal("entered", entered, tc.wantEntry)
			}
			if _, _, err := p.PrepareAPIExecution(t.Context(), executionapp.APIExecutionCheck{}); !errors.Is(err, execution.ErrNotStarted) || inner.calls > 1 {
				t.Fatal("preparation began after the attachment ended", err, inner.calls)
			}
			if gate.close() != tc.wantEntry {
				t.Fatal("a refused late preparation changed the answer")
			}
		})
	}
}
