package bootstrap

import (
	"context"
	"errors"
	"testing"

	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/collector"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/targets"
)

type argumentGatePreparer struct {
	executionapp.APIExecutionPreparer
	err    error
	calls  int
	permit collector.ArgumentObservationPermit
	source targets.PacketSourceObservation
}

func (p *argumentGatePreparer) PrepareArgumentRecording(_ context.Context, _ executionapp.APIExecutionCheck, source targets.PacketSourceObservation) (execution.APIExecution, bool, collector.ArgumentObservationPermit, error) {
	p.calls++
	p.source = source
	return execution.APIExecution{}, true, p.permit, p.err
}
func TestRegionalArgumentPreparationGatePreservesUnknownSpend(t *testing.T) {
	for _, mode := range []string{"prepared", "unknown", "rolled back", "closed", "missing companion"} {
		t.Run(mode, func(t *testing.T) {
			inner := &argumentGatePreparer{permit: collector.ArgumentObservationPermit{Sequence: 1, EventCredit: 42, ByteCredit: 512}}
			gate := &preparationGate{}
			p := gatedPreparer{inner, gate}
			switch mode {
			case "unknown":
				inner.err = execution.ErrUnavailable
			case "rolled back":
				inner.err = errors.Join(execution.ErrUnavailable, execution.ErrNotStarted)
			case "closed":
				gate.close()
			case "missing companion":
				p.APIExecutionPreparer = &gateProbePreparer{}
			}
			source := targets.PacketSourceObservation{PodUID: "original"}
			_, first, permit, err := p.PrepareArgumentRecording(t.Context(), executionapp.APIExecutionCheck{}, source)
			if mode == "closed" || mode == "missing companion" {
				if !errors.Is(err, execution.ErrNotStarted) || inner.calls != 0 || first || permit != (collector.ArgumentObservationPermit{}) {
					t.Fatal("unprepared argument operation reached SQL", err)
				}
			} else if inner.calls != 1 || inner.source != source || permit != inner.permit || !first || !errors.Is(err, inner.err) {
				t.Fatal("argument companion altered its immutable result", err)
			}
			gate.close()
			wantUnstarted := mode == "rolled back" || mode == "closed" || mode == "missing companion"
			if gate.notStarted() != wantUnstarted {
				t.Fatal("unknown argument preparation became unspent", mode)
			}
			calls := inner.calls
			if _, _, _, err = p.PrepareArgumentRecording(t.Context(), executionapp.APIExecutionCheck{}, source); !errors.Is(err, execution.ErrNotStarted) || inner.calls != calls {
				t.Fatal("closed gate permitted new preparation", err)
			}
		})
	}
}
