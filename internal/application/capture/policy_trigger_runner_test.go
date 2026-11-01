package capture

import (
	"context"
	"errors"
	"testing"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// One capture goroutine per policy: a running policy is reported busy (its
// tick is skipped), another policy is not, and the join waits for both.
func TestTriggerRunnerBoundsAndJoinsPolicyCaptures(t *testing.T) {
	r := &triggerRunner{busy: map[string]bool{}}
	release := make(chan struct{})
	done := 0
	r.start("a", func() { <-release; done++ })
	if !r.running("a") || r.running("b") {
		t.Fatal("busy state", r.running("a"), r.running("b"))
	}
	close(release)
	r.wg.Wait()
	if r.running("a") || done != 1 {
		t.Fatal("finished capture still busy or not joined", done)
	}
}

type recordingLedger struct {
	PolicyTriggerLedger
	recorded []string
	err      error
}

func (l *recordingLedger) RecordOccurrence(ctx context.Context, _ value.PolicyOccurrence, _, refusal string) error {
	l.recorded, l.err = append(l.recorded, refusal), ctx.Err()
	return ctx.Err()
}

// A capture finished during shutdown still records its outcome: the record
// context survives Run's cancellation instead of leaving the occurrence open.
func TestTriggerRecordsOutcomeAfterRunCancellation(t *testing.T) {
	l := &recordingLedger{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	PolicyTrigger{Ledger: l}.run(ctx, authorization.AcceptedPolicyAuthority{}, value.RestartPolicy{}, targets.RestartObservation{}, []value.PolicyOccurrence{{ID: "occurrence", PodUID: "gone"}})
	if len(l.recorded) != 1 || l.recorded[0] != "unavailable" || l.err != nil {
		t.Fatal("outcome not recorded after cancellation", l.recorded, l.err)
	}
}

// REQ-LIF-002: a failed ongoing-source maintenance (for example a restart
// that closed the source) never hides the occurrence it accompanies.
func TestOccurrencesAfterMaintainFailureStillAdmitted(t *testing.T) {
	maintain := errors.New("maintain: source closed")
	ticked := 0
	tick := func() ([]value.PolicyOccurrence, error) {
		ticked++
		return []value.PolicyOccurrence{{ID: "occurrence"}}, nil
	}
	got, err := occurrencesAfterMaintain(maintain, false, tick)
	if ticked != 1 || len(got) != 1 || !errors.Is(err, maintain) {
		t.Fatal("maintenance failure hid the occurrence", got, err)
	}
	if got, err = occurrencesAfterMaintain(maintain, true, tick); ticked != 1 || got != nil || !errors.Is(err, maintain) {
		t.Fatal("busy policy evaluated a new occurrence", got, err)
	}
	ledger := errors.New("ledger")
	if got, err = occurrencesAfterMaintain(maintain, false, func() ([]value.PolicyOccurrence, error) { return nil, ledger }); got != nil || !errors.Is(err, maintain) || !errors.Is(err, ledger) {
		t.Fatal("ledger failure lost an error", got, err)
	}
}
