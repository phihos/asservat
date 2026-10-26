package capture

import (
	"context"
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
