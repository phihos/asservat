package contextstart

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

func TestQueryStepNamesWhereAQueryStopped(t *testing.T) {
	ctx, d := NewStreamDiagnosticContext(context.Background())
	if got := queryStep(fleet.ErrUnavailable, d); got != "router" {
		t.Fatalf("no interruption: %q", got)
	}
	if got := queryStep(errQueryAnswer{targets.ErrUnavailable}, d); got != "answer/"+queryFailureLabel(targets.ErrUnavailable) {
		t.Fatalf("answer: %q", got)
	}
	s := &frameStream{}
	s.record(streamHubQueryCheck, streamExpired)
	recordStreamDiagnostic(ctx, s, fleet.ErrUnavailable, streamHubQuery)
	if got := queryStep(fleet.ErrUnavailable, d); got != "hub-query-check/deadline" {
		t.Fatalf("first interruption: %q", got)
	}
	for _, stage := range []streamStage{streamHubQuery, streamHubQuerySource, streamHubQueryCheck, streamRegionalQueryOwner, streamRegionalQueryWrite} {
		if (StreamInterruption{stage: stage}).Stage() == "unknown" {
			t.Fatalf("stage %d has no name", stage)
		}
	}
}
