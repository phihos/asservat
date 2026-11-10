package privacy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/privacy"
)

// The durable adapter decodes its prepared scope from JSON before returning
// it. A non-hour offset receives a different time.Location allocation.
type processingRoundTripDecisions struct{ *processingFixture }

func (f processingRoundTripDecisions) PrepareProcessing(ctx context.Context, authority value.ProcessingAuthority, draft ProcessingDecision) (ProcessingPrepared, error) {
	prepared, err := f.processingFixture.PrepareProcessing(ctx, authority, draft)
	if err != nil {
		return prepared, err
	}
	raw, err := json.Marshal(prepared.Decision)
	if err == nil {
		err = json.Unmarshal(raw, &prepared.Decision)
	}
	return prepared, err
}

func TestProcessingWorkloadIntervalJSONRoundTrip(t *testing.T) {
	f, s, c := newProcessingFixture(t)
	s.Decisions = processingRoundTripDecisions{f}
	n := f.now.In(time.FixedZone("operator", 5*3600+30*60))
	c.Action, c.RuleID = "restrict_processing", processingID(8)
	c.Scope = value.ProcessingScope{Kind: "workloadInterval", ClusterID: processingID(9), NamespaceUID: "namespace", WorkloadUID: "workload", AcquiredFrom: n.Add(-time.Second), AcquiredUntil: n.Add(time.Second)}
	out, err := s.Change(context.Background(), f, c)
	if err != nil || out.State != "restricted" || f.applies != 1 || f.begins != 1 || f.finishes != 1 {
		t.Fatal("same interval refused after durable JSON round trip", out, err, f.applies, f.begins, f.finishes)
	}
}
