package privacy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/privacy"
)

// The durable adapter decodes its stored scope from JSON. A non-hour offset
// receives a different time.Location allocation.
type processingRoundTripDecisions struct{ *processingFixture }

func (f processingRoundTripDecisions) ApplyProcessing(ctx context.Context, authority value.ProcessingAuthority, d ProcessingDecision) (value.ProcessingReceipt, error) {
	raw, err := json.Marshal(d)
	if err == nil {
		err = json.Unmarshal(raw, &d)
	}
	if err != nil {
		return value.ProcessingReceipt{}, err
	}
	return f.processingFixture.ApplyProcessing(ctx, authority, d)
}

func TestProcessingWorkloadIntervalJSONRoundTrip(t *testing.T) {
	f, s, c := newProcessingFixture(t)
	s.Decisions = processingRoundTripDecisions{f}
	n := f.now.In(time.FixedZone("operator", 5*3600+30*60))
	c.Scope = value.ProcessingScope{Kind: "workloadInterval", ClusterID: processingID(9), NamespaceUID: "namespace", WorkloadUID: "workload", AcquiredFrom: n.Add(-time.Second), AcquiredUntil: n.Add(time.Second)}
	out, err := s.Change(context.Background(), f, c)
	if err != nil || out.State != "restricted" || f.applies != 1 {
		t.Fatal("same interval refused after durable JSON round trip", out, err, f.applies)
	}
}
