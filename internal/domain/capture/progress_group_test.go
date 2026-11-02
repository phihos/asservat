package capture

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
)

// ADR-276: a composition group ("collect") stays on one Pod; a recording
// save group spans a workload and never names a Pod.
func TestGroupProgressTargetFollowsOperation(t *testing.T) {
	now := time.Now()
	pod := authorization.Target{ClusterID: "00000000-0000-4000-8000-000000000001", NamespaceUID: "ns", WorkloadUID: "wl", PodUID: "pod"}
	workload := pod
	workload.PodUID = ""
	for _, c := range []struct {
		operation string
		target    authorization.Target
		valid     bool
	}{{"collect", pod, true}, {"collect", workload, false}, {"recordingSave", workload, true}, {"recordingSave", pod, false}} {
		p := ContextProgressObservation{CaptureID: "00000000-0000-4000-8000-000000000070", CandidateCaseID: "00000000-0000-4000-8000-000000000071", Target: c.target, Operation: c.operation, Revision: 1, Phase: "Running", ReasonCode: "GroupInProgress", CreatedAt: now.Add(-time.Minute), Deadline: now.Add(time.Minute), ObservedAt: now, ValidUntil: now.Add(time.Second), Actions: []ContextActionProgress{
			{InstanceID: "00000000-0000-4000-8000-000000000072", PodUID: "pod", PodName: "api", ActionID: "net", Phase: "Running", ReasonCode: "Recording"},
			{InstanceID: "00000000-0000-4000-8000-000000000073", PodUID: "pod", PodName: "api", ActionID: "calls", Phase: "Running", ReasonCode: "Recording"},
		}}
		if p.Valid(now) != c.valid {
			t.Fatal(c.operation, c.target.PodUID, c.valid)
		}
	}
}
