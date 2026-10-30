package capture

import (
	"context"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// Only the trigger/application dispatch contract is controlled here; this
// receipt double is not evidence of SQL admission, node capture or custody.
type policySnapshotServiceFixture struct {
	selection          PolicySnapshotSelection
	previews, requests int
	key                string
}

func (f *policySnapshotServiceFixture) PreviewPolicySnapshot(_ context.Context, _ identities.CurrentIdentity, s PolicySnapshotSelection) (ContextPreviewResult, error) {
	f.previews++
	f.selection = s
	return ContextPreviewResult{Preview: value.ContextPreview{ID: fixtureID(910), Actor: s.Authority.Executor, Target: s.Target, Intent: value.ContextIntent{Snapshot: &planning.SourceSnapshotContext{Request: artifact.SourceSnapshotRequest{T0: s.TriggeredAt}}}}}, nil
}
func (f *policySnapshotServiceFixture) Request(_ context.Context, _ identities.CurrentIdentity, _ string, key string) (value.Accepted, error) {
	f.requests++
	f.key = key
	return value.Accepted{CaptureID: fixtureID(911)}, value.ErrPreparationUncertain
}

func TestPolicySourceSnapshotDispatchKeepsOccurrenceAnchorAndUnknownReceipt(t *testing.T) {
	cohort := newSourceCohortFixture(t, 1)
	if err := cohort.maintain(0); err != nil {
		t.Fatal(err)
	}
	var source PolicySourceState
	for _, row := range cohort.rows {
		source = row
	}
	original := cohort.f.target.Request
	original.PodUID = source.Binding.PodUID
	source.Target = &targets.SourceSnapshotTarget{Request: original}
	cohort.rows[source.Binding.PodUID] = source
	service := &policySnapshotServiceFixture{}
	trigger := PolicyTrigger{OngoingSources: cohort.runtime, SourceSnapshots: service}
	occurrence := value.PolicyOccurrence{ID: fixtureID(912), PolicyUID: cohort.authority.PolicyUID, PodUID: source.Binding.PodUID, TriggeredAt: cohort.f.now.Add(-2 * time.Second)}
	observation := targets.RestartObservation{ClusterID: original.ClusterID, Namespace: original.Namespace, Workload: original.Workload}
	id, refusal := trigger.captureSourceSnapshot(t.Context(), nil, cohort.authority, cohort.policy, observation, original.PodName, occurrence)
	if id != fixtureID(911) || refusal != "" || service.previews != 1 || service.requests != 1 || service.key != occurrence.ID || service.selection.TriggeredAt != occurrence.TriggeredAt || service.selection.Source.Binding != source.Binding || service.selection.Policy.Recorder.Action.ExecutionMode != "ongoing" {
		t.Fatal("trigger restarted a policy, changed T0 or retried unknown snapshot", id, refusal, service.previews, service.requests)
	}
	occurrence.TriggeredAt = time.Time{}
	if id, _ = trigger.captureSourceSnapshot(t.Context(), nil, cohort.authority, cohort.policy, observation, original.PodName, occurrence); id != "" || service.requests != 1 {
		t.Fatal("missing original T0 sampled a new window")
	}
}
