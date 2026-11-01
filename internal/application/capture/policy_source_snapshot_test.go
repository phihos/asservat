package capture

import (
	"context"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// Only the trigger/application dispatch contract is controlled here; this
// receipt double is not evidence of SQL admission, node capture or custody.
type policySnapshotServiceFixture struct {
	selection          PolicySnapshotSelection
	selections         []PolicySnapshotSelection
	previews, requests int
	key                string
	keys               []string
}

func (f *policySnapshotServiceFixture) PreviewPolicySnapshot(_ context.Context, _ identities.CurrentIdentity, s PolicySnapshotSelection) (ContextPreviewResult, error) {
	f.previews++
	f.selection = s
	f.selections = append(f.selections, s)
	return ContextPreviewResult{Preview: value.ContextPreview{ID: fixtureID(910), Actor: s.Authority.Executor, Target: s.Target, Intent: value.ContextIntent{Snapshot: &planning.SourceSnapshotContext{Request: artifact.SourceSnapshotRequest{T0: s.TriggeredAt}}}}}, nil
}
func (f *policySnapshotServiceFixture) Request(_ context.Context, _ identities.CurrentIdentity, _ string, key string) (value.Accepted, error) {
	f.requests++
	f.key = key
	f.keys = append(f.keys, key)
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
	cohort.rows[sourceKey(source.Binding.PodUID, source.Binding.ActionID)] = source
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

// ADR-275: an incident of a packet + syscall policy captures each recorder's
// window of the triggering Pod. The first is the occurrence's capture under
// the occurrence key; the further one names its occurrence and uses the
// derived key, so a retry never takes a second execution.
func TestPolicySourceSnapshotCapturesEveryRecorder(t *testing.T) {
	cohort := newSourceCohortFixture(t, 1)
	composition := networkComposition()
	composition.Components = append(composition.Components, planning.ProfileComponent{ID: "calls", Profile: planning.ProfileRef{Catalog: "builtin", Name: "syscall-activity", Version: "v1"}})
	composition.MaxTotalBytes, composition.MaxDuration = 32<<20, "30s"
	all, err := compiler.CompileOngoingPolicyRecorders(*composition, &stubFilters{})
	if err != nil {
		t.Fatal(err)
	}
	cohort.policy.Recorder, cohort.policy.MoreRecorders = &all[0], all[1:]
	if err = cohort.maintain(0); err != nil {
		t.Fatal(err)
	}
	original := cohort.f.target.Request
	for key, row := range cohort.rows {
		original.PodUID = row.Binding.PodUID
		row.Target = &targets.SourceSnapshotTarget{Request: original}
		cohort.rows[key] = row
	}
	service := &policySnapshotServiceFixture{}
	trigger := PolicyTrigger{OngoingSources: cohort.runtime, SourceSnapshots: service}
	occurrence := value.PolicyOccurrence{ID: fixtureID(912), PolicyUID: cohort.authority.PolicyUID, PodUID: original.PodUID, TriggeredAt: cohort.f.now.Add(-2 * time.Second)}
	observation := targets.RestartObservation{ClusterID: original.ClusterID, Namespace: original.Namespace, Workload: original.Workload}
	id, refusal := trigger.captureSourceSnapshot(t.Context(), nil, cohort.authority, cohort.policy, observation, original.PodName, occurrence)
	if id != fixtureID(911) || refusal != "" || service.requests != 2 || len(service.selections) != 2 {
		t.Fatal("incident did not capture every recorder", id, refusal, service.requests)
	}
	first, further := service.selections[0], service.selections[1]
	if first.OccurrenceID != "" || service.keys[0] != occurrence.ID || first.Source.Binding.ActionID != all[0].Action.ID ||
		further.OccurrenceID != occurrence.ID || service.keys[1] != value.OccurrenceCaptureKey(occurrence.ID, all[1].Action.ID) || further.Source.Binding.ActionID != all[1].Action.ID {
		t.Fatal("recorder captures not keyed per occurrence and action", service.keys)
	}
}
