package capture

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	planning "asservat.local/asservat/internal/domain/planning"
)

func TestSnapshotAudienceKeepsFullOriginalReadersAndExcludesNewAssignments(t *testing.T) {
	_, _, _, current := newTeamRecordingFixture(t)
	f, _, _, _ := newTeamRecordingFixture(t)
	eligible := f.svc.Eligibility.ContextEligibilityCurrent(t.Context(), current, f.target.Target())
	if !eligible.Eligible || len(eligible.DefaultAudience) < 1 {
		t.Fatal("complete initial audience fixture")
	}
	original := slices.Clone(eligible.DefaultAudience)
	reader := original[0]
	reader.AssignmentID = fixtureID(801)
	reader.SubjectID = "other-original-reader"
	original = append(original, reader)
	digest, err := compiler.SourceAudienceDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	selected := &planning.SourceSnapshotContext{SourceAudience: original, SourceAudienceDigest: digest}
	newReader := reader
	newReader.AssignmentID = fixtureID(802)
	newReader.SubjectID = "new-reader"
	currentFull := append(slices.Clone(original), newReader)
	actual, err := SnapshotAudience(selected, currentFull)
	if err != nil || !slices.Equal(actual, original) || !slices.Contains(actual, reader) {
		t.Fatal("save widened old bytes or discarded original non-contributing reader", actual, err)
	}
	if _, err = SnapshotAudience(&planning.SourceSnapshotContext{}, currentFull); err == nil {
		t.Fatal("legacy source without original full audience saved")
	}
	selected.SourceAudience[0].SubjectID = "changed-original"
	if _, err = SnapshotAudience(selected, currentFull); !errors.Is(err, value.ErrChanged) {
		t.Fatal("changed original audience reused old digest", err)
	}
}

func TestPolicySourceSnapshotPreviewAndRequestUseOnlyExistingWindow(t *testing.T) {
	cohort := newSourceCohortFixture(t, 1)
	if err := cohort.maintain(0); err != nil {
		t.Fatal("initial synthetic source", err)
	}
	var source PolicySourceState
	for _, row := range cohort.rows {
		source = row
	}
	f := cohort.f
	accepted := &teamRecordingAuthority{f: f, authority: cohort.authority}
	current := newPolicyIdentity(t.Context(), accepted, cohort.authority, f.now.Add(45*time.Second), func() time.Time { return f.now })
	eligible := f.svc.Eligibility.ContextEligibilityCurrent(t.Context(), current, f.target.Target())
	if !eligible.Eligible {
		t.Fatal("policy current rights")
	}
	source.Audience = slices.Clone(eligible.DefaultAudience)
	digest, err := compiler.SourceAudienceDigest(source.Audience)
	if err != nil {
		t.Fatal(err)
	}
	source.Binding.AudienceDigest = [32]byte(digest)
	target := f.target.Request
	target.PodUID = source.Binding.PodUID
	// This source fixture models the same admitted Pod; no discovery is allowed
	// to replace it. Update its exact retained pin to the selected source UID.
	f.target.Request = target
	f.target.Pin.UID = target.PodUID
	source.StartedAt = f.now.Add(-time.Minute)
	source.Target = &targets.SourceSnapshotTarget{Request: target, Pin: f.target.Pin, NodeUID: source.Binding.NodeUID, BootID: source.Binding.BootID, CollectorPodUID: source.Binding.CollectorPodUID, CollectorEpoch: source.Binding.CollectorEpoch, SourceID: source.Binding.SourceID, Fence: source.Binding.Fence, BindingDigest: deliveryapp.SourceBindingDigest(source.Binding)}
	retained := &retainedSourceTargetsFixture{ContextTargets: f, now: func() time.Time { return f.now }}
	f.svc.Targets = retained
	if _, settingsErr := f.svc.requireRecordingApproval(t.Context(), current, cohort.authority.Executor); settingsErr != nil {
		t.Fatal("source fixture settings", settingsErr)
	}
	if !f.svc.configured() {
		t.Fatal("configured fixture false")
	}
	if _, ok := f.svc.Targets.(SourceSnapshotTargets); !ok {
		t.Fatal("missing typed source resolver")
	}
	preview, err := f.svc.PreviewPolicySnapshot(t.Context(), current, PolicySnapshotSelection{Policy: cohort.policy, Authority: cohort.authority, Source: source, Target: target, TriggeredAt: f.now})
	if err != nil {
		var failure interface{ FixedStep() string }
		if errors.As(err, &failure) {
			t.Log("preview failure", failure.FixedStep())
		}
		t.Fatal("existing-source preview", err)
	}
	saved := preview.Preview.Intent.Snapshot
	if saved == nil || preview.Preview.Intent.Composition != nil || preview.Preview.Intent.Diagnostic != "" || saved.Request.T0 != f.now || saved.Request.Before <= 0 || saved.Request.After <= 0 || preview.Assessment.OutputLimit != saved.Request.MaxBytes {
		t.Fatal("snapshot was reinterpreted as finite composition", saved)
	}
	originalT0, originalDeadline := saved.Request.T0, saved.Request.ProcessingUntil
	f.now = f.now.Add(500 * time.Millisecond)
	admission := &retainedRecording{investigationFixture: f}
	f.svc.Admission = admission
	_, err = f.svc.Request(t.Context(), current, preview.Preview.ID, fixtureID(901))
	if !errors.Is(err, reachedRecordingAdmission) || len(admission.seen) != 1 {
		t.Fatal("source snapshot failed before shared admission", err, len(admission.seen))
	}
	if retained.podReads != 0 {
		t.Fatal("retained source save read a live Pod or namesake", retained.podReads)
	}
	plan := admission.seen[0].Plan
	if plan.Input.Snapshot == nil || plan.Input.Recorder != nil || plan.Input.Snapshot.Request.T0 != originalT0 || plan.Input.Snapshot.Request.ProcessingUntil != originalDeadline || plan.Input.Retention.AnchorAt != artifact.SourceSnapshotAnchor(saved.Request) {
		t.Fatal("request renewed original window/processing/source age", plan.Input.Snapshot)
	}
}

type retainedSourceTargetsFixture struct {
	ContextTargets
	now      func() time.Time
	podReads int
}

func (f *retainedSourceTargetsFixture) ResolvePod(context.Context, targets.Request) (targets.PodResolution, error) {
	f.podReads++
	return targets.PodResolution{}, targets.ErrChanged
}
func (f *retainedSourceTargetsFixture) ResolveSourceSnapshot(_ context.Context, original targets.SourceSnapshotTarget) (targets.SourceSnapshotResolution, error) {
	now := f.now()
	return targets.SourceSnapshotResolution{Original: original, Process: targets.PacketSourceObservation{PodUID: original.Request.PodUID, NodeUID: original.NodeUID, BootID: original.BootID, CollectorPodUID: original.CollectorPodUID, CollectorEpoch: original.CollectorEpoch, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, State: targets.RecorderSourceState{IssuedAt: now.Add(-time.Second), LeafUntil: now.Add(20 * time.Second), Credit: 1, SourceID: original.SourceID, Fence: original.Fence, ObservedAt: now, FreshUntil: now.Add(15 * time.Second)}, ReportedAt: now, ReportFreshUntil: now.Add(15 * time.Second), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
