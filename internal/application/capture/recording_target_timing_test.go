package capture

import (
	value "asservat.local/asservat/internal/domain/capture"
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// The installed phases are bucketed, not precise timings: target<500ms,
// recorder<2s and storage<2–3s. This deterministic composition models400ms,
// 1.4s and1.8s with an original receiver proof leaving3s at query start.
// Every authority deadline remains unchanged; only duplicate work can be removed.
type recordingTargetTiming struct {
	*investigationFixture
	resolving                    bool
	until                        time.Time
	recorderCalls, combinedCalls int
	combinedErr                  error
	changed                      bool
}

func (f *recordingTargetTiming) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	p, e := f.investigationFixture.ResolvePod(ctx, r)
	if f.resolving {
		p.FreshUntil = f.until
		f.now = f.now.Add(400 * time.Millisecond)
	}
	return p, e
}
func (f *recordingTargetTiming) PacketRecorder(context.Context, targets.PodResolution) error {
	f.recorderCalls++
	if f.resolving {
		f.now = f.now.Add(1400 * time.Millisecond)
	}
	return nil
}
func (f *recordingTargetTiming) ResolvePacketRecorder(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	f.combinedCalls++
	if f.combinedErr != nil {
		return targets.PodResolution{}, f.combinedErr
	}
	p, err := f.ResolvePod(ctx, r)
	if f.changed {
		p.Request.PodUID = "replacement"
		p.Pin.UID = "replacement"
	}
	return p, err // availability shares the region's same exact read
}
func (f *recordingTargetTiming) ContextProcessingCoverage(ctx context.Context, r value.ProcessingCoverageRequest, recovery artifact.RecoveryProof) (value.ProcessingCoverage, error) {
	until := recovery.FreshUntil
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	return value.ProcessingCoverage{Request: r, ObservedAt: f.now, FreshUntil: until}, nil
}
func TestRecordingRequestComposesTargetAndAvailabilityBeforeStorage(t *testing.T) {
	base := newInvestigationFixture()
	f := &recordingTargetTiming{investigationFixture: base}
	retained := &retainedRecording{investigationFixture: base}
	base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
	base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	base.svc.Previews, base.svc.Admission, base.svc.Recorders, base.svc.Targets = retained, retained, f, f
	p, err := base.svc.PreviewComposition(t.Context(), base.source(t, t.Context()), base.compositionIntent(networkComposition()))
	if err != nil || !p.Recordable {
		t.Fatal("preview", err)
	}
	base.svc.Processing = f
	base.svc.ReportPreviewFailure = func(s string) { t.Log(s) }
	f.resolving = true
	f.until = f.now.Add(3 * time.Second)
	base.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
		f.now = f.now.Add(1800 * time.Millisecond)
		return base.ContextStorage(ctx, target)
	})
	_, err = base.svc.Request(t.Context(), base.source(t, t.Context()), p.Preview.ID, "one-intent")
	if !errors.Is(err, reachedRecordingAdmission) {
		t.Fatal("duplicate availability exchange aged original target before admission", err)
	}
	if f.combinedCalls != 1 || f.recorderCalls != 1 || len(retained.seen) != 1 {
		t.Fatal("expected one combined submission and original preview availability", f.combinedCalls, f.recorderCalls, len(retained.seen))
	}
	if !f.now.Before(f.until) {
		t.Fatal("original target deadline changed or expired")
	}
	if base.previews[p.Preview.ID].Pin.NodeName != "" {
		t.Fatal("API pin acquired node execution identity")
	}
}

func TestRecordingCombinedTargetDoesNotAdmitChangedOrUnavailableTarget(t *testing.T) {
	for _, mode := range []string{"changed-pod", "recorder-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			base := newInvestigationFixture()
			f := &recordingTargetTiming{investigationFixture: base}
			retained := &retainedRecording{investigationFixture: base}
			base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
			base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
			base.svc.Previews, base.svc.Admission, base.svc.Recorders, base.svc.Targets = retained, retained, f, f
			p, err := base.svc.PreviewComposition(t.Context(), base.source(t, t.Context()), base.compositionIntent(networkComposition()))
			if err != nil || !p.Recordable {
				t.Fatal("preview", err)
			}
			want := value.ErrChanged
			if mode == "changed-pod" {
				f.changed = true
			} else {
				f.combinedErr = targets.ErrUnsupported
				want = value.ErrRecorderUnavailable
			}
			if _, err = base.svc.Request(t.Context(), base.source(t, t.Context()), p.Preview.ID, "one-intent"); !errors.Is(err, want) || len(retained.seen) != 0 || f.combinedCalls != 1 || f.recorderCalls != 1 {
				t.Fatal("changed/unavailable target reached admission or duplicate query", err, len(retained.seen), f.combinedCalls, f.recorderCalls)
			}
		})
	}
}

func TestRecordingCombinedQueryRemainsPacketOnly(t *testing.T) {
	base := newInvestigationFixture()
	f := &recordingTargetTiming{investigationFixture: base}
	retained := &retainedRecording{investigationFixture: base}
	base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
	base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	base.svc.Previews, base.svc.Admission, base.svc.Recorders, base.svc.Targets = retained, retained, f, f
	p, err := base.svc.PreviewComposition(t.Context(), base.source(t, t.Context()), base.compositionIntent(networkComposition()))
	if err != nil || !p.Recordable {
		t.Fatal(err)
	}
	// A structurally valid retained input must not widen the recorder port to
	// syscalls, even if it carries a storage selection. Scope remains immutable;
	// unsupported acquisition is refused before dispatching any target query.
	stored := base.previews[p.Preview.ID].Clone()
	stored.Intent.Composition = &planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "calls", Profile: planning.ProfileRef{Catalog: "builtin", Name: "syscall-activity", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
	if !ValidContextPreview(stored) {
		t.Fatal("structural fixture invalid")
	}
	base.previews[stored.ID] = stored
	if _, err = base.svc.Request(t.Context(), base.source(t, t.Context()), stored.ID, "one-intent"); !errors.Is(err, value.ErrRecorderUnavailable) || f.combinedCalls != 0 || len(retained.seen) != 0 {
		t.Fatal("unsupported recorder dispatched or reached admission", err, f.combinedCalls, len(retained.seen))
	}
}
