package capture

import (
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type availableProcesses struct {
	availableRecording
	unavailable bool
	calls       int
}

func (r *availableProcesses) ProcessRecorder(context.Context, targets.PodResolution) error {
	r.calls++
	if r.unavailable {
		return targets.ErrUnsupported
	}
	return nil
}
func (r *availableProcesses) ResolveProcessRecorder(ctx context.Context, request targets.Request) (targets.PodResolution, error) {
	r.calls++
	if r.unavailable {
		return targets.PodResolution{}, targets.ErrUnsupported
	}
	return r.fixture.ResolvePod(ctx, request)
}
func TestProcessPreviewAndRequestUseExactQualifiedWholePodWithoutRawApproval(t *testing.T) {
	base := newInvestigationFixture()
	f := &retainedRecording{investigationFixture: base}
	base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
	base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	base.svc.Previews, base.svc.Admission = f, f
	recorders := &availableProcesses{availableRecording: availableRecording{base}}
	base.svc.Recorders = recorders
	c := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "inventory", Profile: planning.ProfileRef{Catalog: "builtin", Name: "inspect-processes", Version: "v1"}}}, MaxTotalBytes: artifact.ProcessNativeLimit, MaxDuration: "10s"}
	preview, err := base.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(&c))
	if err != nil || !preview.Recordable || preview.Plan.Approval != nil {
		t.Fatal("ordinary process preview invented raw review or lost qualified source", err)
	}
	if _, err := f.request(t, preview.Preview, "original-processes"); !errors.Is(err, reachedRecordingAdmission) || len(f.seen) != 1 {
		t.Fatal("process request did not reach original admission", err)
	}
	a := f.seen[0]
	p, _, err := compiler.ProcessesForContext(a.Plan)
	if err != nil || p.Mode != artifact.ProcessAll || a.Registration.NativeLimit != artifact.ProcessNativeLimit || a.Plan.ScopeDigest != preview.Preview.ScopeDigest || a.Plan.Input.Processes == nil || a.Plan.Input.Recorder != nil || a.Plan.Input.Profile != nil || a.Plan.Input.Logs != nil || a.Plan.Input.Target.Pin.UID != base.target.Pin.UID || a.Plan.Input.Target.NodeUID != "" {
		t.Fatal("accepted metadata scope changed whole-Pod authority", err)
	}
	if recorders.calls < 2 {
		t.Fatal("request skipped actual source recheck")
	}
	recorders.unavailable = true
	unavailable, err := base.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(&c))
	if err != nil || unavailable.Recordable {
		t.Fatal("unqualified collector became requestable", err)
	}
}

// The admitted expectation is supplied by the synthetic fixture; this tests
// authored settings persistence/restoration, not SQL or encrypted custody.
func TestProcessHistoryPreservesRecipeAndFreshRepeat(t *testing.T) {
	f := newInvestigationFixture()
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	f.svc.Recorders = &availableProcesses{availableRecording: availableRecording{f}}
	c := &planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "inventory", Profile: planning.ProfileRef{Catalog: "builtin", Name: "inspect-processes", Version: "v1"}}}, MaxTotalBytes: artifact.ProcessNativeLimit, MaxDuration: "10s"}
	original, err := f.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(c))
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the synthetic admission port and supply the process expectation
	// that the real PG adapter constructs (the legacy fixture emits pod-status).
	retained := &retainedRecording{investigationFixture: f}
	f.svc.Admission = retained
	if _, err := retained.request(t, original.Preview, "history-process"); !errors.Is(err, reachedRecordingAdmission) || len(retained.seen) != 1 {
		t.Fatal(err)
	}
	admission := retained.seen[0]
	accepted, err := f.AdmitReviewedContext(t.Context(), original.Preview.ID, admission)
	if err != nil {
		t.Fatal(err)
	}
	process, action, err := compiler.ProcessesForContext(admission.Plan)
	if err != nil {
		t.Fatal(err)
	}
	accepted.Expectation.NativeType = artifact.ProcessesArtifact
	accepted.Expectation.Processes = &process
	accepted.Expectation.ActionID = action
	draft, err := HistoryDraftFromPreview(original.Preview, accepted)
	if err != nil {
		t.Fatal("process history draft", err)
	}
	raw, err := value.CanonicalHistoryParameters(draft)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := value.ParseHistoryParameters(raw)
	if err != nil {
		t.Fatal(err)
	}
	var recipe struct {
		Actions []struct {
			Kind string `json:"kind"`
		} `json:"actions"`
	}
	if json.Unmarshal(restored.RecipeJSON, &recipe) != nil || len(recipe.Actions) != 1 || recipe.Actions[0].Kind != "processSnapshot" || restored.Composition == nil || restored.Composition.Components[0].Profile.Name != "inspect-processes" || restored.OriginalExecutionDigest != original.Preview.ScopeDigest {
		t.Fatal("settings lost process recipe/version")
	}
	service, reader := historyService(f)
	reader.settings.Composition = restored.Composition
	reader.settings.RecipeJSON = restored.RecipeJSON
	reader.settings.CompositionJSON = restored.CompositionJSON
	reader.settings.DependencyJSON = restored.DependencyJSON
	reader.settings.FrozenFilters = restored.FrozenFilters
	reader.settings.ExecutionDigest = restored.OriginalExecutionDigest
	before := bytes.Clone(restored.RecipeJSON)
	repeated, settings, err := service.PreviewRepeat(t.Context(), f.source(t, t.Context()), original.Preview.CaptureID, nil)
	if err != nil || repeated.Recorder == nil || !repeated.Recorder.Recordable || repeated.Preview.CaptureID == original.Preview.CaptureID || repeated.Preview.Intent.Composition.Components[0].Profile.Name != "inspect-processes" || !bytes.Equal(before, settings.RecipeJSON) || repeated.Preview.Intent.RepeatedFrom == nil {
		t.Fatal("process settings failed fresh preview", err)
	}
}
