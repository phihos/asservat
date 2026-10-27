package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type stubFilters struct{ calls int }

func (s *stubFilters) CompileFilter(string) (planning.CompiledFilter, error) {
	s.calls++
	return planning.CompiledFilter{LinkType: planning.FilterLinkType, Snaplen: planning.FilterSnaplen, Program: []planning.BPFInstruction{{Code: 0x6, K: 65535}}}, nil
}

func networkComposition(edits ...planning.ProfileEdit) *planning.ProfileComposition {
	return &planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "net", Profile: planning.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: edits}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
}

func (f *investigationFixture) compositionIntent(c *planning.ProfileComposition) value.ContextIntent {
	return value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: fixtureID(4), Namespace: "payments", Kind: "Deployment", Name: "api"}, RequestedSeconds: 60, Composition: c}
}

func TestCompositionPreviewIsPlanOnlyAndRequestRefused(t *testing.T) {
	f := newInvestigationFixture()
	filters := &stubFilters{}
	f.svc.Filters = filters
	ctx := context.Background()
	r, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition(planning.ProfileEdit{ActionID: "sample", Field: "packetFilter", Text: "tcp port 8080"})))
	if err != nil {
		t.Fatal(err)
	}
	p := r.Preview
	if filters.calls != 1 || f.admissions.Load() != 0 || p.Intent.Composition == nil || p.Storage != (value.ContextStorageSelection{}) || !ValidContextPreview(p) || p.ScopeDigest != r.Plan.ScopeDigest || !bytes.Equal(p.CanonicalScope, r.Plan.CanonicalScope) {
		t.Fatal("composition preview reserved work or is not the reviewed plan")
	}
	if r.Assessment.PlanDigest != p.ScopeDigest || p.AssessmentRulesDigest != compiler.RecorderAssessmentRulesDigest() || r.Assessment.ID != p.AssessmentID || p.Retention.Policies[0].UID != "baseline" {
		t.Fatal("assessment or retention differs from the stored preview")
	}
	stored, ok := f.previews[p.ID]
	if !ok || stored.Intent.Composition == nil {
		t.Fatal("composition preview not persisted")
	}
	// The persisted blueprint survives the SQL adapter's strict decode and
	// byte-exact re-encode (adapters/postgres previewRecord).
	b, _ := json.Marshal(stored)
	var decoded value.ContextPreview
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&decoded) != nil || !ValidContextPreview(decoded) {
		t.Fatal("blueprint does not decode strictly")
	}
	again, _ := json.Marshal(decoded)
	if !bytes.Equal(again, b) {
		t.Fatal("blueprint is not canonical across a round trip")
	}
	// request_capture: refused before target, storage or admission work.
	reads := f.targetReads.Load()
	if _, err := f.request(t, p, "recorder-1"); !errors.Is(err, value.ErrRecorderUnavailable) {
		t.Fatal(err)
	}
	if f.admissions.Load() != 0 || f.targetReads.Load() != reads || len(f.accepted) != 0 {
		t.Fatal("a refused recorder plan reached admission")
	}
}

func TestCompositionErrorsFollowEligibility(t *testing.T) {
	f := newInvestigationFixture()
	ctx := context.Background()
	bad := networkComposition(planning.ProfileEdit{ActionID: "sample", Field: "packetFilter", Text: "host db.payments.svc"})
	_, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(bad))
	var refusal planning.CompositionError
	if !errors.As(err, &refusal) || refusal.Code != planning.CompositionFilterRejected {
		t.Fatal("name lookup not refused", err)
	}
	// An authenticated but ineligible caller (no evidence:capture scope)
	// learns nothing about its composition or the target.
	f.identityChange = "scopes"
	_, err = f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(bad))
	if !errors.Is(err, value.ErrDenied) || errors.As(err, &refusal) {
		t.Fatal("composition refusal disclosed before eligibility", err)
	}
	if len(f.previews) != 0 {
		t.Fatal("refused composition stored a preview")
	}
}

func TestCompositionIntentExcludesSharingAndDiagnostic(t *testing.T) {
	f := newInvestigationFixture()
	i := f.compositionIntent(networkComposition())
	if !i.Valid() {
		t.Fatal("valid composition intent rejected")
	}
	i.Diagnostic = value.ContextDiagnosticName
	if i.Valid() {
		t.Fatal("diagnostic and composition together")
	}
	i.Diagnostic = ""
	i.Sharing = &value.ContextSharing{}
	if i.Valid() {
		t.Fatal("sharing accepted on a plan-only preview")
	}
	// The pod-status preview path refuses a composition intent.
	ctx := context.Background()
	if _, err := f.svc.Preview(ctx, f.source(t, ctx), f.compositionIntent(networkComposition())); err == nil {
		t.Fatal("pod-status preview accepted a composition")
	}
}

func TestComposedPolicyRefusedWithFieldPath(t *testing.T) {
	s := restartSpec()
	delete(s, "recipeRef")
	s["profileComposition"] = map[string]any{"components": []any{map[string]any{"id": "net", "profileRef": map[string]any{"catalog": "builtin", "name": "network-connections", "version": "v1"}}}, "maxTotalBytes": 16 << 20, "maxDuration": "20s"}
	_, err := compileSpec(t, s)
	var field value.PolicyFieldError
	if !errors.As(err, &field) || field.Path != "spec.profileComposition.components[0].profileRef" {
		t.Fatal(err)
	}
	s["profileComposition"] = map[string]any{"components": []any{map[string]any{"id": "ctx", "profileRef": map[string]any{"catalog": "builtin", "name": "process-context", "version": "v1"}}}, "maxTotalBytes": 1, "maxDuration": "1s"}
	if _, err = compileSpec(t, s); !errors.As(err, &field) || field.Path != "spec.profileComposition" {
		t.Fatal(err)
	}
}

type refusedRecorderPreview struct {
	availableRecording
	err   error
	calls int
}

func (r *refusedRecorderPreview) PacketRecorder(context.Context, targets.PodResolution) error {
	r.calls++
	return r.err
}
func TestRecorderPreviewOperationalFailureCannotStorePlanOnlyApproval(t *testing.T) {
	for _, failure := range []error{targets.ErrUnavailable, targets.ErrChanged, context.Canceled, context.DeadlineExceeded, errors.New("private routing failure")} {
		t.Run(failure.Error(), func(t *testing.T) {
			f := newInvestigationFixture()
			filters := &stubFilters{}
			f.svc.Filters = filters
			f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
			f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
			recorder := &refusedRecorderPreview{availableRecording: availableRecording{f}, err: failure}
			f.svc.Recorders = recorder
			got, err := f.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(networkComposition(planning.ProfileEdit{ActionID: "sample", Field: "packetFilter", Text: "tcp port 8080"})))
			if !errors.Is(err, failure) || got.Preview.ID != "" || len(f.previews) != 0 || filters.calls != 0 || f.admissions.Load() != 0 || recorder.calls != 1 {
				t.Fatal("operational failure produced a frozen plan", err, len(f.previews), filters.calls, recorder.calls)
			}
		})
	}
}
func TestRecorderPreviewExplicitUnsupportedRemainsPlanOnly(t *testing.T) {
	f := newInvestigationFixture()
	filters := &stubFilters{}
	f.svc.Filters = filters
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	recorder := &refusedRecorderPreview{availableRecording: availableRecording{f}, err: targets.ErrUnsupported}
	f.svc.Recorders = recorder
	got, err := f.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(networkComposition(planning.ProfileEdit{ActionID: "sample", Field: "packetFilter", Text: "tcp port 8080"})))
	if err != nil || got.Recordable || got.Preview.ID == "" || len(f.previews) != 1 || filters.calls != 1 || got.Preview.Storage != (value.ContextStorageSelection{}) || f.admissions.Load() != 0 || recorder.calls != 1 {
		t.Fatal("known unsupported capability lost plan-only preview", err, got.Recordable, len(f.previews))
	}
}
