package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func historyRecordingFixture(t *testing.T) (*investigationFixture, ContextHistoryService, *historyReaderFixture) {
	t.Helper()
	f := newInvestigationFixture()
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	f.svc.Recorders = availableRecording{f}
	f.svc.Filters = &stubFilters{}
	s, r := historyService(f)
	s.Previews = f.svc
	c := networkComposition(planning.ProfileEdit{ActionID: "sample", Field: "packetFilter", Text: "tcp port 443"}, planning.ProfileEdit{ActionID: "sample", Field: "packetAfter", Text: "3s"})
	original, err := f.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(c))
	if err != nil || !original.Recordable {
		t.Fatal("original recording", err)
	}
	r.settings.Composition = c.Clone()
	r.settings.SettingsKey = artifact.Digest{8}
	r.settings.OriginalEffectiveSeconds = 60
	pins := []map[string]string{{"role": "collector", "digest": hex.EncodeToString(f.cap.CollectorImageDigest[:])}, {"role": "captureProfile", "digest": hex.EncodeToString(original.Plan.Profiles[0].DefinitionDigest[:])}}
	r.settings.DependencyJSON, _ = json.Marshal(pins)
	var scope struct{ Recipe, Filters json.RawMessage }
	if json.Unmarshal(original.Plan.CanonicalScope, &scope) != nil {
		t.Fatal("scope")
	}
	r.settings.RecipeJSON = scope.Recipe
	r.settings.FrozenFilters = scope.Filters
	return f, s, r
}
func TestHistoryRecorderRepeatRestoresFilterWindowAndFreshPod(t *testing.T) {
	f, s, r := historyRecordingFixture(t)
	f.target.Request.PodName, f.target.Request.PodUID, f.target.Pin.Name, f.target.Pin.UID = "api-new", "pod-new", "api-new", "pod-new"
	result, settings, err := s.PreviewRepeat(t.Context(), f.source(t, t.Context()), fixtureID(41), nil)
	if err != nil || result.Recorder == nil || !result.Recorder.Recordable {
		t.Fatal("recorder repeat substituted preset", err)
	}
	p := result.Preview
	if p.Target.PodUID != "pod-new" || p.CaptureID == fixtureID(41) || p.Intent.Composition == nil || p.Intent.Composition.Components[0].Edits[0].Text != "tcp port 443" || p.Intent.Composition.Components[0].Edits[1].Text != "3s" || p.Intent.RepeatedFrom == nil || p.Intent.RepeatedFrom.CaptureID != fixtureID(41) || p.Deadline.After(settings.ExpiresAt) || p.Intent.Reason != nil || p.Intent.Sharing != nil {
		t.Fatal("repeat lost authored settings/current selection or restored old authority", p.Intent)
	}
	edited := r.settings.Composition.Clone()
	edited.Components[0].Edits[0].Text = "tcp port 8443"
	edited.MaxDuration = "15s"
	fresh, _, err := s.PreviewEditedRepeat(t.Context(), f.source(t, t.Context()), fixtureID(41), nil, value.HistoryRepeatEdits{Composition: edited, RequestedSeconds: 90})
	if err != nil || fresh.Recorder == nil || fresh.Preview.Intent.RequestedSeconds != 90 || fresh.Preview.Intent.Composition.Components[0].Edits[0].Text != "tcp port 8443" || fresh.Preview.Intent.Composition.MaxDuration != "15s" {
		t.Fatal("edited repeat lost explicit edits", err)
	}
	f.cap.CollectorImageDigest = artifact.Digest{99}
	if _, _, err = s.PreviewRepeat(t.Context(), f.source(t, t.Context()), fixtureID(41), nil); !errors.Is(err, value.ErrProfileChanged) {
		t.Fatal("repeat silently upgraded collector image", err)
	}
}
func TestHistoryPolicyRequiresExplicitCurrentSelectionAndPodRepeatPinsUID(t *testing.T) {
	f, s, r := historyRecordingFixture(t)
	r.settings.Selection = "triggeringPod"
	if _, _, err := s.PreviewRepeat(t.Context(), f.source(t, t.Context()), fixtureID(41), nil); !errors.Is(err, value.ErrHistorySelectionRequired) {
		t.Fatal("policy occurrence silently selected a manual Pod", err)
	}
	if _, _, err := s.PreviewEditedRepeat(t.Context(), f.source(t, t.Context()), fixtureID(41), nil, value.HistoryRepeatEdits{Selection: "currentEligiblePod"}); err != nil {
		t.Fatal("explicit current selection failed", err)
	}
	original := authorization.Target{ClusterID: fixtureID(4), NamespaceUID: "ns", WorkloadUID: "deployment", PodUID: "old-pod"}
	if _, err := f.svc.PreviewRepeat(t.Context(), f.source(t, t.Context()), f.intent(), original); !errors.Is(err, value.ErrTargetReplaced) {
		t.Fatal("preset repeat replaced explicit Pod under same workload", err)
	}
	if _, err := f.svc.PreviewCompositionRepeat(t.Context(), f.source(t, t.Context()), f.compositionIntent(r.settings.Composition), original); !errors.Is(err, value.ErrTargetReplaced) {
		t.Fatal("recorder repeat replaced explicit Pod under same workload", err)
	}
}
func TestHistoryFiltersRefuseImplicitCompilerDrift(t *testing.T) {
	old := []byte(`[{"actionID":"net_sample","expression":"tcp port 443","program":[[6,0,0,64]],"programDigest":"one"}]`)
	changed := []byte(`{"filters":[{"actionID":"net_sample","expression":"tcp port 443","program":[[6,0,0,0]],"programDigest":"two"}]}`)
	if historyFiltersMatch(old, changed, false) || historyFiltersMatch(old, changed, true) {
		t.Fatal("same filter silently changed its compiled observation predicate")
	}
	intentional := []byte(`{"filters":[{"actionID":"net_sample","expression":"tcp port 8443","program":[[6,0,0,0]],"programDigest":"two"}]}`)
	if !historyFiltersMatch(old, intentional, true) {
		t.Fatal("explicit edited predicate rejected")
	}
}
func TestHistoryDraftPreservesAuthoredPolicyInsteadOfTriggeringPod(t *testing.T) {
	f := newInvestigationFixture()
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	intent := f.intent()
	authored := intent.Target
	intent.Target.Kind, intent.Target.Name = "Pod", f.target.Request.PodName
	intent.HistoryAuthored = &value.HistoryAuthored{Target: authored, TargetJSON: json.RawMessage(`{"namespace":"payments","workloadRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"api"},"maxPods":1,"selection":"triggeringPod","adoption":"pinUID"}`), Selector: value.HistorySelector{ClusterID: fixtureID(4), NamespaceUID: "ns", WorkloadKind: "Deployment", WorkloadUID: "deployment"}, Selection: "triggeringPod", PolicyOrigins: []value.HistoryPolicyOrigin{{UID: "policy", Generation: 3, IntentVersion: 2, CollectionDigest: artifact.Digest{7}}}}
	preview, err := f.svc.Preview(t.Context(), f.source(t, t.Context()), intent)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := f.svc.Request(t.Context(), f.source(t, t.Context()), preview.Preview.ID, "policy-history-draft")
	if err != nil {
		t.Fatal(err)
	}
	draft, err := HistoryDraftFromPreview(preview.Preview, accepted)
	if err != nil || draft.Target != authored || draft.ExplicitPodUID != "" || draft.Selector().WorkloadKind != "Deployment" || draft.Selection != "triggeringPod" || len(draft.PolicyOrigins) != 1 || draft.PolicyOrigins[0].IntentVersion != 2 || draft.PolicyOrigins[0].Generation != 3 {
		t.Fatal("policy history copied a resolved Pod instead of its authored selector/version", draft, err)
	}
	clone := preview.Preview.Clone()
	clone.Intent.HistoryAuthored.PolicyOrigins[0].Generation++
	if preview.Preview.Intent.HistoryAuthored.PolicyOrigins[0].Generation != 3 {
		t.Fatal("policy source clone aliases history provenance")
	}
}
