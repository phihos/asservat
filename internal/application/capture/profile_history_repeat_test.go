package capture

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func namespaceHeapHistory(t *testing.T) (storedProfileReview, ContextHistoryService, *historyReaderFixture) {
	t.Helper()
	x := newStoredProfileReview(t, true)
	s, reader := historyService(x.f.investigationFixture)
	p := x.preview.Preview
	reader.settings.CaptureID = p.CaptureID
	// Match the persisted settings boundary: current catalog documents and
	// old endpoint resolutions are not authored repeat input.
	composition, err := json.Marshal(p.Intent.Composition)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(composition, &reader.settings.Composition); err != nil || reader.settings.Composition.Resolved != nil {
		t.Fatal("stored composition", err)
	}
	reader.settings.SettingsKey = artifact.Digest{8}
	reader.settings.ExecutionDigest = p.ScopeDigest
	reader.settings.RequestedSeconds = p.Intent.RequestedSeconds
	reader.settings.OriginalEffectiveSeconds = 60
	reader.settings.ExpiresAt = x.f.now.Add(2 * time.Second)
	pins := []map[string]string{{"role": "collector", "digest": hex.EncodeToString(x.preview.CollectorImageDigest[:])}, {"role": "captureProfile", "digest": hex.EncodeToString(x.preview.Plan.Profiles[0].DefinitionDigest[:])}}
	reader.settings.DependencyJSON, err = json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	var scope struct{ Recipe, Filters, ProfileComposition json.RawMessage }
	if err := json.Unmarshal(p.CanonicalScope, &scope); err != nil {
		t.Fatal(err)
	}
	reader.settings.RecipeJSON, reader.settings.FrozenFilters, reader.settings.CompositionJSON = scope.Recipe, scope.Filters, scope.ProfileComposition
	return x, s, reader
}

func TestProfileHistoryNamespaceHeapRepeatRehydratesFreshPreview(t *testing.T) {
	x, service, reader := namespaceHeapHistory(t)
	original := x.preview.Preview
	settingsBefore, err := json.Marshal(reader.settings)
	if err != nil {
		t.Fatal(err)
	}
	compositionBefore, err := json.Marshal(reader.settings.Composition)
	if err != nil {
		t.Fatal(err)
	}
	catalogReads, endpointReads := x.catalog.reads, x.endpoint.calls
	x.f.now = x.f.now.Add(100 * time.Millisecond)
	x.f.target.Request.PodName, x.f.target.Request.PodUID = "api-current", "current-pod"
	x.f.target.Pin.Name, x.f.target.Pin.UID = "api-current", "current-pod"
	x.endpoint.changed = true
	x.catalog.onRead = func(_ context.Context, target targets.PodResolution, refs []planning.ProfileRef) {
		if target.Request != x.f.target.Request || len(refs) != 1 || refs[0] != reader.settings.Composition.Components[0].Profile {
			t.Fatal("repeat catalog read lost current target or exact namespace version", target, refs)
		}
	}
	repeated, settings, err := service.PreviewRepeat(t.Context(), x.f.source(t, t.Context()), original.CaptureID, nil)
	if err != nil || repeated.Recorder == nil || !repeated.Recorder.Recordable {
		t.Fatal("namespace heap history repeat", err)
	}
	p, plan := repeated.Preview, repeated.Recorder.Plan
	compositionAfter, err := json.Marshal(p.Intent.Composition)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compositionBefore, compositionAfter) || p.ID == original.ID || p.CaptureID == original.CaptureID || p.Target.PodUID != "current-pod" || p.Intent.RepeatedFrom == nil || p.Intent.RepeatedFrom.CaptureID != original.CaptureID || !p.Intent.RepeatedFrom.ExpiresAt.Equal(reader.settings.ExpiresAt) || !p.Deadline.Equal(reader.settings.ExpiresAt) || !settings.ExpiresAt.Equal(reader.settings.ExpiresAt) || p.Intent.RequestedSeconds != reader.settings.RequestedSeconds {
		t.Fatal("repeat changed authored settings/source expiry or reused original identity", p)
	}
	if x.catalog.reads != catalogReads+1 || x.endpoint.calls != endpointReads+1 || len(plan.Profiles) != 1 || plan.Profiles[0] != x.preview.Plan.Profiles[0] || len(plan.Input.Endpoints) != 1 || plan.Input.Endpoints[0].Request.Target.PodUID != "current-pod" || !plan.Input.Endpoints[0].ResolvedAt.Equal(x.f.now) || plan.Input.Endpoints[0].EndpointDigest != (artifact.Digest{9}) || plan.Input.Endpoints[0].ResolvedAt.Equal(x.preview.Plan.Input.Endpoints[0].ResolvedAt) {
		t.Fatal("repeat reused stale catalog/endpoint observations", plan.Input.Endpoints)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].ProfileType != "heap" || plan.Actions[0].ProfileMode != "snapshot" || plan.Actions[0].ForceGC || plan.Actions[0].Duration != "" || plan.Actions[0].Timeout != "5s" || plan.Actions[0].MaxBytes != 16<<20 || len(x.grants.requests) != 0 || len(x.f.seen) != 0 {
		t.Fatal("passive repeat changed heap acquisition or requested approval/capture", plan.Actions)
	}
	settingsAfter, err := json.Marshal(reader.settings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(settingsBefore, settingsAfter) || reader.settings.Composition.Resolved != nil || !reflect.DeepEqual(x.f.previews[original.ID].CanonicalScope, original.CanonicalScope) {
		t.Fatal("repeat mutated source settings or original preview")
	}
}

func TestProfileHistoryNamespaceHeapRepeatRejectsChangedVersion(t *testing.T) {
	for _, change := range []string{"definition", "disabled", "missing"} {
		t.Run(change, func(t *testing.T) {
			x, service, reader := namespaceHeapHistory(t)
			before, err := json.Marshal(reader.settings)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "definition":
				x.catalog.profiles[0].Document = bytes.Replace(x.catalog.profiles[0].Document, []byte(`"timeout":"5s"`), []byte(`"timeout":"6s"`), 1)
			case "disabled":
				x.catalog.profiles[0].Enabled = false
			case "missing":
				x.catalog.profiles = nil
			}
			result, _, err := service.PreviewRepeat(t.Context(), x.f.source(t, t.Context()), x.preview.Preview.CaptureID, nil)
			if err == nil || result.Recorder != nil || len(x.grants.requests) != 0 || len(x.f.seen) != 0 {
				t.Fatal("changed namespace version produced repeat", change, err)
			}
			if change == "definition" && !errors.Is(err, value.ErrProfileChanged) {
				t.Fatal("immutable version drift did not require fresh selection", change, err)
			}
			after, marshalErr := json.Marshal(reader.settings)
			if marshalErr != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal changed original settings", marshalErr)
			}
		})
	}
}
