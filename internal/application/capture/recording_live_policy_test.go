package capture

import (
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"testing"
	"time"
)

type recordingLiveAccepted struct {
	snapshot authorization.AcceptedPolicySnapshot
}

func (p recordingLiveAccepted) AcceptedPolicyAuthority(context.Context, string) (authorization.AcceptedPolicySnapshot, error) {
	return p.snapshot, nil
}

func TestCurrentSourcePolicyDoesNotRequireSeparateRecordingSaveOptIn(t *testing.T) {
	f, activation := newWorkloadActivationFixture(t)
	activation.CompileRecorder = ongoingSaveCompiler
	edit := f.edit
	f.edit = func(spec map[string]any) {
		edit(spec)
		component := spec["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)
		delete(component, "overrides")
	}
	if _, e := activation.Activate(t.Context(), f, "restarts", "ongoing", true); e != nil {
		t.Fatal(e)
	}
	accepted := recordingLiveAccepted{authorization.AcceptedPolicySnapshot{IntentVersion: 1, Authority: f.accepted[0].Authority, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), SourceUntil: f.now.Add(5 * time.Second)}}
	s := CurrentRecordingPolicies{Documents: f, Accepted: accepted, CompileRecorder: ongoingSaveCompiler, RecipeName: "builtin-pod-status-v1", RecipeDigest: testRecipe, Now: func() time.Time { return f.now }}
	p, e := s.SourcePolicy(t.Context(), "restarts", "policy-uid")
	if e != nil || p.Policy.Recorder == nil || p.Policy.Recorder.Action.ExecutionMode != "ongoing" || p.Policy.RecordingSaves {
		t.Fatal(p, e)
	}
	if _, e = s.RecordingPolicy(t.Context(), "restarts", "policy-uid"); e == nil {
		t.Fatal("source observation enabled separately disabled Save")
	}
	f.now = f.now.Add(5 * time.Second)
	if _, e = s.SourcePolicy(t.Context(), "restarts", "policy-uid"); e == nil {
		t.Fatal("expired accepted source revived")
	}
}
