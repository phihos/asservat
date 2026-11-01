package postgres

import (
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/planning"
	"testing"
	"time"
)

func TestManualSaveCanonicalTimeoutCannotExceedProtectedAuthoredCaps(t *testing.T) {
	in, now := sourceRetentionCheckFixture(t, 120, 20)
	_, selected := sourceProvenanceTestRow(t, 1)
	for _, test := range []struct {
		name, recipe string
		larger       time.Duration
	}{{"recipe-at-action-bound", "15s", 16 * time.Second}, {"longer-recipe-keeps-action-cap", "1m", 16 * time.Second}} {
		t.Run(test.name, func(t *testing.T) {
			composition := in.Policy.Recorder.Composition
			composition.MaxDuration = test.recipe
			recorder, err := compiler.CompileOngoingPolicyRecorder(composition, nil)
			if err != nil {
				t.Fatal("real protected profile compilation", err)
			}
			p := in.Policy
			p.Recorder = &recorder
			action, err := time.ParseDuration(recorder.Action.Timeout)
			if err != nil {
				t.Fatal(err)
			}
			recipe, err := time.ParseDuration(recorder.Composition.MaxDuration)
			if err != nil {
				t.Fatal(err)
			}
			maximum := min(action, recipe)
			if test.larger <= maximum {
				t.Fatal("negative fixture does not exceed authored cap", test.larger, maximum)
			}
			scope := compiler.RecordingSaveScopeInput{CaptureID: in.SourceID, Requester: in.Authority.Creator, Authority: in.Authority, Sources: []compiler.RecordingSaveScopeSource{{PolicyUID: in.Authority.PolicyUID, ExecutionDigest: in.Authority.ScopeDigest, Original: *selected.SourceTarget, ActionID: recorder.Action.ID, Kind: recorder.Action.Kind, DefinitionDigest: artifact.Digest(recorder.Digest), AudienceDigest: selected.SourceAudienceDigest, ApprovedBefore: 30 * time.Second, Before: time.Second, MaxBytes: 64 << 10}}, IncidentPodLimit: 1, FinalizeTimeout: maximum, CeilingDigest: artifact.Digest{1}, RetentionDigest: artifact.Digest{2}}
			compile := func(timeout time.Duration) planning.ContextPlan {
				t.Helper()
				scope.FinalizeTimeout = timeout
				raw, digest, err := compiler.CompileRecordingSaveScope(scope, now)
				if err != nil {
					t.Fatal("actual canonical manual scope", err)
				}
				return planning.ContextPlan{CanonicalScope: raw, ScopeDigest: digest}
			}
			if !manualPolicySaveFinalizeCurrent(p, compile(maximum)) {
				t.Fatal("valid authored cap refused", maximum)
			}
			if manualPolicySaveFinalizeCurrent(p, compile(test.larger)) {
				t.Fatal("canonical timeout exceeded independently protected authored cap", test.larger, maximum)
			}
			if !manualPolicySaveFinalizeCurrent(p, compile(time.Second)) {
				t.Fatal("shorter manual timeout refused")
			}
		})
	}
}
