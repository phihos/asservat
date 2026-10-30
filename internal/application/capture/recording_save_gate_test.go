package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestDisabledManualSaveRetainsAcceptedReplayButCannotContinue(t *testing.T) {
	f, x, s, p := submissionTest(t)
	x.current = f.source(t, t.Context())
	// Seed the normal accepted journal through its real app path, then substitute
	// a structurally valid snapshot receipt to exercise accepted-only routing.
	a, err := f.svc.Request(t.Context(), x.current, p.ID, "original")
	if err != nil {
		t.Fatal(err)
	}
	e := a.Expectation
	scope, binding := []byte(`{"schemaVersion":"recording-save/v1"}`), []byte(`{}`)
	e.NativeType, e.ActionID = artifact.PCAPNGArtifact, "a0123456789abcdef01234567"
	e.PlanDigest = sha256.Sum256(scope)
	e.Registration.NativeLimit = 64 << 10
	q := artifact.SourceSnapshotRequest{SourceBindingDigest: sha256.Sum256(binding), SourceID: fixtureID(810), Fence: fixtureID(811), SnapshotID: fixtureID(812), SourceStartedAt: e.TriggeredAt, SourceHardUntil: e.Registration.WriteUntil, T0: e.TriggeredAt, IssuedAt: e.TriggeredAt, StartBy: e.TriggeredAt.Add(5 * time.Second), ProcessingUntil: e.Registration.WriteUntil, Before: time.Second, MaxBytes: e.Registration.NativeLimit}
	e.Snapshot = &q
	e.SourceSnapshotManifest = &artifact.SourceSnapshotManifest{CanonicalScope: scope, Binding: binding}
	e.Lifecycle = &artifact.OngoingLifecycle{TriggerKind: "recordingSave", SourceSessionID: q.SourceID, SourceStartedAt: q.SourceStartedAt, SnapshotID: q.SnapshotID, RequestedBefore: q.Before, HistoryCoverage: "unknown", WindowCoverage: "unknown", GapReasons: []string{"unknownLoss"}, Origin: &artifact.RecordingSaveOrigin{PolicyUID: "original-policy", PolicyExecutionDigest: artifact.Digest{1}}}
	a.Expectation, a.ScopeDigest = e, e.PlanDigest
	if !acceptedContext(a, ContextRequestDigest(p.ID)) {
		t.Fatal("valid accepted snapshot receipt baseline required", e.Validate(), q.Valid(), e.Lifecycle.Validate(e.TriggeredAt), e.Registration.Validate(), q)
	}
	f.accepted[fixtureKey(f.actor, "original")] = a
	replay, err := s.Request(t.Context(), x.current, p.ID, "original")
	if err != nil || !replay.Replay || replay.CaptureID != a.CaptureID || x.starts != 0 || x.intentReads != 0 {
		t.Fatal("disabled Save hid accepted receipt or started replay", replay, err)
	}
	continued, err := s.Continue(t.Context(), x.current, p.ID, "original")
	if !errors.Is(err, value.ErrUnavailable) || continued.CaptureID != a.CaptureID || x.starts != 0 || x.intentReads != 0 {
		t.Fatal("disabled Save continuation reached active path", continued, err)
	}
}
