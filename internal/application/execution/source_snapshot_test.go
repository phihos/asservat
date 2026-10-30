package execution

import (
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/execution"
	"context"
	"encoding/json"
	"testing"
	"time"

	deliveryapp "asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	planning "asservat.local/asservat/internal/domain/planning"
)

func snapshotExecutionFixture(t *testing.T) (*apiRunnerFixture, APIContextRunner, identities.CurrentIdentity) {
	t.Helper()
	f, runner, current := apiRunner(t)
	f.work.Accepted.Deadline = f.now.Add(20 * time.Second)
	e := f.work.Accepted.Expectation
	e.Registration.WriteUntil = f.work.Accepted.Deadline
	b := collector.SourceBinding{RootID: contextID(41), PolicyUID: "policy", AcceptanceID: contextID(62), SourceID: contextID(63), Fence: contextID(64), ActionID: "a000000000000000000000001", PodUID: e.PodUID, NodeUID: contextID(70), BootID: contextID(65), CollectorPodUID: contextID(66), CollectorEpoch: contextID(67), Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}
	audienceDigest, audienceErr := compiler.SourceAudienceDigest(e.Audience)
	if audienceErr != nil {
		t.Fatal(audienceErr)
	}
	b.AudienceDigest = [32]byte(audienceDigest)
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: deliveryapp.SourceBindingDigest(b), SourceID: b.SourceID, Fence: b.Fence, SnapshotID: contextID(68), SourceStartedAt: f.now.Add(-time.Minute), SourceHardUntil: f.now.Add(time.Hour), T0: f.now, IssuedAt: f.now, StartBy: f.now.Add(5 * time.Second), ProcessingUntil: f.work.Accepted.Deadline, Before: 30 * time.Second, MaxBytes: artifact.RecordingNativeLimit}
	snapshot := &planning.SourceSnapshotContext{Request: request, ActionID: b.ActionID, PolicyUID: b.PolicyUID, TriggerKind: "policy", ExecutionDigest: artifact.Digest(b.Scope), RecipeDigest: e.RecipeDigest, SourceAudience: e.Audience, SourceAudienceDigest: audienceDigest}
	f.retention.EvidenceType = "packetCapture"
	f.retention.AnchorAt = artifact.SourceSnapshotAnchor(request)
	f.retention.ExpiresAt = f.retention.ExpiresAt.Add(-30 * time.Second)
	f.retention.DeleteBy = f.retention.DeleteBy.Add(-30 * time.Second)
	plan, err := compiler.CompileContext(planning.ContextInput{CaptureID: e.CaptureUID, CaseID: e.CaseID, Executor: f.work.Actor, Deadline: f.work.Accepted.Deadline, Target: f.target, Retention: f.retention, Capability: f.cap, Snapshot: snapshot}, f.now)
	if err != nil {
		t.Fatal("snapshot plan", err)
	}
	e.NativeType, e.ActionID, e.Snapshot = artifact.PCAPNGArtifact, b.ActionID, &request
	e.Lifecycle, err = compiler.SourceSnapshotLifecycle(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.Registration.AnchorAt = f.retention.AnchorAt
	e.Registration.ExpiresAt, e.Registration.DeleteBy = f.retention.ExpiresAt, f.retention.DeleteBy
	e.TriggeredAt = request.T0
	e.PlanDigest = plan.ScopeDigest
	bindingJSON, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	e.SourceSnapshotManifest = &artifact.SourceSnapshotManifest{CanonicalScope: plan.CanonicalScope, Binding: bindingJSON}
	if err = e.Validate(); err != nil {
		t.Fatal("valid admitted snapshot fixture", err)
	}
	f.work.Accepted.Expectation = e
	f.work.Accepted.ScopeDigest = e.PlanDigest
	f.work.SourceBinding = &b
	f.work.SourceAudience = e.Audience
	if !b.Valid() {
		t.Fatal("invalid independently retained source binding")
	}
	return f, runner, current
}

func TestAPIContextSnapshotRecompilesOnlyAdmittedSource(t *testing.T) {
	f, runner, current := snapshotExecutionFixture(t)
	b := *f.work.SourceBinding
	check, _, err := runner.checkObserved(t.Context(), current, f.work, f.actor.ValidUntil, nil, nil)
	if err != nil || !check.Valid(f.now) || check.Plan.Input.Snapshot == nil || check.Plan.Input.Recorder != nil {
		t.Fatal("admitted source snapshot cannot reach typed API check", err)
	}
	replacement := b
	replacement.Fence = contextID(69)
	f.work.SourceBinding = &replacement
	if _, _, err = runner.checkObserved(t.Context(), current, f.work, f.actor.ValidUntil, nil, nil); err == nil {
		t.Fatal("different source fence inherited admitted snapshot")
	}
}

type snapshotCollectionFixture struct{ collection evidence.RecordingCollection }

func (s snapshotCollectionFixture) CollectRecording(context.Context) (evidence.RecordingCollection, error) {
	return s.collection, nil
}

type snapshotCompletionFixture struct {
	*apiRunnerFixture
	snapshotCompletions int
}

func (s *snapshotCompletionFixture) RecordAPIStoredSnapshotCompletion(_ context.Context, r value.APIExecution, _ artifact.ContextWriterCompletion, _ artifact.SourceSnapshotCoverage, _ value.APIProcessObservation, _ artifact.RecoveryProof) (value.APIExecution, error) {
	s.snapshotCompletions++
	return r, nil
}

func TestAPIContextSnapshotCollectionKeepsAcceptedDigestAndChecksCoverage(t *testing.T) {
	f, runner, _ := snapshotExecutionFixture(t)
	e := f.work.Accepted.Expectation
	accepted := evidence.ContextExpectationDigest(e)
	coverage := artifact.SourceSnapshotCoverage{Request: *e.Snapshot, AcceptedExpectationDigest: accepted, NativeBytes: 100, Retained: 1, AvailableFrom: e.Snapshot.T0.Add(-time.Second), ObservedUntil: e.Snapshot.T0, CompletedAt: f.now}
	projected, err := artifact.ProjectSourceSnapshotCoverage(e, accepted, coverage)
	if err != nil {
		t.Fatal("valid partial coverage", err)
	}
	var copies artifact.Copies
	for n := range copies {
		copies[n] = artifact.CopyReceipt{VersionID: "v1", ETag: "synthetic", Bytes: 100, SHA256: artifact.Digest{byte(n + 1)}}
	}
	c := evidence.RecordingCollection{State: evidence.RecordingStored, Acquired: e.Registration.AnchorAt, Completion: artifact.ContextWriterCompletion{RegistrationDigest: artifact.Digest{1}, ExpectationDigest: evidence.ContextExpectationDigest(projected), Copies: copies, StoredAt: f.now, ClosedAt: f.now}, SnapshotCoverage: &coverage}
	recorder := &snapshotCompletionFixture{apiRunnerFixture: f}
	runner.Record = recorder
	execution := value.APIExecution{Phase: "started", ExpectationDigest: accepted}
	result, err := runner.CollectRecording(t.Context(), f.work, execution, snapshotCollectionFixture{c})
	if err != nil || result.State != "StoredPendingVerification" || recorder.snapshotCompletions != 1 || execution.ExpectationDigest != accepted {
		t.Fatal("snapshot bypassed typed coverage completion or changed accepted digest", result.State, err, recorder.snapshotCompletions)
	}
	changed := coverage
	changed.Request.Fence = contextID(99)
	c.SnapshotCoverage = &changed
	if _, err = runner.CollectRecording(t.Context(), f.work, execution, snapshotCollectionFixture{c}); err == nil || recorder.snapshotCompletions != 1 {
		t.Fatal("different source window reached completion persistence", err, recorder.snapshotCompletions)
	}
}
