package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// Full typed application plan -> accepted-row codec. Every authority/proof and
// receipt below is an explicit unit fixture; real admission uses the separate
// policy_source_snapshot_admission integration helper. No persisted finite row
// is edited here and this is not SQL/provider/collector qualification.
func TestGeneratedSourceSnapshotPlanDecodesAcceptedAPIWork(t *testing.T) {
	facts, _, _ := apiCompletedFixture(t)
	base, err := admittedRecord(facts.ContextCapture)
	if err != nil {
		t.Fatal(err)
	}
	check, now := sourceRetentionCheckFixture(t, 120, 20)
	e := base.Expectation
	bindingJSON := json.RawMessage(`{"fixture":"independent-source-binding"}`)
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(sha256.Sum256(bindingJSON)), SourceID: check.SourceID, Fence: check.Fence, SnapshotID: "20000000-0000-4000-8000-000000000020", SourceStartedAt: now.Add(-time.Minute), SourceHardUntil: now.Add(time.Hour), T0: now, IssuedAt: now, StartBy: now.Add(5 * time.Second), ProcessingUntil: now.Add(20 * time.Second), Before: 30 * time.Second, MaxBytes: 64 << 10}
	original := targets.SourceSnapshotTarget{Request: check.Target.Request, Pin: check.Target.Pin, NodeUID: check.Node.NodeUID, BootID: check.Node.BootID, CollectorPodUID: check.Node.CollectorPodUID, CollectorEpoch: check.Node.CollectorEpoch, SourceID: request.SourceID, Fence: request.Fence, BindingDigest: [32]byte(request.SourceBindingDigest)}
	audienceDigest, err := compiler.SourceAudienceDigest(e.Audience)
	if err != nil {
		t.Fatal(err)
	}
	selected := &planning.SourceSnapshotContext{Request: request, ActionID: check.Policy.Recorder.Action.ID, PolicyUID: check.Authority.PolicyUID, TriggerKind: "policy", ExecutionDigest: check.Authority.ScopeDigest, RecipeDigest: check.Policy.Recorder.RecipeDigest, SourceAudience: e.Audience, SourceAudienceDigest: audienceDigest, SourceTarget: &original}
	retained := check.Retention
	retained.AnchorAt = retained.AnchorAt.Add(-30 * time.Second)
	retained.ExpiresAt = retained.ExpiresAt.Add(-30 * time.Second)
	retained.DeleteBy = retained.DeleteBy.Add(-30 * time.Second)
	report := targets.SourceSnapshotResolution{Original: original, Process: check.Node, State: targets.RecorderSourceState{SourceID: request.SourceID, Fence: request.Fence, IssuedAt: now.Add(-time.Second), LeafUntil: now.Add(30 * time.Second), Credit: 1, ObservedAt: now, FreshUntil: now.Add(15 * time.Second)}, ReportedAt: now, ReportFreshUntil: now.Add(15 * time.Second), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	routing := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: original.Request, Pin: original.Pin}
	capability := planning.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Enabled: true, Revision: identity.Revision{UID: "fixture-ceiling", Generation: 1, Digest: artifact.Digest{1}}, CollectorVersion: e.CollectorVersion, CollectorImageDigest: e.CollectorImageDigest, ProjectionDigest: compiler.ProjectionDigest(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	plan, err := compiler.CompileContext(planning.ContextInput{CaptureID: e.CaptureUID, CaseID: e.CaseID, Executor: check.Authority.Executor, Deadline: request.ProcessingUntil, Target: routing, Retention: retained, Capability: capability, Snapshot: selected, SnapshotSource: &report}, now)
	if err != nil {
		t.Fatal("generated snapshot scope", err)
	}
	e.NativeType, e.ActionID, e.Snapshot = artifact.PCAPNGArtifact, selected.ActionID, request.Clone()
	e.Lifecycle, err = compiler.SourceSnapshotLifecycle(selected)
	if err != nil {
		t.Fatal(err)
	}
	e.Registration.Location.ClusterID = original.Request.ClusterID
	e.Registration.NativeLimit = request.MaxBytes
	e.Registration.AnchorAt, e.Registration.WriteUntil, e.Registration.ExpiresAt, e.Registration.DeleteBy = retained.AnchorAt, request.ProcessingUntil, retained.ExpiresAt, retained.DeleteBy
	e.Namespace, e.NamespaceUID, e.WorkloadUID, e.PodUID = original.Request.Namespace.Name, original.Request.Namespace.UID, original.Request.Workload.UID, original.Request.PodUID
	e.RequestedAgeSeconds, e.MaximumAgeSeconds, e.DeletionBudgetSeconds = retained.RequestedSeconds, retained.MaximumSeconds, retained.DeletionBudgetSeconds
	e.PurposeRef, e.RetentionRules = retained.PurposeRef, retained.Policies
	e.RecipeDigest, e.PlanDigest, e.TriggeredAt = plan.RecipeDigest, plan.ScopeDigest, request.T0
	e.SourceSnapshotManifest = &artifact.SourceSnapshotManifest{CanonicalScope: plan.CanonicalScope, Binding: bindingJSON}
	if err = e.Validate(); err != nil {
		t.Fatal("full expected snapshot", err)
	}
	t.Run("reviewed-admission", func(t *testing.T) {
		assertReviewedSnapshotPlan(t, plan, e, check)
	})
	row := facts.ContextCapture
	row.ExpectationJson, _ = json.Marshal(e)
	row.PodPinJson, _ = json.Marshal(original.Pin)
	row.ScopeJson, row.ScopeDigest = plan.CanonicalScope, plan.ScopeDigest[:]
	row.CreatedAt, row.Deadline = ts(now), ts(request.ProcessingUntil)
	intent, err := captureIntent(row)
	if err != nil {
		t.Fatal("full snapshot audit input", err)
	}
	row.IntentDigest = digest(intent)
	work, err := apiWork(row)
	if err != nil || work.Actor != check.Authority.Executor || work.Accepted.Expectation.Snapshot == nil || !work.Accepted.Expectation.Snapshot.Equal(request) || evidence.ContextExpectationDigest(work.Accepted.Expectation) != evidence.ContextExpectationDigest(e) {
		t.Fatal("application-generated snapshot failed accepted API codec", err)
	}
	// This codec deliberately returns no current target. Its caller must obtain
	// that ONLY from the independently protected107 source-provenance reader.
	if work.SourceTarget != nil || work.Target != (targets.Request{}) {
		t.Fatal("scope labels were used as independent current source authority")
	}
	if kinds := historyActionKinds(e); len(kinds) != 1 || kinds[0] != "packetCapture" {
		t.Fatal("valid packet snapshot mislabeled in capture history", kinds)
	}
	if scope, err := requestRecordScope(row); err != nil || scope.Actor != check.Authority.Executor || scope.Target != original.Target() {
		t.Fatal("genuine accepted snapshot could not resolve its original request", err)
	}
}
