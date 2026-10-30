package planning

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

func sourceSnapshotInput(t *testing.T) (value.ContextInput, time.Time) {
	t.Helper()
	in, now := contextInput(t)
	in.Target.ExecutionClass = artifact.ContextAPIExecution
	in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
	in.Capability.ExecutionClass = artifact.ContextAPIExecution
	in.Retention.EvidenceType = "packetCapture"
	in.Retention.AnchorAt = now.Add(-30 * time.Second)
	in.Retention.ExpiresAt = in.Retention.ExpiresAt.Add(-30 * time.Second)
	in.Retention.DeleteBy = in.Retention.DeleteBy.Add(-30 * time.Second)
	in.Snapshot = &value.SourceSnapshotContext{Request: artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest{9}, SourceID: "00000000-0000-4000-8000-000000000061", Fence: "00000000-0000-4000-8000-000000000062", SnapshotID: "00000000-0000-4000-8000-000000000063", SourceStartedAt: now.Add(-time.Minute), SourceHardUntil: now.Add(time.Hour), T0: now, IssuedAt: now, StartBy: now.Add(5 * time.Second), ProcessingUntil: in.Deadline, Before: 30 * time.Second, MaxBytes: artifact.RecordingNativeLimit}, ActionID: "packets", PolicyUID: "policy", TriggerKind: "recordingSave", ExecutionDigest: artifact.Digest{7}, RecipeDigest: artifact.Digest{8}}
	in.Snapshot.SourceAudience = []artifact.AudienceAssignment{{Kind: "Group", Issuer: in.Executor.Issuer, SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: "00000000-0000-4000-8000-000000000064", BasisDigest: artifact.Digest{4}}}
	var err error
	in.Snapshot.SourceAudienceDigest, err = SourceAudienceDigest(in.Snapshot.SourceAudience)
	if err != nil {
		t.Fatal(err)
	}
	if !in.Snapshot.Request.Valid() {
		t.Fatal("invalid request fixture")
	}
	return in, now
}

func TestSourceSnapshotContextUsesDistinctImmutableScope(t *testing.T) {
	in, now := sourceSnapshotInput(t)
	plan, err := CompileContext(in, now)
	if err != nil {
		t.Fatal("existing-source after0 snapshot lacks accepted planning branch", err)
	}
	if !VerifyContextPlan(plan, now) || plan.Input.Recorder != nil || plan.Input.Snapshot == nil {
		t.Fatal("snapshot was coerced into finite recorder or pod status")
	}
	frozen := plan.ScopeDigest
	in.Snapshot.Request.Before = time.Second
	in.Retention.AnchorAt = in.Retention.AnchorAt.Add(29 * time.Second)
	in.Retention.ExpiresAt = in.Retention.ExpiresAt.Add(29 * time.Second)
	in.Retention.DeleteBy = in.Retention.DeleteBy.Add(29 * time.Second)
	if plan.Input.Snapshot.Request.Before != 30*time.Second || !VerifyContextPlan(plan, now) {
		t.Fatal("caller mutated accepted snapshot input")
	}
	changed, err := CompileContext(in, now)
	if err != nil || changed.ScopeDigest == frozen {
		t.Fatal("changed requested window not bound independently", err)
	}
}

func TestSourceSnapshotScopeUsesOriginalInstantsAcrossSQLTimeLocations(t *testing.T) {
	in, now := sourceSnapshotInput(t)
	original, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	other := in
	other.Snapshot = in.Snapshot.Clone()
	request := &other.Snapshot.Request
	zone := time.FixedZone("sql-session", 3600)
	request.SourceStartedAt = request.SourceStartedAt.In(zone)
	request.SourceHardUntil = request.SourceHardUntil.In(zone)
	request.T0 = request.T0.In(zone)
	request.IssuedAt = request.IssuedAt.In(zone)
	request.StartBy = request.StartBy.In(zone)
	request.ProcessingUntil = request.ProcessingUntil.In(zone)
	restored, err := CompileContext(other, now)
	if err != nil || restored.ScopeDigest != original.ScopeDigest {
		t.Fatal("SQL timestamp location changed immutable source scope", err)
	}
}
