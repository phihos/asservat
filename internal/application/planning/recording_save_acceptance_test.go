package planning

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
	"testing"
	"time"
)

func manualSnapshotPlan(t *testing.T) (value.ContextPlan, artifact.Registration, time.Time) {
	t.Helper()
	scope, now := recordingSaveScopeInput(t)
	in, _ := sourceSnapshotInput(t)
	source := &scope.Sources[0]
	source.ActionID, source.Before, source.MaxBytes = in.Snapshot.ActionID, in.Snapshot.Request.Before, in.Snapshot.Request.MaxBytes
	in.Snapshot.SourceDefinitionDigest = source.DefinitionDigest
	scope.CeilingDigest = artifact.Digest(in.Capability.Revision.Digest)
	scope.RetentionDigest = artifact.Digest(in.Retention.PolicyRevision.Digest)
	raw, _, err := CompileRecordingSaveScope(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	in.Executor = scope.Authority.Executor
	in.Snapshot.SourceTarget = &source.Original
	in.Snapshot.TriggerKind = "recordingSave"
	in.Snapshot.RecordingSaveScope = raw
	plan, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	uuid := func(suffix string) string { return "10000000-0000-4000-8000-0000000000" + suffix }
	r := artifact.Registration{Location: artifact.Location{ClusterID: in.Target.Request.ClusterID, ArtifactID: uuid("01"), AttemptID: uuid("02")}, StoreID: uuid("03"), AllocationID: uuid("04"), PoolRevision: 1, AllocationRevision: 1, NativeLimit: in.Snapshot.Request.MaxBytes, AnchorAt: in.Retention.AnchorAt, WriteUntil: in.Deadline, ExpiresAt: in.Retention.ExpiresAt, DeleteBy: in.Retention.DeleteBy}
	if r.Validate() != nil {
		t.Fatal("valid original registration")
	}
	return plan, r, now
}

func TestManualAcceptanceReanchorsOnlyAtOriginalDatabaseT0(t *testing.T) {
	plan, r, now := manualSnapshotPlan(t)
	t0 := now.Add(2300 * time.Millisecond)
	accepted, registration, err := ReanchorRecordingSave(plan, r, t0, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	request := accepted.Input.Snapshot.Request
	if !request.T0.Equal(t0) || !request.IssuedAt.Equal(t0) || !request.ProcessingUntil.Equal(t0.Add(20*time.Second)) || !request.StartBy.Equal(t0.Add(5*time.Second)) {
		t.Fatal("DB acceptance did not fix original incident clocks", request)
	}
	if accepted.ScopeDigest != plan.ScopeDigest || accepted.RecipeDigest != plan.RecipeDigest || request.SourceID != plan.Input.Snapshot.Request.SourceID || request.SnapshotID != plan.Input.Snapshot.Request.SnapshotID || request.SourceHardUntil != plan.Input.Snapshot.Request.SourceHardUntil {
		t.Fatal("acceptance replaced source/window authority")
	}
	if !registration.AnchorAt.Equal(r.AnchorAt.Add(2300*time.Millisecond)) || !registration.ExpiresAt.Equal(r.ExpiresAt.Add(2300*time.Millisecond)) || !registration.DeleteBy.Equal(r.DeleteBy.Add(2300*time.Millisecond)) {
		t.Fatal("save click reset source-age retention", registration)
	}
	if !plan.Input.Snapshot.Request.T0.Equal(now) || r.WriteUntil != plan.Input.Deadline {
		t.Fatal("caller mutated frozen passive plan")
	}
	if _, _, err = ReanchorRecordingSave(plan, r, now.Add(-time.Microsecond), now.Add(time.Hour)); err == nil {
		t.Fatal("acceptance before original request compilation")
	}
	if _, _, err = ReanchorRecordingSave(plan, r, t0, t0); err == nil {
		t.Fatal("expired authority extended")
	}
	bounded, _, err := ReanchorRecordingSave(plan, r, t0, t0.Add(3*time.Second))
	if err != nil || !bounded.Input.Deadline.Equal(t0.Add(3*time.Second)) {
		t.Fatal("authored timeout overrode earlier authority", err)
	}
}
