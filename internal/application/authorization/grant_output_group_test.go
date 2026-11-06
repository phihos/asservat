package authorization

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"errors"
	"testing"
)

type groupGrantStore struct {
	*memoryGrants
	output value.VerifiedOutput
	group  value.GrantOutputGroup
	reads  int
	deny   bool
}

func (s *groupGrantStore) ResolveGrantedOutput(ctx context.Context, parent string, scope artifact.DownloadScope, action string) (value.VerifiedOutput, *value.GrantOutputGroup, error) {
	s.reads++
	if ctx.Err() != nil || s.deny || parent != s.rows[parent].ID || scope.RootID != s.group.RootID || scope.CaptureID != s.output.CaptureID || scope.ArtifactID != s.output.ArtifactID || scope.Version != s.output.ArtifactDigest || action != "" && action != s.output.ActionID {
		return value.VerifiedOutput{}, nil, value.ErrGrantScope
	}
	copy := s.group
	return s.output, &copy, nil
}
func TestLogGroupReusesExactInitialParentWithoutNewReviewOrPool(t *testing.T) {
	f := newGrantFixture(t)
	access := f.access()
	access.Operations = []string{value.GrantDownloadOperation, value.GrantLogQueryOperation}
	access.MaxBytes = 2 * query.ContextResultBytes
	access.MaxOperations = 2
	g := f.approve(t, f.request(t, 1, access))
	f.requester.Scopes = []string{"evidence:read", "evidence:raw", "evidence:download"}
	_, _, scope := newLogProjectionFixture()
	scope.RootID = grantRoot
	scope.CaptureID = grantID(600)
	scope.ArtifactID = grantID(601)
	scope.ClusterID = f.target.ClusterID
	scope.NamespaceUID = f.target.NamespaceUID
	scope.WorkloadUID = f.target.WorkloadUID
	scope.PodUID = f.target.PodUID
	scope.Principal = f.requester.Principal
	scope.RawGrantID = g.ID
	record := ContextProjectionEvidence{CaptureID: scope.CaptureID, ActionID: "a1", ExecutionDigest: artifact.Digest{91}, Version: scope.Version}
	record.Retained.Input.Target = f.target
	out := value.VerifiedOutput{CaptureID: scope.CaptureID, ArtifactID: scope.ArtifactID, ActionID: record.ActionID, ExecutionDigest: record.ExecutionDigest, ArtifactDigest: scope.Version, Target: f.target}
	store := &groupGrantStore{memoryGrants: f.store, output: out, group: value.GrantOutputGroup{RootID: g.RootID, ParentCaptureID: g.CaptureID, ParentExecutionDigest: g.ExecutionDigest, CaptureID: out.CaptureID, ExecutionDigest: out.ExecutionDigest, ArtifactID: out.ArtifactID, ArtifactDigest: out.ArtifactDigest, ActionID: out.ActionID, ChildIndex: 0, ChildCount: 2}}
	f.svc.Store = store
	f.store.locator[out.ArtifactID] = out.CaptureID
	who := grantIdentity{f.requester, &f.now}
	ref, _, err := f.svc.LogProjectionGrant(t.Context(), who, scope, record, true)
	if err != nil || ref.ParentID != g.ID || len(f.store.rows) != 1 || len(f.store.children) != 1 || store.reads != 1 {
		t.Fatal("exact initial parent", ref, err, store.reads)
	}
	// Current checks consume the joined existing child; no repeated association read.
	if again, _, e := f.svc.LogProjectionGrant(t.Context(), who, scope, record, false); e != nil || again != ref || store.reads != 1 {
		t.Fatal("current group child", again, e, store.reads)
	}
	child, _ := f.store.GrantChild(t.Context(), ref.ChildID)
	if child.Output != out || child.Group == nil || child.Output.CaptureID == g.CaptureID {
		t.Fatal("child relabeled")
	}
	use := value.GrantUse{Operation: value.GrantLogQueryOperation, Bytes: query.ContextResultBytes, Operations: 1}
	if _, _, err = f.svc.Use(t.Context(), who, ref.ChildID, grantID(602), use); err != nil {
		t.Fatal(err)
	}
	if _, replay, e := f.svc.Use(t.Context(), who, ref.ChildID, grantID(602), use); e != nil || !replay {
		t.Fatal("use replay", e)
	}
	if _, _, e := f.svc.Use(t.Context(), who, ref.ChildID, grantID(603), use); e != nil {
		t.Fatal(e)
	}
	if _, _, e := f.svc.Use(t.Context(), who, ref.ChildID, grantID(604), use); !errors.Is(e, value.ErrGrantPoolExhausted) {
		t.Fatal("shared pool refilled", e)
	}
	if f.store.rows[g.ID].Spent.Artifacts != 1 || f.store.rows[g.ID].Spent.Bytes != 2*query.ContextResultBytes || f.store.rows[g.ID].Spent.Operations != 2 {
		t.Fatal("wrong original pool accounting")
	}
}
