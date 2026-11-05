package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"testing"
	"time"
)

func TestRawSyscallExistingChildCurrentGrantAndWrongOperation(t *testing.T) {
	for _, operation := range []string{value.GrantSyscallQueryOperation, value.GrantDownloadOperation, value.GrantPacketQueryOperation} {
		t.Run(operation, func(t *testing.T) {
			f := newGrantFixture(t)
			access := f.access()
			access.Operations = []string{operation}
			access.MaxBytes = 2 * query.ContextResultBytes
			g := f.approve(t, f.request(t, 1, access))
			f.requester.Scopes = []string{"evidence:read", "evidence:raw"}
			_, _, scope := newSyscallProjectionFixture(artifact.SyscallArgumentsArtifact, query.SyscallQueryView)
			scope.RootID = grantRoot
			scope.CaptureID = g.CaptureID
			scope.ArtifactID = grantID(500)
			scope.ClusterID = f.target.ClusterID
			scope.NamespaceUID = f.target.NamespaceUID
			scope.WorkloadUID = f.target.WorkloadUID
			scope.PodUID = f.target.PodUID
			scope.Principal = f.requester.Principal
			scope.RawGrantID = g.ID
			scope.DisplayVersion = query.SyscallQueryDisplayVersion

			record := ContextProjectionEvidence{CaptureID: g.CaptureID, ActionID: "a1", ExecutionDigest: g.ExecutionDigest, Version: artifact.Digest{5}}
			record.Retained.Input.Target = f.target
			f.store.locator[scope.ArtifactID] = g.CaptureID // synthetic independently published locator
			caller := grantIdentity{f.requester, &f.now}
			ref, until, e := f.svc.SyscallProjectionGrant(t.Context(), caller, scope, record, true)
			if operation != value.GrantSyscallQueryOperation {
				if e == nil {
					t.Fatal("downloadcoversquery")
				}
				return
			}
			if e != nil || !ref.Valid() || ref.ParentID != g.ID || !until.Equal(g.ExpiresAt) {
				t.Fatal("materialize", e)
			}
			prior, eChild := f.store.GrantChildFor(t.Context(), g.ID, scope.ArtifactID, f.requester.Principal.ClientID)
			if eChild != nil || prior.ID != ref.ChildID {
				t.Fatal("child", eChild)
			}
			again, _, e := f.svc.SyscallProjectionGrant(t.Context(), caller, scope, record, false)
			if e != nil || again != ref {
				t.Fatal("current", e)
			}
			g.RevokedAt = f.now
			g.Revoker = f.approver.Principal
			g.Revision++
			f.store.rows[g.ID] = g
			if _, _, e = f.svc.SyscallProjectionGrant(t.Context(), caller, scope, record, false); e == nil {
				t.Fatal("revocation")
			}
			f.now = f.now.Add(time.Second)
		})
	}
}

// The standalone grant request must select the syscall artifact through its
// ordinary/raw facet, with no download or packet-facet substitute.
type rawSyscallGrantSelection struct {
	RawQuerySelectionReader
	calls int
}

func (r *rawSyscallGrantSelection) ResolveRawSyscallQuery(ctx context.Context, current identities.CurrentIdentity, caseID string, digests []artifact.Digest) (RawQuerySelection, error) {
	r.calls++
	return r.ResolveRawQuery(ctx, current, caseID, digests)
}
func TestRawSyscallStandaloneReviewUsesExactSelectorAndReusesCoveringPool(t *testing.T) {
	f, in, _ := rawQueryFixture(t)
	selector := &rawSyscallGrantSelection{RawQuerySelectionReader: f.svc.RawSelections}
	f.svc.RawSelections = selector
	in.Operations = []string{value.GrantSyscallQueryOperation}
	in.MaxBytes = 2 * query.ContextResultBytes
	f.requester.Scopes = []string{"evidence:read", "evidence:raw"}
	pending := requestRawFixture(t, f, in)
	if selector.calls != 1 || pending.RawQuery.Operations[0] != value.GrantSyscallQueryOperation {
		t.Fatal("wrong review selection")
	}
	approved := f.approve(t, pending)
	in.IdempotencyKey = "covering-again"
	reused, prior, e := f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, in)
	if e != nil || !prior || reused.ID != approved.ID || selector.calls != 2 {
		t.Fatal("covering pool not reused", e, prior)
	}
	in.IdempotencyKey = "wrong-operation"
	in.Operations = []string{value.GrantPacketQueryOperation, value.GrantSyscallQueryOperation}
	if _, _, e = f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, in); e == nil {
		t.Fatal("one syscall source covered incompatible packet operation")
	}
}

func TestRawSyscallCombinedDownloadReviewNeedsBothClientScopes(t *testing.T) {
	for _, mode := range []string{"both", "missing-raw", "missing-download"} {
		t.Run(mode, func(t *testing.T) {
			f, in, _ := rawQueryFixture(t)
			selector := &rawSyscallGrantSelection{RawQuerySelectionReader: f.svc.RawSelections}
			f.svc.RawSelections = selector
			in.Operations = []string{value.GrantDownloadOperation, value.GrantSyscallQueryOperation}
			f.requester.Scopes = []string{"evidence:read", "evidence:raw", "evidence:download"}
			if mode == "missing-raw" {
				f.requester.Scopes = []string{"evidence:read", "evidence:download"}
			}
			if mode == "missing-download" {
				f.requester.Scopes = []string{"evidence:read", "evidence:raw"}
			}
			_, _, e := f.svc.RequestRaw(t.Context(), grantIdentity{f.requester, &f.now}, in)
			if mode == "both" {
				if e != nil || selector.calls != 1 {
					t.Fatal("valid combined review", e)
				}
			} else if e == nil || selector.calls != 0 {
				t.Fatal("incomplete client scope reached selection", e)
			}
		})
	}
}
