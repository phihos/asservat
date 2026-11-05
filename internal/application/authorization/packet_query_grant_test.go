package authorization

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"testing"
	"time"
)

func TestPacketQueryExistingChildCurrentGrantAndWrongOperation(t *testing.T) {
	for _, operation := range []string{value.GrantPacketQueryOperation, value.GrantDownloadOperation} {
		t.Run(operation, func(t *testing.T) {
			f := newGrantFixture(t)
			access := f.access()
			access.Operations = []string{operation}
			access.MaxBytes = 2 * query.ContextResultBytes
			g := f.approve(t, f.request(t, 1, access))
			f.requester.Scopes = []string{"evidence:read", "evidence:raw"}
			_, _, scope := rawPacketProjectionFixture()
			scope.RootID = grantRoot
			scope.CaptureID = g.CaptureID
			scope.ArtifactID = grantID(500)
			scope.ClusterID = f.target.ClusterID
			scope.NamespaceUID = f.target.NamespaceUID
			scope.WorkloadUID = f.target.WorkloadUID
			scope.PodUID = f.target.PodUID
			scope.Principal = f.requester.Principal
			scope.RawGrantID = g.ID
			scope.DisplayVersion = query.PacketQueryDisplayVersion
			scope.PacketQuery, _ = (query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex}, MaxPackets: 2, MaxScanBytes: 1000}).Window()
			record := ContextProjectionEvidence{CaptureID: g.CaptureID, ActionID: "a1", ExecutionDigest: g.ExecutionDigest, Version: artifact.Digest{5}}
			record.Retained.Input.Target = f.target
			f.store.locator[scope.ArtifactID] = g.CaptureID // synthetic independently published locator
			caller := grantIdentity{f.requester, &f.now}
			ref, until, e := f.svc.PacketProjectionGrant(t.Context(), caller, scope, record, true)
			if operation == value.GrantDownloadOperation {
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
			again, _, e := f.svc.PacketProjectionGrant(t.Context(), caller, scope, record, false)
			if e != nil || again != ref {
				t.Fatal("current", e)
			}
			g.RevokedAt = f.now
			g.Revoker = f.approver.Principal
			g.Revision++
			f.store.rows[g.ID] = g
			if _, _, e = f.svc.PacketProjectionGrant(t.Context(), caller, scope, record, false); e == nil {
				t.Fatal("revocation")
			}
			f.now = f.now.Add(time.Second)
		})
	}
}
