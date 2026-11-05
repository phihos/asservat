package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
	"time"
)

type syscallGrantProof struct{ packetGrantProof }

func (p *syscallGrantProof) SyscallProjectionGrant(ctx context.Context, i identities.CurrentIdentity, s query.ContextProjectionScope, r ContextProjectionEvidence, m bool) (query.ContextQueryGrant, time.Time, error) {
	return p.PacketProjectionGrant(ctx, i, s, r, m)
}
func TestRawSyscallAuthorityRequiresExactGrantAndCurrentRawClient(t *testing.T) {
	for _, mode := range []string{"resolve", "current", "missing", "wrong-parent", "raw-scope", "groups-after-block", "no-grant", "no-grant-denied"} {
		t.Run(mode, func(t *testing.T) {
			f, s, scope := newSyscallProjectionFixture(artifact.SyscallArgumentsArtifact, query.SyscallQueryView)
			scope.RawGrantID = projectionTestID(80)
			f.identity.Scopes = append(f.identity.Scopes, "evidence:raw")
			proof := &syscallGrantProof{packetGrantProof{ref: query.ContextQueryGrant{ParentID: scope.RawGrantID, ChildID: projectionTestID(81)}, until: f.now.Add(time.Minute)}}
			s.SyscallGrants = proof
			switch mode {
			case "missing":
				s.SyscallGrants = nil
			case "wrong-parent":
				proof.ref.ParentID = projectionTestID(82)
			case "raw-scope":
				f.identity.Scopes = []string{"evidence:read"}
			case "groups-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.identity.Groups = nil
					}
				}
			case "no-grant", "no-grant-denied":
				scope.RawGrantID = ""
				if mode == "no-grant-denied" {
					f.permission.Denies = f.permission.Allows
				}
			}
			var a query.ContextProjectionAuthority
			var e error
			if mode == "current" {
				a, e = s.CheckProjectionCurrent(t.Context(), f, scope)
			} else {
				a, e = s.ResolveProjectionCurrent(t.Context(), f, scope.Candidate())
			}
			if mode == "resolve" || mode == "current" {
				if e != nil || !a.Valid(f.now) || a.Grant != proof.ref || proof.materializes != map[bool]int{true: 1, false: 0}[mode == "resolve"] {
					t.Fatal("exact raw authority", a, e)
				}
			} else if mode == "no-grant" {
				if _, ok := e.(*syscallQueryApprovalRequired); !ok || a.Valid(f.now) || proof.calls != 0 || f.counts["catalog"] != 1 || len(f.evidence) != 2 {
					t.Fatal("approval remedy skipped current facts", e, f.counts)
				}
			} else {
				if e == nil {
					t.Fatal("unsafe raw authority")
				}
				if _, ok := e.(*syscallQueryApprovalRequired); ok {
					t.Fatal("unauthorized caller got source approval hint")
				}
			}
			if mode == "no-grant" {
				if _, e = s.CheckProjectionCurrent(t.Context(), f, scope); e == nil {
					t.Fatal("pregrant accepted")
				}
			}
		})
	}
}

func TestRawSyscallClientPolicyUsesRawOutputClass(t *testing.T) {
	for _, class := range []string{"raw", "extract"} {
		t.Run(class, func(t *testing.T) {
			f, _, record, actor := newEnvironmentFixture()
			s, _ := NewContextProjectionPolicies(f, func() time.Time { return f.now })
			path := f.policy.Paths[0]
			f.policy.Clients[0].DataClasses = []string{class}
			f.policy.Clients[0].EvidenceTypes = []string{"syscallTrace"}
			policy, e := s.ContextProjectionPolicyFor(t.Context(), path.TargetClusterID, path.StoreID, artifact.SyscallArgumentsArtifact, query.SyscallQueryDisplayVersion)
			if e != nil || policy.Permits(actor, path.TargetClusterID, path.StoreID, record.PurposeRef, f.now) != (class == "raw") {
				t.Fatal("wrong raw syscall client output policy", e)
			}
		})
	}
}
