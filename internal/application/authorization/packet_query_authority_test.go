package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
	"time"
)

type packetGrantProof struct {
	ref                 query.ContextQueryGrant
	calls, materializes int
	err                 error
	until               time.Time
}

func (p *packetGrantProof) PacketProjectionGrant(_ context.Context, _ identities.CurrentIdentity, _ query.ContextProjectionScope, _ ContextProjectionEvidence, materialize bool) (query.ContextQueryGrant, time.Time, error) {
	p.calls++
	if materialize {
		p.materializes++
	}
	return p.ref, p.until, p.err
}
func TestPacketQueryAuthorityKeepsRawGrantSeparateFromSummary(t *testing.T) {
	for _, mode := range []string{"resolve", "current", "missing", "wrong-parent", "raw-scope", "groups-after-block"} {
		t.Run(mode, func(t *testing.T) {
			f, s, scope := rawPacketProjectionFixture()
			scope.DisplayVersion = query.PacketQueryDisplayVersion
			scope.RawGrantID = projectionTestID(80)
			scope.PacketQuery, _ = (query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex}, MaxPackets: 10, MaxScanBytes: 100}).Window()
			f.identity.Scopes = append(f.identity.Scopes, "evidence:raw")
			proof := &packetGrantProof{ref: query.ContextQueryGrant{ParentID: scope.RawGrantID, ChildID: projectionTestID(81)}, until: f.now.Add(time.Minute)}
			s.PacketGrants = proof
			switch mode {
			case "missing":
				s.PacketGrants = nil
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
			}
			var a query.ContextProjectionAuthority
			var e error
			if mode == "resolve" {
				a, e = s.ResolveProjectionCurrent(t.Context(), f, scope.Candidate())
			} else {
				a, e = s.CheckProjectionCurrent(t.Context(), f, scope)
			}
			if mode == "resolve" || mode == "current" {
				if e != nil || a.Grant != proof.ref || !a.Valid(f.now) || proof.materializes != map[bool]int{true: 1, false: 0}[mode == "resolve"] {
					t.Fatal(mode, e)
				}
			} else if e == nil {
				t.Fatal("rawquerygrantbypass", mode)
			}
			if f.record.NativeType != artifact.RawPCAPNGArtifact {
				t.Fatal("sourcechanged")
			}
		})
	}
}

func TestPacketQueryClientPolicyFollowsQueryOutputInsteadOfSummary(t *testing.T) {
	for _, native := range []string{artifact.RawPCAPNGArtifact, artifact.PCAPNGArtifact} {
		for _, class := range []string{"raw", "extract"} {
			t.Run(native+"/"+class, func(t *testing.T) {
				f, _, record, actor := newEnvironmentFixture()
				s, _ := NewContextProjectionPolicies(f, func() time.Time { return f.now })
				path := f.policy.Paths[0]
				f.policy.Clients[0].DataClasses = []string{class}
				f.policy.Clients[0].EvidenceTypes = []string{"packetCapture"}
				policy, e := s.ContextProjectionPolicyFor(t.Context(), path.TargetClusterID, path.StoreID, native, query.PacketQueryDisplayVersion)
				want := native == artifact.RawPCAPNGArtifact && class == "raw" || native == artifact.PCAPNGArtifact && class == "extract"
				if e != nil || policy.Permits(actor, path.TargetClusterID, path.StoreID, record.PurposeRef, f.now) != want {
					t.Fatal("wrongqueryoutputclass", e)
				}
			})
		}
	}
}

func TestPacketQueryMissingApprovalRequiresCompleteCurrentSourceChecks(t *testing.T) {
	for _, mode := range []string{"eligible", "denied", "scope", "audience", "groups-after-block"} {
		t.Run(mode, func(t *testing.T) {
			f, s, scope := rawPacketProjectionFixture()
			scope.DisplayVersion = query.PacketQueryDisplayVersion
			scope.PacketQuery, _ = (query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex}, MaxPackets: 1, MaxScanBytes: 100}).Window()
			scope.RawGrantID = ""
			f.identity.Scopes = append(f.identity.Scopes, "evidence:raw")
			proof := &packetGrantProof{until: f.now.Add(time.Minute)}
			s.PacketGrants = proof
			switch mode {
			case "denied":
				f.permission.Denies = append(f.permission.Denies, f.permission.Allows[0])
			case "scope":
				f.identity.Scopes = []string{"evidence:read"}
			case "audience":
				f.record.Audience = nil
			case "groups-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.identity.Groups = nil
					}
				}
			}
			a, e := s.ResolveProjectionCurrent(t.Context(), f, scope.Candidate())
			_, approval := e.(*packetQueryApprovalRequired)
			if mode == "eligible" {
				if !approval || a.Valid(f.now) || f.counts["catalog"] != 1 || len(f.evidence) != 2 {
					t.Fatal("missingapprovalbeforecompletecurrentchecks", e, f.counts)
				}
			} else if e == nil || approval {
				t.Fatal("ineligiblegotapprovalhint", mode, e)
			}
			if proof.calls != 0 || proof.materializes != 0 {
				t.Fatal("missingapprovalmaterialized")
			}
			if _, e = s.CheckProjectionCurrent(t.Context(), f, scope); e == nil {
				t.Fatal("pregrantscopebecameaccepted")
			}
		})
	}
}
