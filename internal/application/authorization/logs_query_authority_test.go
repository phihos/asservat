package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
	"time"
)

type logGrantProof struct{ packetGrantProof }

func (p *logGrantProof) LogProjectionGrant(ctx context.Context, i identities.CurrentIdentity, s query.ContextProjectionScope, r ContextProjectionEvidence, m bool) (query.ContextQueryGrant, time.Time, error) {
	return p.PacketProjectionGrant(ctx, i, s, r, m)
}
func TestRawLogAuthorityRequiresExactGrantAndCurrentRawClient(t *testing.T) {
	for _, mode := range []string{"resolve", "current", "missing", "wrong-parent", "raw-scope", "groups-after-block", "no-grant", "no-grant-denied"} {
		t.Run(mode, func(t *testing.T) {
			f, s, scope := newLogProjectionFixture()
			scope.RawGrantID = projectionTestID(80)
			f.identity.Scopes = append(f.identity.Scopes, "evidence:raw")
			proof := &logGrantProof{packetGrantProof{ref: query.ContextQueryGrant{ParentID: scope.RawGrantID, ChildID: projectionTestID(81)}, until: f.now.Add(time.Minute)}}
			s.LogGrants = proof
			switch mode {
			case "missing":
				s.LogGrants = nil
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
					t.Fatalf("exact raw authority: %v calls=%v", e, f.calls)
				}
			} else if mode == "no-grant" {
				if _, ok := e.(*logQueryApprovalRequired); !ok || a.Valid(f.now) || proof.calls != 0 || f.counts["catalog"] != 1 || len(f.evidence) != 2 {
					t.Fatal("approval remedy skipped current facts", e, f.counts)
				}
			} else {
				if e == nil {
					t.Fatal("unsafe raw authority")
				}
				if _, ok := e.(*logQueryApprovalRequired); ok {
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

func newLogProjectionFixture() (*projectionFixture, ContextProjectionAuthority, query.ContextProjectionScope) {
	f, s, scope := newProjectionFixture()
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.LogsArtifact, artifact.LogFormat, query.LogQueryDisplayVersion
	scope.SourceProjectionDigest, scope.Selection = artifact.Digest{}, query.LineSelection{}
	scope.Logs = query.LogWindow{Limit: 100}
	f.record.NativeType, f.record.SourceFormat, f.record.SourceProjectionDigest = artifact.LogsArtifact, artifact.LogFormat, artifact.Digest{}
	f.record.DataClass, f.record.Retained.Input.EvidenceType = "raw", "logs"
	f.record.Retained.Registration.NativeLimit = artifact.LogNativeLimit
	return f, s, scope
}
