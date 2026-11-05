package authorization

import (
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"testing"
	"time"
)

func rawPacketProjectionFixture() (*projectionFixture, ContextProjectionAuthority, analysis.ContextProjectionScope) {
	f, s, scope := newPacketProjectionFixture()
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, analysis.RawPacketSummaryDisplayVersion
	f.record.NativeType, f.record.SourceFormat, f.record.DataClass = scope.NativeType, scope.SourceFormat, "raw"
	return f, s, scope
}
func TestRawPacketSummaryAuthorityRetainsRawSourceAndNeverUsesShares(t *testing.T) {
	for _, mode := range []string{"current", "resolve", "permissions", "deny", "permissions-after-block", "audience", "client", "client-after-block", "groups-after-block", "retention-after-block", "cancel-after-block", "expired-after-block", "wrong-kind", "metadata-class", "source-version", "metadata-display", "native-limit"} {
		t.Run(mode, func(t *testing.T) {
			f, s, scope := rawPacketProjectionFixture()
			shares := &projectionShares{now: func() time.Time { return f.now }}
			s.Shares = shares
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "permissions":
				f.permission.Allows = nil
			case "deny":
				f.permission.Denies = append(f.permission.Denies, f.permission.Allows[0])
			case "permissions-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.permission.Allows = nil
					}
				}
			case "audience":
				f.record.Audience[0].AssignmentID = projectionTestID(90)
			case "client":
				f.identity.Principal.ClientID = "other-client"
			case "client-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.identity.Principal.ClientID = "other-client"
					}
				}
			case "groups-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.identity.Groups = nil
					}
				}
			case "retention-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.retention.ExpiresAt = f.now
					}
				}
			case "cancel-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						cancel()
					}
				}
			case "expired-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.now = f.now.Add(6 * time.Second)
					}
				}
			case "wrong-kind":
				f.record.NativeType = artifact.PCAPNGArtifact
			case "metadata-class":
				f.record.DataClass = "metadata"
			case "source-version":
				f.record.Version[0]++
			case "metadata-display":
				scope.DisplayVersion = analysis.PacketSummaryDisplayVersion
			case "native-limit":
				f.record.Retained.Registration.NativeLimit++
			}
			var out analysis.ContextProjectionAuthority
			var err error
			if mode == "resolve" {
				out, err = s.ResolveProjectionCurrent(ctx, f, scope.Candidate())
			} else {
				out, err = s.CheckProjectionCurrent(ctx, f, scope)
			}
			if mode == "current" || mode == "resolve" {
				if err != nil || !out.Valid(f.now) || out.Scope != scope || len(f.evidence) != 2 || f.evidence[0].DataClass != "raw" || f.evidence[0].NativeType != artifact.RawPCAPNGArtifact || !out.ValidUntil.Equal(f.record.ValidUntil) {
					t.Fatal("ordinary aggregate lost exact raw provenance/bounds", err)
				}
				retained := value.Retained{ArtifactID: scope.ArtifactID, Target: f.permission.Target, DataClass: "raw", NativeType: artifact.RawPCAPNGArtifact, ExpiresAt: f.record.Retained.Effective.ExpiresAt, Audience: f.record.Audience}
				if value.Evaluate(f.identity, f.permission, value.ReadApproved, f.permission.Target, &retained, f.now).Eligible || value.Evaluate(f.identity, f.permission, value.DownloadApproved, f.permission.Target, &retained, f.now).Eligible {
					t.Fatal("aggregate widened generic raw authority")
				}
			} else if err == nil {
				t.Fatal("changed raw authority admitted", mode)
			}
			if shares.reads != 0 {
				t.Fatal("raw aggregate consulted metadata shares")
			}
			if (mode == "permissions" || mode == "deny" || mode == "client") && f.counts["catalog"] != 0 {
				t.Fatal("catalog read preceded ordinary identity/target rights")
			}
		})
	}
}

func TestRawPacketSummaryPolicyRequiresExtractPacketClient(t *testing.T) {
	for _, mode := range []string{"extract-packet", "raw-packet", "metadata-packet", "extract-profile", "wrong-client"} {
		t.Run(mode, func(t *testing.T) {
			f, _, record, actor := newEnvironmentFixture()
			service, _ := NewContextProjectionPolicies(f, func() time.Time { return f.now })
			path := f.policy.Paths[0]
			f.policy.Clients[0].DataClasses, f.policy.Clients[0].EvidenceTypes = []string{"extract"}, []string{"packetCapture"}
			switch mode {
			case "raw-packet":
				f.policy.Clients[0].DataClasses = []string{"raw"}
			case "metadata-packet":
				f.policy.Clients[0].DataClasses = []string{"metadata"}
			case "extract-profile":
				f.policy.Clients[0].EvidenceTypes = []string{"profile"}
			case "wrong-client":
				f.policy.Clients[0].ID = "other-client"
			}
			policy, err := service.ContextProjectionPolicy(t.Context(), path.TargetClusterID, path.StoreID, artifact.RawPCAPNGArtifact)
			if err != nil || policy.Permits(actor, path.TargetClusterID, path.StoreID, record.PurposeRef, f.now) != (mode == "extract-packet") {
				t.Fatal("raw input ignored approved output/client allowlist", mode, err)
			}
		})
	}
}
