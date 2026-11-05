package authorization

import (
	"context"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

func TestTargetDiscoveryRequiresCurrentMaintainerAndOriginalAudience(t *testing.T) {
	for _, mode := range []string{"current", "reader-only", "original-reader-only", "deny-reader", "wrong-native", "after-blocking-revocation"} {
		t.Run(mode, func(t *testing.T) {
			f, s, scope := newProjectionFixture()
			shares := &projectionShares{now: func() time.Time { return f.now }}
			s.Shares = shares
			scope.NativeType = artifact.ProcessesArtifact
			scope.SourceProjectionDigest = artifact.Digest{}
			scope.SourceFormat = artifact.ProcessFormat
			scope.DisplayVersion = query.TargetDiscoveryDisplayVersion
			scope.Selection = query.LineSelection{}
			scope.Discovery = query.TargetDiscoveryWindow{Section: "processes", Limit: 20}
			f.record.NativeType = artifact.ProcessesArtifact
			f.record.SourceProjectionDigest = artifact.Digest{}
			f.record.SourceFormat = scope.SourceFormat
			f.record.Retained.Registration.NativeLimit = artifact.ProcessNativeLimit
			f.record.Retained.Input.EvidenceType = "processSnapshot"
			f.permission.Allows[0].Audience.Role = "workload-maintainer"
			f.record.Audience[0].Role = "workload-maintainer"
			switch mode {
			case "reader-only":
				f.permission.Allows[0].Audience.Role = "evidence-reader"
			case "original-reader-only":
				f.record.Audience[0].Role = "evidence-reader"
			case "deny-reader":
				d := f.permission.Allows[0]
				d.Audience.Role = "evidence-reader"
				f.permission.Denies = []value.CurrentAssignment{d}
			case "wrong-native":
				f.record.NativeType = artifact.PodStatusArtifact
			case "after-blocking-revocation":
				f.on = func(_ context.Context, stage string, n int) {
					if stage == "catalog" {
						f.permission.Allows = nil
					}
				}
			}
			out, err := s.CheckProjectionCurrent(context.Background(), f, scope)
			if mode == "current" {
				if err != nil || !out.Valid(f.now) || out.Scope != scope {
					t.Fatalf("current maintainer refused: %v calls=%v recordValid=%t scopeValid=%t detail=%+v", err, f.calls, f.record.Retained.Valid(), scope.Valid(), err)
				}
			} else if err == nil {
				t.Fatal("ineligible source/audience accepted")
			}
			if (mode == "reader-only" || mode == "deny-reader") && f.counts["catalog"] != 0 {
				t.Fatal("source looked up before current rights")
			}
			if shares.reads != 0 {
				t.Fatal("process discovery attempted share fallback")
			}
			if len(f.identity.Scopes) != 1 || f.identity.Scopes[0] != "evidence:read" {
				t.Fatal("discovery invented capture/download scope")
			}
		})
	}
}
