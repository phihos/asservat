package authorization

import (
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
	"time"
)

func newPacketProjectionFixture() (*projectionFixture, ContextProjectionAuthority, analysis.ContextProjectionScope) {
	f, s, scope := newProjectionFixture()
	scope.NativeType = artifact.PCAPNGArtifact
	scope.SourceFormat = artifact.PCAPNGFormat
	scope.DisplayVersion = analysis.PacketSummaryDisplayVersion
	scope.SourceProjectionDigest = artifact.Digest{}
	scope.Selection = analysis.LineSelection{}
	f.record.NativeType = artifact.PCAPNGArtifact
	f.record.SourceFormat = artifact.PCAPNGFormat
	f.record.SourceProjectionDigest = artifact.Digest{}
	f.record.DataClass = "metadata"
	f.record.Retained.Input.EvidenceType = "packetCapture"
	f.record.Retained.Registration.NativeLimit = artifact.RecordingNativeLimit
	return f, s, scope
}
func TestPacketSummaryAuthorityKeepsOrdinaryAudienceAndCurrentGuards(t *testing.T) {
	for _, mode := range []string{"current", "raw", "too-large", "zero-size", "other-version", "audience", "permissions", "cancel-after-block", "expiry-after-block"} {
		t.Run(mode, func(t *testing.T) {
			f, s, scope := newPacketProjectionFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "raw":
				f.record.NativeType = artifact.RawPCAPNGArtifact
				f.record.DataClass = "raw"
			case "too-large":
				f.record.Retained.Registration.NativeLimit++
			case "zero-size":
				f.record.Retained.Registration.NativeLimit = 0
			case "other-version":
				f.record.Version[0]++
			case "audience":
				f.record.Audience[0].AssignmentID = projectionTestID(99)
			case "permissions":
				f.permission.Allows = nil
			case "cancel-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						cancel()
					}
				}
			case "expiry-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.now = f.now.Add(6 * time.Second)
					}
				}
			}
			out, err := s.CheckProjectionCurrent(ctx, f, scope)
			if mode == "current" {
				if err != nil || !out.Valid(f.now) || out.Scope != scope {
					t.Fatal("metadata packet denied ordinary retained reader", err)
				}
				if !out.ValidUntil.Equal(f.record.ValidUntil) {
					t.Fatal("source authority interval changed")
				}
			} else if err == nil {
				t.Fatal("changed packet source/current authority accepted", mode)
			}
			if mode == "permissions" && f.counts["catalog"] != 0 {
				t.Fatal("protected catalog preceded ordinary rights")
			}
		})
	}
}
