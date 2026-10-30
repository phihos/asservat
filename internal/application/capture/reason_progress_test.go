package capture

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

type progressReasonFunc func(context.Context, value.CaptureReasonMetadata) (string, error)

func (f progressReasonFunc) ReadCaptureReason(ctx context.Context, m value.CaptureReasonMetadata) (string, error) {
	return f(ctx, m)
}
func TestReasonDisplayUsesExistingFinalMetadataAuthority(t *testing.T) {
	for _, mode := range []string{"available", "unavailable", "expired-after-open", "changed-after-open", "denied-before-open"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationFixture()
			ctx := context.Background()
			calls := 0
			metadata := &value.CaptureReasonMetadata{RootID: fixtureID(1), CaptureID: fixtureID(30), AuditCaptureID: fixtureID(30), Reference: value.ProtectedReasonRef{ID: fixtureID(44), CiphertextDigest: artifact.Digest{3}}, Requester: f.actor, ScopeDigest: artifact.Digest{4}}
			p := value.ContextProgressObservation{ReasonMetadata: metadata, CaptureID: fixtureID(30), CandidateCaseID: fixtureID(31), CandidateArtifactID: fixtureID(32), Target: f.target.Target(), Revision: 4, Phase: "Pending", ActionPhase: "Pending", ReasonCode: "DispatchUnconfirmed", CreatedAt: f.now.Add(-time.Minute), Deadline: f.now.Add(time.Minute), ObservedAt: f.now, ValidUntil: f.now.Add(2 * time.Second)}
			s := ContextProgressService{RootID: fixtureID(1), InstallationID: fixtureID(2), Recovery: f, Now: func() time.Time { return f.now }}
			s.Reader = progressReadFunc(func(context.Context, value.ProgressQuery) (value.ContextProgressObservation, error) {
				if mode == "denied-before-open" {
					return value.ContextProgressObservation{}, value.ErrDenied
				}
				return p, nil
			})
			text := "  investigate user data\n"
			s.Reasons = progressReasonFunc(func(_ context.Context, m value.CaptureReasonMetadata) (string, error) {
				calls++
				if m != *metadata {
					t.Fatal("original capture binding changed")
				}
				switch mode {
				case "unavailable":
					return "", value.ErrUnavailable
				case "expired-after-open":
					f.now = f.now.Add(2 * time.Second)
				case "changed-after-open":
					f.identityChange = "groups"
				}
				return text, nil
			})
			got, err := s.Get(ctx, f.source(t, ctx), p.CaptureID)
			switch mode {
			case "available":
				if err != nil || got.Reason == nil || *got.Reason != text || got.ReasonState != "available" || calls != 1 {
					t.Fatal("authorized descriptive text lost", err)
				}
			case "unavailable":
				if err != nil || got.Reason != nil || got.ReasonState != "unavailable" || got.Phase != "Pending" {
					t.Fatal("reason outage became collection-status authority", err)
				}
			case "denied-before-open":
				if err == nil || calls != 0 {
					t.Fatal("opened reason before current capture rights")
				}
			default:
				if err == nil {
					t.Fatal("blocking reason read extended metadata identity/proof deadline")
				}
			}
		})
	}
}
