package capture

import (
	"context"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
)

// The stored reason is shown only after the existing progress authorization.
func TestReasonDisplayFollowsProgressAuthority(t *testing.T) {
	for _, mode := range []string{"available", "denied"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationFixture()
			ctx := context.Background()
			text := "  investigate user data\n"
			p := value.ContextProgressObservation{Reason: &text, CaptureID: fixtureID(30), CandidateCaseID: fixtureID(31), CandidateArtifactID: fixtureID(32), Target: f.target.Target(), Revision: 4, Phase: "Pending", ActionPhase: "Pending", ReasonCode: "DispatchUnconfirmed", CreatedAt: f.now.Add(-time.Minute), Deadline: f.now.Add(time.Minute), ObservedAt: f.now, ValidUntil: f.now.Add(2 * time.Second)}
			s := ContextProgressService{RootID: fixtureID(1), InstallationID: fixtureID(2), Now: func() time.Time { return f.now }}
			s.Reader = progressReadFunc(func(context.Context, value.ProgressQuery) (value.ContextProgressObservation, error) {
				if mode == "denied" {
					return value.ContextProgressObservation{}, value.ErrDenied
				}
				return p, nil
			})
			got, err := s.Get(ctx, f.source(t, ctx), p.CaptureID)
			if mode == "denied" {
				if err == nil || got.Reason != nil {
					t.Fatal("reason shown without current capture rights")
				}
				return
			}
			if err != nil || got.Reason == nil || *got.Reason != text || got.ReasonState != "available" {
				t.Fatal("stored reason lost", err)
			}
		})
	}
}
