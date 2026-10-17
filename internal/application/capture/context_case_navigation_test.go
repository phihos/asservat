package capture

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/catalog"
	"context"
	"testing"
	"time"
)

type caseReadFunc func(context.Context, identities.CurrentIdentity, string) (catalog.ContextCase, error)

func (f caseReadFunc) GetContextCase(c context.Context, i identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
	return f(c, i, id)
}
func TestCaseNavigationRequiresExactPublishedCurrentlyVisibleArtifact(t *testing.T) {
	for _, name := range []string{"available", "unpublished", "denied", "wrong-case", "wrong-artifact", "wrong-capture", "wrong-target", "late", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newInvestigationFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := f.source(t, ctx)
			p := capturevalue.ContextProgressObservation{CaptureID: fixtureID(30), CandidateCaseID: fixtureID(31), CandidateArtifactID: fixtureID(32), Target: f.target.Target(), Revision: 4, Phase: "Succeeded", ActionPhase: "Succeeded", ReasonCode: "Published", CreatedAt: f.now.Add(-time.Minute), Deadline: f.now.Add(time.Minute), ObservedAt: f.now, ValidUntil: f.now.Add(time.Second)}
			calls := 0
			s := ContextCaseNavigator{Now: func() time.Time { return f.now }, Cases: caseReadFunc(func(_ context.Context, got identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
				calls++
				if got != source || id != p.CandidateCaseID {
					t.Fatal("case request detached")
				}
				a := catalog.ContextCaseArtifact{ArtifactID: p.CandidateArtifactID, CaptureID: p.CaptureID, Target: p.Target, Version: artifact.Digest{1}, ExpiresAt: f.now.Add(time.Hour), DeleteBy: f.now.Add(2 * time.Hour)}
				c := catalog.ContextCase{CaseID: id, Artifacts: []catalog.ContextCaseArtifact{a}, ObservedAt: f.now, ValidUntil: f.now.Add(2 * time.Second)}
				switch name {
				case "denied":
					return catalog.ContextCase{}, catalog.ErrUnavailable
				case "wrong-case":
					c.CaseID = fixtureID(99)
				case "wrong-artifact":
					c.Artifacts[0].ArtifactID = fixtureID(99)
				case "wrong-capture":
					c.Artifacts[0].CaptureID = fixtureID(99)
				case "wrong-target":
					c.Artifacts[0].Target.PodUID = "other"
				case "late":
					f.now = f.now.Add(time.Second)
				case "cancelled":
					cancel()
				}
				return c, nil
			})}
			if name == "unpublished" {
				p.Phase = "Finalizing"
				p.ActionPhase = "Finalizing"
				p.ReasonCode = "PublicationPending"
			}
			got, err := s.ContextCaseNavigation(ctx, source, p)
			if name == "available" {
				if err != nil || got.CaseID != p.CandidateCaseID || !got.ValidUntil.Equal(p.ValidUntil) {
					t.Fatal("authorized navigation", got, err)
				}
			} else if err == nil || got.CaseID != "" {
				t.Fatal("unproven navigation", got, err)
			}
			if name == "unpublished" && calls != 0 {
				t.Fatal("unpublished metadata lookup")
			}
		})
	}
}
