package capture

import (
	"context"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/catalog"
)

func TestGroupCaseNavigationKeepsPublishedSiblingVisible(t *testing.T) {
	for _, name := range []string{"published-with-pending", "not-published", "wrong-member", "wrong-pod", "denied"} {
		t.Run(name, func(t *testing.T) {
			f := newInvestigationFixture()
			target := f.target.Target()
			workload := target
			workload.PodUID = ""
			p := value.ContextProgressObservation{CaptureID: fixtureID(70), CandidateCaseID: fixtureID(71), Target: workload, Operation: "recordingSave", Revision: 3, Phase: "Pending", ReasonCode: "GroupPending", CreatedAt: f.now.Add(-time.Minute), Deadline: f.now.Add(time.Minute), ObservedAt: f.now, ValidUntil: f.now.Add(time.Second), Actions: []value.ContextActionProgress{
				{InstanceID: fixtureID(72), PodUID: target.PodUID, PodName: "api-one", ActionID: "traffic", Phase: "Succeeded", ReasonCode: "Published"},
				{InstanceID: fixtureID(73), PodUID: "other-pod", PodName: "api-two", ActionID: "traffic", Phase: "Pending", ReasonCode: "DispatchUnconfirmed"},
			}}
			if name == "not-published" {
				p.Actions[0].Phase, p.Actions[0].ReasonCode = "Finalizing", "PublicationPending"
			}
			calls := 0
			s := ContextCaseNavigator{Now: func() time.Time { return f.now }, Cases: caseReadFunc(func(context.Context, identities.CurrentIdentity, string) (catalog.ContextCase, error) {
				calls++
				if name == "denied" {
					return catalog.ContextCase{}, catalog.ErrUnavailable
				}
				a := catalog.ContextCaseArtifact{ArtifactID: fixtureID(74), CaptureID: p.Actions[0].InstanceID, Target: target, Version: artifact.Digest{1}, ExpiresAt: f.now.Add(time.Hour), DeleteBy: f.now.Add(2 * time.Hour)}
				if name == "wrong-member" {
					a.CaptureID = fixtureID(99)
				} else if name == "wrong-pod" {
					a.Target.PodUID = "unselected-pod"
				}
				return catalog.ContextCase{CaseID: p.CandidateCaseID, Artifacts: []catalog.ContextCaseArtifact{a}, ObservedAt: f.now, ValidUntil: f.now.Add(2 * time.Second)}, nil
			})}
			got, err := s.ContextCaseNavigation(t.Context(), f.source(t, t.Context()), p)
			if name == "published-with-pending" {
				if err != nil || got.CaseID != p.CandidateCaseID {
					t.Fatal("waiting sibling hid authorized published output", got, err)
				}
			} else if err == nil || got.CaseID != "" {
				t.Fatal("unproven group navigation", got, err)
			}
			if name == "not-published" && calls != 0 {
				t.Fatal("group without published output queried the catalog")
			}
		})
	}
}
