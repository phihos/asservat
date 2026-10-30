package capture

import (
	"context"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

// The consumer owns this port; C-09 does not import the C-16 implementation or
// turn historical collection status into evidence-disclosure authority.
type ContextCaseReader interface {
	GetContextCase(context.Context, identities.CurrentIdentity, string) (catalog.ContextCase, error)
}
type ContextCaseNavigator struct {
	Cases ContextCaseReader
	Now   func() time.Time
}

func (s ContextCaseNavigator) ContextCaseNavigation(ctx context.Context, source identities.CurrentIdentity, p capture.ContextProgressObservation) (ContextCaseLink, error) {
	var zero ContextCaseLink
	if ctx == nil || ctx.Err() != nil || s.Cases == nil || s.Now == nil || source == nil || !p.Valid(s.Now()) || len(p.Actions) == 0 && (p.Phase != "Succeeded" || p.ReasonCode != "Published") {
		return zero, catalog.ErrUnavailable
	}
	if len(p.Actions) != 0 {
		published := false
		for _, child := range p.Actions {
			published = published || child.Phase == "Succeeded" || child.Phase == "Partial"
		}
		if !published {
			return zero, catalog.ErrUnavailable
		}
	}
	c, err := s.Cases.GetContextCase(ctx, source, p.CandidateCaseID)
	if err != nil || c.CaseID != p.CandidateCaseID || !c.Valid(s.Now()) || !p.Valid(s.Now()) || ctx.Err() != nil {
		return zero, catalog.ErrUnavailable
	}
	if len(p.Actions) != 0 {
		// A useful published sibling remains navigable while other members are
		// pending or failed. The catalog independently authorizes every artifact.
		for _, a := range c.Artifacts {
			for _, child := range p.Actions {
				if (child.Phase == "Succeeded" || child.Phase == "Partial") && a.CaptureID == child.InstanceID && a.Target.PodUID == child.PodUID && a.Target.ClusterID == p.Target.ClusterID && a.Target.NamespaceUID == p.Target.NamespaceUID && a.Target.WorkloadUID == p.Target.WorkloadUID {
					return ContextCaseLink{CaseID: c.CaseID, ObservedAt: c.ObservedAt, ValidUntil: identity.Earlier(c.ValidUntil, p.ValidUntil)}, nil
				}
			}
		}
		return zero, catalog.ErrUnavailable
	}
	for _, a := range c.Artifacts {
		if a.ArtifactID == p.CandidateArtifactID && a.CaptureID == p.CaptureID && a.Target == p.Target {
			return ContextCaseLink{CaseID: c.CaseID, ObservedAt: c.ObservedAt, ValidUntil: identity.Earlier(c.ValidUntil, p.ValidUntil)}, nil
		}
	}
	return zero, catalog.ErrUnavailable
}
