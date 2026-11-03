package analysis

import (
	"context"
	"encoding/json"
	"errors"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ProfileSummaries exposes the typed internal admission only when explicitly
// composed. No production constructor installs the route reader yet.
func (s ContextProjectionService) ProfileSummaries() (ProfileSummaryReads, bool) {
	return ProfileSummaryReads{Service: s, Routes: s.ProfileRoutes}, s.ProfileRoutes != nil
}

type ProfileSummaryReads struct {
	Service ContextProjectionService
	Routes  ContextProjectionRouteReader
}

func (s ProfileSummaryReads) Begin(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, request value.ProfileSummaryRequest) (*ContextProjectionDelivery, error) {
	var d *ContextProjectionDelivery
	err := queryStepped("configuration", value.ErrUnavailable)
	if request.Valid() && s.Routes != nil {
		d, err = s.Service.begin(ctx, current, invocation, "get_profile_summary", ContextQueryInput{Profile: request}, func(ctx context.Context, caller identity.Identity, recovery artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
			c, err := s.Routes.ResolveProjectionRoute(ctx, request.CaseID, request.ArtifactID, caller, recovery)
			if err != nil || !c.RouteValid() || c.CaseID != request.CaseID || c.ArtifactID != request.ArtifactID || c.Selection != (value.LineSelection{}) || c.NativeType != "" || c.Headers != (value.HTTPHeaderWindow{}) || c.Profile != (value.ProfileSummarySelection{}) {
				return value.ContextProjectionCandidate{}, errors.Join(value.ErrUnavailable, err)
			}
			c.NativeType, c.Profile = artifact.PprofArtifact, request.Selection
			return c, nil
		})
	}
	s.Service.Results.refused(ctx, "profile-summary", err)
	return d, err
}

func (d *ContextProjectionDelivery) ProfileSummary() (value.ProfileSummary, bool) {
	if d == nil || d.pending || d.owner.query.Scope.NativeType != artifact.PprofArtifact {
		return value.ProfileSummary{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.summary == nil {
		return value.ProfileSummary{}, false
	}
	return value.CloneProfileSummary(*d.summary), true
}

// The coordinator checks the encoded worker result independently of parser
// success. The domain remains a structural value model; encoding belongs here.
func boundedProfileSummary(s *value.ProfileSummary, selection value.ProfileSummarySelection) bool {
	if s == nil || !s.Valid(selection) {
		return false
	}
	body, err := json.Marshal(s)
	return err == nil && len(body) <= value.ProfileSummaryBytes
}
