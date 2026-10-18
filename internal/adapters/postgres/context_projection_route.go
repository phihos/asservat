package postgres

import (
	"context"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

var _ analysisapp.ContextProjectionRoutes = (*ContextCaseReads)(nil)

// ResolveContextProjection uses only the bounded private case locator. It does
// not read source content or provide an authorization decision; C-03 must check
// current target eligibility before resolving the protected publication facts.
func (s *ContextCaseReads) ResolveContextProjection(ctx context.Context, selection analysis.ContextExcerptSelection, caller identity.Identity, recovery artifact.RecoveryProof) (analysis.ContextProjectionCandidate, error) {
	var out analysis.ContextProjectionCandidate
	if s == nil || ctx == nil || ctx.Err() != nil || !selection.Valid() {
		return out, analysis.ErrUnavailable
	}
	routes, err := s.ResolveContextCase(ctx, catalog.CaseRouteQuery{RootID: s.root, CaseID: selection.CaseID, Identity: caller, Recovery: recovery})
	if err != nil || routes.CaseID != selection.CaseID || !routes.Valid(time.Now()) {
		return out, analysis.ErrUnavailable
	}
	matched := false
	for _, route := range routes.Routes {
		if route.ArtifactID != selection.ArtifactID {
			continue
		}
		if matched {
			return analysis.ContextProjectionCandidate{}, analysis.ErrUnavailable
		}
		matched = true
		out = analysis.ContextProjectionCandidate{
			RootID: s.root, CaseID: routes.CaseID, ArtifactID: route.ArtifactID, CaptureID: route.CaptureID,
			ClusterID: route.Target.ClusterID, NamespaceUID: route.Target.NamespaceUID,
			WorkloadUID: route.Target.WorkloadUID, PodUID: route.Target.PodUID,
			Selection: selection.Selection, Principal: caller.Principal,
		}
	}
	if ctx.Err() != nil || !routes.Valid(time.Now()) || !out.Valid() {
		return analysis.ContextProjectionCandidate{}, analysis.ErrUnavailable
	}
	return out, nil
}
