package postgres

import (
	"context"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

var (
	_ analysisapp.ContextProjectionRoutes = (*ContextCaseReads)(nil)
	_ authapp.ProjectionRouteReader       = (*ContextCaseReads)(nil)
)

// ResolveContextProjection uses only the bounded private case locator. It does
// not read source content or provide an authorization decision; C-03 must check
// current target eligibility before resolving the protected publication facts.
func (s *ContextCaseReads) ResolveContextProjection(ctx context.Context, selection analysis.ContextExcerptSelection, caller identity.Identity, recovery artifact.RecoveryProof) (analysis.ContextProjectionCandidate, error) {
	if !selection.Valid() {
		return analysis.ContextProjectionCandidate{}, analysis.ErrUnavailable
	}
	out, err := s.ResolveProjectionRoute(ctx, selection.CaseID, selection.ArtifactID, caller, recovery)
	if err != nil {
		return analysis.ContextProjectionCandidate{}, err
	}
	out.Selection = selection.Selection
	if !out.Valid() {
		return analysis.ContextProjectionCandidate{}, analysis.ErrUnavailable
	}
	return out, nil
}

// ResolveProjectionRoute returns the routing facts of one case artifact
// without a source or selection (ADR-282 reuses it for httpHeaders reads).
func (s *ContextCaseReads) ResolveProjectionRoute(ctx context.Context, caseID, artifactID string, caller identity.Identity, recovery artifact.RecoveryProof) (analysis.ContextProjectionCandidate, error) {
	var out analysis.ContextProjectionCandidate
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(caseID) || !authorization.UUID(artifactID) {
		return out, analysis.ErrUnavailable
	}
	routes, err := s.ResolveContextCase(ctx, catalog.CaseRouteQuery{RootID: s.root, CaseID: caseID, Identity: caller, Recovery: recovery})
	if err != nil || routes.CaseID != caseID || !routes.Valid(time.Now()) {
		return out, analysis.ErrUnavailable
	}
	matched := false
	for _, route := range routes.Routes {
		if route.ArtifactID != artifactID {
			continue
		}
		if matched {
			return analysis.ContextProjectionCandidate{}, analysis.ErrUnavailable
		}
		matched = true
		out = analysis.ContextProjectionCandidate{
			RootID: s.root, CaseID: routes.CaseID, ArtifactID: route.ArtifactID, CaptureID: route.CaptureID,
			ClusterID: route.Target.ClusterID, NamespaceUID: route.Target.NamespaceUID,
			WorkloadUID: route.Target.WorkloadUID, PodUID: route.Target.PodUID, Principal: caller.Principal,
		}
	}
	if ctx.Err() != nil || !routes.Valid(time.Now()) || !out.RouteValid() {
		return analysis.ContextProjectionCandidate{}, analysis.ErrUnavailable
	}
	return out, nil
}
