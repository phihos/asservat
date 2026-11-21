package authorization

import (
	"context"
	"slices"

	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// FindRawGrant returns the ID of a current approved grant of the caller that
// names operation for this artifact, or "" when none does. A raw query that
// names no grant reuses it (ADR-335 D5, REQ-MCP-003); the query's own grant
// check then verifies it in full and charges it as if it had been named.
func (s GrantService) FindRawGrant(ctx context.Context, i identity.Identity, caseID, artifactID, captureID, operation string) (string, error) {
	if s.Store == nil || s.Now == nil || i.Principal.Kind != identity.Human {
		return "", nil
	}
	now := s.Now()
	var after GrantCursor
	for {
		page, err := s.Store.RequestedGrants(ctx, i.Principal, after, grantListBatch)
		if err != nil {
			return "", ErrGrantUnavailable
		}
		for _, g := range page {
			after = GrantCursor{RequestedAt: g.RequestedAt, ID: g.ID}
			if g.Phase(now) == value.GrantApproved && g.RootID == s.RootID && rawGrantCovers(g, caseID, artifactID, captureID, operation) {
				return g.ID, nil
			}
		}
		if len(page) < grantListBatch {
			return "", nil
		}
	}
}

func rawGrantCovers(g value.Grant, caseID, artifactID, captureID, operation string) bool {
	if g.Kind == value.GrantRawQuery {
		return g.RawQuery != nil && g.RawQuery.CaseID == caseID && slices.Contains(g.RawQuery.Operations, operation) &&
			slices.ContainsFunc(g.RawQuery.Artifacts, func(a value.RawQueryArtifact) bool { return a.Output.ArtifactID == artifactID })
	}
	return g.Kind == value.GrantAdHocCapture && g.CaptureID == captureID && g.ResultAccess != nil && slices.Contains(g.ResultAccess.Operations, operation)
}
