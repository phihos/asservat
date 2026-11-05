package postgres

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	analysisapp "asservat.local/asservat/internal/application/analysis"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var _ analysisapp.TargetDiscoveryRoutes = (*ContextCaseReads)(nil)

// ResolveTargetDiscoveryRoute locates exactly one published process artifact
// for the original capture. It supplies no evidence or read authority; C-03
// independently checks current maintainer rights and the original audience.
func (s *ContextCaseReads) ResolveTargetDiscoveryRoute(ctx context.Context, captureID string, caller identity.Identity, proof artifact.RecoveryProof) (analysis.ContextProjectionCandidate, error) {
	var out analysis.ContextProjectionCandidate
	if s == nil || s.ledger == nil || s.recovery == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(captureID) {
		return out, analysis.ErrUnavailable
	}
	caller.Groups = slices.Clone(caller.Groups)
	caller.Scopes = slices.Clone(caller.Scopes)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		first, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !caller.Valid(first.Time) || !proof.Valid(first.Time) {
			return analysis.ErrUnavailable
		}
		held, err := s.recovery.lock(ctx, q, s.root, proof)
		if err != nil {
			return err
		}
		rows, err := q.ReadTargetDiscoveryRoute(ctx, custodydb.ReadTargetDiscoveryRouteParams{RootID: id(s.root), CaptureID: id(captureID)})
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return analysis.ErrUnavailable
		}
		r := rows[0]
		if uid(r.RootID) != s.root || uid(r.CaptureID) != captureID || len(r.Version) != 32 {
			return analysis.ErrUnavailable
		}
		var version artifact.Digest
		copy(version[:], r.Version)
		if version == (artifact.Digest{}) {
			return analysis.ErrUnavailable
		}
		out = analysis.ContextProjectionCandidate{RootID: s.root, CaseID: uid(r.CaseID), ArtifactID: uid(r.ArtifactID), CaptureID: captureID, ClusterID: uid(r.ClusterID), NamespaceUID: r.NamespaceUid, WorkloadUID: r.WorkloadUid, PodUID: r.PodUid, Principal: caller.Principal, NativeType: artifact.ProcessesArtifact}
		if !out.RouteValid() {
			return analysis.ErrUnavailable
		}
		if err = s.recovery.check(ctx, q, held, s.root, proof); err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !caller.Valid(now.Time) || !proof.Valid(now.Time) {
			return analysis.ErrUnavailable
		}
		return ctx.Err()
	})
	if err != nil || ctx.Err() != nil {
		return analysis.ContextProjectionCandidate{}, analysis.ErrUnavailable
	}
	return out, nil
}
