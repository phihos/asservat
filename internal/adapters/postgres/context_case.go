package postgres

import (
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/catalog"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextCaseReads returns only bounded internal target locators. A separate
// ordinary evaluator must authorize each target before reading its metadata.
// The role cannot insert catalog/locator rows or mutate any capture state.
type ContextCaseReads struct {
	ledger *Ledger
	root   string
}

var _ app.ContextCaseRoutes = (*ContextCaseReads)(nil)

func NewContextCaseReads(ctx context.Context, pool *pgxpool.Pool, root string) (*ContextCaseReads, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrUnavailable
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &ContextCaseReads{ledger: l, root: root}, nil
}

func (s *ContextCaseReads) ResolveContextCase(ctx context.Context, request value.CaseRouteQuery) (value.ContextCaseRoutes, error) {
	var out value.ContextCaseRoutes
	if ctx == nil || ctx.Err() != nil || s == nil || s.ledger == nil || request.RootID != s.root || !request.Identity.Valid(request.Identity.VerifiedAt) {
		return out, value.ErrUnavailable
	}
	request.Identity.Groups = slices.Clone(request.Identity.Groups)
	request.Identity.Scopes = slices.Clone(request.Identity.Scopes)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = value.ContextCaseRoutes{}
		first, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !request.Valid(first.Time) {
			return value.ErrUnavailable
		}
		rows, err := q.ReadContextCaseRoutes(ctx, custodydb.ReadContextCaseRoutesParams{RootID: id(s.root), CaseID: id(request.CaseID)})
		if err != nil {
			return err
		}
		if len(rows) < 1 || len(rows) > value.MaxContextCaseArtifacts {
			return value.ErrUnavailable
		}
		out = value.ContextCaseRoutes{CaseID: request.CaseID, ObservedAt: first.Time, ValidUntil: identity.Earlier(first.Time.Add(5*time.Second), request.Identity.ValidUntil)}
		if d, ok := ctx.Deadline(); ok {
			out.ValidUntil = identity.Earlier(out.ValidUntil, d)
		}
		for _, row := range rows {
			if uid(row.RootID) != s.root || uid(row.CaseID) != request.CaseID {
				return value.ErrUnavailable
			}
			if len(row.Version) != 32 {
				return value.ErrUnavailable
			}
			var version artifact.Digest
			copy(version[:], row.Version)
			out.Routes = append(out.Routes, value.ContextCaseRoute{Version: version, CaptureID: uid(row.CaptureID), ArtifactID: uid(row.ArtifactID), NativeType: row.NativeType, Target: authorization.Target{ClusterID: uid(row.ClusterID), NamespaceUID: row.NamespaceUid, WorkloadUID: row.WorkloadUid, PodUID: row.PodUid}})
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !request.Valid(now.Time) || !out.Valid(now.Time) {
			return value.ErrUnavailable
		}
		return ctx.Err()
	})
	if err != nil || ctx.Err() != nil {
		return value.ContextCaseRoutes{}, value.ErrUnavailable
	}
	return out, nil
}
