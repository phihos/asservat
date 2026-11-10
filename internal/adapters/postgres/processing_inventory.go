package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// ProcessingInventory reuses the processing-decision duty's exact existing
// table grants and recovery/source transaction. It adds no pool or SQL role.
type ProcessingInventory struct{ decisions *ProcessingDecisions }

var _ app.ProcessingInventoryReader = (*ProcessingInventory)(nil)
var _ app.ProcessingArtifactScopes = (*ProcessingInventory)(nil)

func NewProcessingInventory(ctx context.Context, pool *pgxpool.Pool, root string, recovery *RecoveryTransactionGuard) (*ProcessingInventory, error) {
	decisions, err := NewProcessingDecisions(ctx, pool, root, recovery)
	if err != nil {
		return nil, err
	}
	return &ProcessingInventory{decisions}, nil
}
func (s *ProcessingInventory) ReadProcessingInventory(ctx context.Context, a value.ProcessingAuthority, query value.ProcessingInventoryQuery) (value.ProcessingInventoryPage, error) {
	var out value.ProcessingInventoryPage
	if s == nil || s.decisions == nil || !query.Valid() {
		return out, value.ErrUnavailable
	}
	err := s.decisions.transaction(ctx, a, func(call context.Context, q *custodydb.Queries, p custodydb.ProcessingRoot, now time.Time) error {
		after := pgtype.UUID{}
		if query.After != "" {
			after = id(query.After)
		}
		rows, err := q.ListProcessingInventoryRules(call, custodydb.ListProcessingInventoryRulesParams{RootID: p.RootID, AfterID: after, PageLimit: int32(query.Limit + 1)})
		if err != nil || len(rows) > query.Limit+1 {
			return value.ErrUnavailable
		}
		out = value.ProcessingInventoryPage{RootID: uid(p.RootID), Epoch: uid(p.Epoch), Initialized: p.InitializedAt.Valid, Sequence: p.Sequence, Rules: []value.ProcessingInventoryRule{}, ObservedAt: a.ObservedAt, ValidUntil: identity.Earlier(a.ValidUntil, p.ValidUntil.Time)}
		more := len(rows) > query.Limit
		if more {
			rows = rows[:query.Limit]
		}
		for _, row := range rows {
			rule := value.ProcessingInventoryRule{ID: uid(row.ID), Revision: row.Revision, State: row.State, AdministrationUntil: row.ValidUntil.Time, RetireBy: row.RetireBy.Time}
			if json.Unmarshal(row.Scope, &rule.Scope) != nil || !rule.Valid() {
				return value.ErrUnavailable
			}
			out.Rules = append(out.Rules, rule)
		}
		if more {
			out.NextCursor = out.Rules[len(out.Rules)-1].ID
		}
		if out.RootID != s.decisions.root || !out.Valid(query, now) {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return value.ProcessingInventoryPage{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ProcessingInventory) ResolveProcessingArtifactScope(ctx context.Context, a value.ProcessingAuthority, artifactID string) (value.ProcessingScope, error) {
	var out value.ProcessingScope
	if s == nil || s.decisions == nil || !authorization.UUID(artifactID) {
		return out, value.ErrUnavailable
	}
	err := s.decisions.transaction(ctx, a, func(call context.Context, q *custodydb.Queries, p custodydb.ProcessingRoot, now time.Time) error {
		row, err := q.ResolveProcessingArtifactScope(call, custodydb.ResolveProcessingArtifactScopeParams{RootID: p.RootID, ArtifactID: id(artifactID)})
		out = value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: uid(row.ClusterID), ArtifactID: uid(row.ArtifactID), AttemptID: uid(row.AttemptID)}}
		if err != nil || !out.Valid() || out.Location.ArtifactID != artifactID {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return value.ProcessingScope{}, value.ErrUnavailable
	}
	return out, nil
}
