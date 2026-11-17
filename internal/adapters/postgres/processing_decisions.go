package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type ProcessingDecisions struct {
	ledger *Ledger
	root   string
}

var _ app.ProcessingDecisions = (*ProcessingDecisions)(nil)

func NewProcessingDecisions(ctx context.Context, pool *pgxpool.Pool, root string) (*ProcessingDecisions, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return &ProcessingDecisions{l, root}, nil
}
func processingConfigured(p custodydb.ProcessingRoot, a value.ProcessingAuthority, now time.Time) bool {
	var backing value.ProcessingBacking
	return a.Valid(now) && a.Policy.RootID == uid(p.RootID) && a.Policy.InstallationID == uid(p.InstallationID) && a.Policy.Revision.UID == uid(p.SourceUid) && bytes.Equal(a.Policy.ProtectionDigest[:], p.ProtectionDigest) && now.Before(p.ValidUntil.Time) && json.Unmarshal(p.Backing, &backing) == nil && backing.Valid() && backing.RootID == uid(p.RootID) && backing.InstallationID == uid(p.InstallationID) && backing.ValidUntil.Equal(p.ValidUntil.Time) && backing.RetireBy.Equal(p.RetireBy.Time)
}
func processingReceipt(row custodydb.ProcessingDecision, p custodydb.ProcessingRoot, a value.ProcessingAuthority, now time.Time) (value.ProcessingReceipt, error) {
	state := "initialized"
	rule := ""
	if row.Action == value.RequestEarlyErasure {
		state = "erasureRequested"
	} else if row.RuleID.Valid {
		rule = uid(row.RuleID)
		state = "restricted"
		if row.Action == "release_processing" {
			state = "released"
		}
	}
	out := value.ProcessingReceipt{RootID: uid(row.RootID), Epoch: uid(p.Epoch), RequestID: uid(row.ID), RuleID: rule, OperationID: uid(row.ID), State: state, Revision: row.ResultRevision.Int64, Sequence: row.ResultSequence.Int64, ObservedAt: a.ObservedAt, ValidUntil: identity.Earlier(a.ValidUntil, identity.Earlier(p.ValidUntil.Time, row.RetireBy.Time))}
	if !row.AppliedAt.Valid || !row.ResultRevision.Valid || !row.ResultSequence.Valid || !out.Valid(now) {
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ProcessingDecisions) transaction(ctx context.Context, a value.ProcessingAuthority, fn func(context.Context, *custodydb.Queries, custodydb.ProcessingRoot, time.Time) error) error {
	if s == nil || ctx == nil || ctx.Err() != nil || a.Policy.RootID != s.root {
		return value.ErrUnavailable
	}
	call, stop := context.WithDeadline(ctx, a.ValidUntil)
	defer stop()
	return s.ledger.transaction(call, func(q *custodydb.Queries) error {
		if _, e := q.LockPermissionStream(call, id(s.root)); e != nil {
			return e
		}
		p, e := q.LockProcessingRoot(call, id(s.root))
		if e != nil {
			return e
		}
		now, e := q.CurrentTime(call)
		if e != nil || !processingConfigured(p, a, now.Time) {
			return value.ErrUnavailable
		}
		if e = fn(call, q, p, now.Time); e != nil {
			return e
		}
		final, e := q.CurrentTime(call)
		if e != nil || !processingConfigured(p, a, final.Time) || call.Err() != nil {
			return value.ErrUnavailable
		}
		return nil
	})
}

// ApplyProcessing inserts and applies the decision and writes its audit row
// in one transaction. A replay of the request ID by the same actor returns
// the existing receipt and writes nothing.
func (s *ProcessingDecisions) ApplyProcessing(ctx context.Context, a value.ProcessingAuthority, d app.ProcessingDecision) (value.ProcessingReceipt, error) {
	var out value.ProcessingReceipt
	if s == nil || ctx == nil || ctx.Err() != nil || !d.Valid() || a.Policy.RootID != s.root {
		return out, value.ErrUnavailable
	}
	actor, _ := json.Marshal(a.Identity.Principal)
	requestDigest := digest(d.Change)
	e := s.transaction(ctx, a, func(ctx context.Context, q *custodydb.Queries, p custodydb.ProcessingRoot, now time.Time) error {
		row, e := q.LockProcessingDecision(ctx, custodydb.LockProcessingDecisionParams{RootID: id(s.root), ID: id(d.Change.RequestID), Actor: actor})
		if e == nil {
			if !bytes.Equal(row.RequestDigest, requestDigest) {
				return value.ErrConflict
			}
			if !row.AppliedAt.Valid {
				return value.ErrUnavailable
			}
			if row.Action == value.RequestEarlyErasure {
				if e = verifyProcessingErasure(ctx, q, row); e != nil {
					return e
				}
			}
			out, e = processingReceipt(row, p, a, now)
			return e
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if !now.Before(d.RequestUntil) {
			return value.ErrUnavailable
		}
		var rule pgtype.UUID
		var erasure []byte
		scope, _ := json.Marshal(d.Change.Scope)
		switch d.Change.Action {
		case "initialize_processing":
			empty, e := q.ProcessingCatalogEmpty(ctx, id(s.root))
			if e != nil || !empty || p.InitializedAt.Valid {
				return value.ErrUnavailable
			}
		case value.RequestEarlyErasure:
			if p.RootTransitions+2 >= p.MaxRootTransitions {
				return app.ErrCapacity
			}
			if erasure, e = prepareProcessingErasure(ctx, q, s.root, d, requestDigest); e != nil {
				return e
			}
		default:
			rule = id(d.Change.RuleID)
			r, e := q.LockProcessingRule(ctx, custodydb.LockProcessingRuleParams{RootID: id(s.root), ID: rule})
			if errors.Is(e, pgx.ErrNoRows) && d.Change.Action == "restrict_processing" && d.Change.ExpectedRevision == 0 {
				if p.Rules >= p.MaxRules {
					return app.ErrCapacity
				}
				if e = q.InsertProcessingRule(ctx, custodydb.InsertProcessingRuleParams{RootID: id(s.root), ID: rule, Scope: scope}); e != nil {
					return e
				}
			} else if e != nil {
				return e
			} else {
				if r.Decisions >= 16 || d.Change.Action == "restrict_processing" && r.Decisions >= 15 {
					return app.ErrCapacity
				}
				var retained value.ProcessingScope
				if json.Unmarshal(r.Scope, &retained) != nil || r.Revision != d.Change.ExpectedRevision || !retained.Equal(d.Change.Scope) {
					return value.ErrConflict
				}
			}
		}
		if _, e = q.InsertProcessingDecision(ctx, custodydb.InsertProcessingDecisionParams{ID: id(d.Change.RequestID), RootID: id(s.root), RuleID: rule, ExpectedRevision: d.Change.ExpectedRevision, Actor: actor, RequestDigest: requestDigest, Scope: scope, Action: d.Change.Action, CreatedAt: ts(d.CreatedAt), RequestUntil: ts(d.RequestUntil), ErasureDecision: erasure}); e != nil {
			return e
		}
		if row, e = q.ApplyProcessingDecision(ctx, custodydb.ApplyProcessingDecisionParams{RootID: id(s.root), ID: id(d.Change.RequestID)}); e != nil {
			return e
		}
		event := audit.Event{ID: uuid.NewString(), OperationID: d.Change.RequestID, Kind: d.Change.Action, Operation: d.Change.Action, Actor: a.Identity.Principal, Status: "success", Effect: "accepted"}
		if d.Change.Action == value.RequestEarlyErasure {
			event.ArtifactIDs = []string{d.Change.Scope.Location.ArtifactID}
		}
		if e = InsertAuditEvent(ctx, q, event); e != nil {
			return e
		}
		current, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		out, e = processingReceipt(row, p, a, current.Time)
		return e
	})
	switch {
	case errors.Is(e, app.ErrCapacity):
		return value.ProcessingReceipt{}, app.ErrCapacity
	case errors.Is(e, value.ErrConflict):
		return value.ProcessingReceipt{}, value.ErrConflict
	case e != nil:
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	return out, nil
}
