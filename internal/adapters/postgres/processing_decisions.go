package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type ProcessingDecisions struct {
	ledger   *Ledger
	root     string
	recovery *RecoveryTransactionGuard
}

var _ app.ProcessingDecisions = (*ProcessingDecisions)(nil)

func NewProcessingDecisions(ctx context.Context, pool *pgxpool.Pool, root string, recovery *RecoveryTransactionGuard) (*ProcessingDecisions, error) {
	if recovery == nil || recovery.root != root || !authorization.UUID(root) {
		return nil, value.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return &ProcessingDecisions{l, root, recovery}, nil
}
func processingConfigured(p custodydb.ProcessingRoot, a value.ProcessingAuthority, now time.Time) bool {
	var backing value.ProcessingBacking
	return a.Valid(now) && a.Recovery.IssuerEpoch == uid(p.IssuerEpoch) && a.Policy.RootID == uid(p.RootID) && a.Policy.InstallationID == uid(p.InstallationID) && a.Policy.Revision.UID == uid(p.SourceUid) && bytes.Equal(a.Policy.ProtectionDigest[:], p.ProtectionDigest) && now.Before(p.ValidUntil.Time) && json.Unmarshal(p.Backing, &backing) == nil && backing.Valid() && backing.RootID == uid(p.RootID) && backing.InstallationID == uid(p.InstallationID) && backing.ValidUntil.Equal(p.ValidUntil.Time) && backing.RetireBy.Equal(p.RetireBy.Time)
}
func processingSeed(d app.ProcessingDecision) ([]byte, []byte, error) {
	i, e := json.Marshal(d.Intent)
	if e != nil {
		return nil, nil, e
	}
	var seed map[string]json.RawMessage
	if e = json.Unmarshal(i, &seed); e != nil {
		return nil, nil, e
	}
	delete(seed, "Actor")
	delete(seed, "Peer")
	delete(seed, "Process")
	i, e = json.Marshal(seed)
	if e != nil {
		return nil, nil, e
	}
	o, e := json.Marshal(d.Outcome)
	if e != nil {
		return nil, nil, e
	}
	var output map[string]json.RawMessage
	if e = json.Unmarshal(o, &output); e != nil {
		return nil, nil, e
	}
	delete(output, "Intent")
	o, e = json.Marshal(output)
	return i, o, e
}
func decodeProcessingDecision(row custodydb.ProcessingDecision, actor identity.Principal) (app.ProcessingDecision, error) {
	var d app.ProcessingDecision
	d.Change = value.ProcessingChange{RequestID: uid(row.ID), RuleID: uid(row.RuleID), Action: row.Action, ExpectedRevision: row.ExpectedRevision}
	if !row.RuleID.Valid {
		d.Change.RuleID = ""
	}
	if json.Unmarshal(row.Scope, &d.Change.Scope) != nil || json.Unmarshal(row.IntentSeed, &d.Intent) != nil || json.Unmarshal(row.OutcomeJson, &d.Outcome) != nil || len(row.DecisionDigest) != 32 {
		return d, value.ErrUnavailable
	}
	d.Intent.Actor = actor
	d.Outcome.Intent = d.Intent
	copy(d.DecisionDigest[:], row.DecisionDigest)
	copy(d.ReleaseAccount[:], row.ReleaseAccount)
	if !row.ValidUntil.Valid || !row.RetireBy.Valid || !row.RetireBy.Time.After(row.ValidUntil.Time) || row.RequestUntil.Time.After(row.ValidUntil.Time) || !d.Valid() || d.Intent.ID != uid(row.ID) || d.Intent.RootID != uid(row.RootID) || app.ProcessingDecisionDigest(d) != d.DecisionDigest || !d.Intent.CreatedAt.Equal(row.CreatedAt.Time) || !d.Intent.RequestUntil.Equal(row.RequestUntil.Time) || !bytes.Equal(row.RequestDigest, digest(d.Change)) {
		return app.ProcessingDecision{}, value.ErrUnavailable
	}
	return d, nil
}
func processingReceipt(row custodydb.ProcessingDecision, p custodydb.ProcessingRoot, a value.ProcessingAuthority, now time.Time) (value.ProcessingReceipt, error) {
	state := "initialized"
	rule := ""
	if row.RuleID.Valid {
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
	if s == nil || ctx == nil || ctx.Err() != nil || s.recovery == nil || a.Policy.RootID != s.root {
		return value.ErrUnavailable
	}
	call, stop := context.WithDeadline(ctx, a.ValidUntil)
	defer stop()
	return s.ledger.transaction(call, func(q *custodydb.Queries) error {
		trust, e := s.recovery.lock(call, q, s.root, a.Recovery)
		if e != nil {
			return e
		}
		if _, e = q.LockPermissionStream(call, id(s.root)); e != nil {
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
		if e = s.recovery.check(call, q, trust, s.root, a.Recovery); e != nil {
			return e
		}
		final, e := q.CurrentTime(call)
		if e != nil || !processingConfigured(p, a, final.Time) || call.Err() != nil {
			return value.ErrUnavailable
		}
		return nil
	})
}
func (s *ProcessingDecisions) PrepareProcessing(ctx context.Context, a value.ProcessingAuthority, draft app.ProcessingDecision) (app.ProcessingPrepared, error) {
	var out app.ProcessingPrepared
	if s == nil || ctx == nil || ctx.Err() != nil || !draft.Valid() || draft.Intent.Actor != a.Identity.Principal || draft.Intent.RootID != s.root || app.ProcessingDecisionDigest(draft) != draft.DecisionDigest {
		return out, value.ErrUnavailable
	}
	ctx, stop := context.WithDeadline(ctx, a.ValidUntil)
	defer stop()
	actor, _ := json.Marshal(a.Identity.Principal)
	e := s.transaction(ctx, a, func(ctx context.Context, q *custodydb.Queries, p custodydb.ProcessingRoot, now time.Time) error {
		row, e := q.LockProcessingDecision(ctx, custodydb.LockProcessingDecisionParams{RootID: id(s.root), ID: id(draft.Change.RequestID), Actor: actor})
		if e == nil {
			if !bytes.Equal(row.RequestDigest, digest(draft.Change)) {
				return value.ErrConflict
			}
			if row.AppliedAt.Valid {
				receipt, e := processingReceipt(row, p, a, now)
				if e != nil {
					return e
				}
				out.Receipt = &receipt
				return nil
			}
			previous, e := decodeProcessingDecision(row, a.Identity.Principal)
			if e != nil || !now.Before(previous.Intent.RequestUntil) || previous.Intent.InputDigest != draft.Intent.InputDigest || previous.Intent.MACVersion != draft.Intent.MACVersion {
				return value.ErrUnavailable
			}
			out.Decision = previous
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if !now.Before(draft.Intent.RequestUntil) {
			return value.ErrUnavailable
		}
		var rule pgtype.UUID
		scope, _ := json.Marshal(draft.Change.Scope)
		if draft.Change.Action == "initialize_processing" {
			empty, e := q.ProcessingCatalogEmpty(ctx, id(s.root))
			if e != nil || !empty || p.InitializedAt.Valid {
				return value.ErrUnavailable
			}
		} else {
			rule = id(draft.Change.RuleID)
			r, e := q.LockProcessingRule(ctx, custodydb.LockProcessingRuleParams{RootID: id(s.root), ID: rule})
			if errors.Is(e, pgx.ErrNoRows) && draft.Change.Action == "restrict_processing" && draft.Change.ExpectedRevision == 0 {
				if p.Rules >= p.MaxRules {
					return app.ErrCapacity
				}
				if e = q.InsertProcessingRule(ctx, custodydb.InsertProcessingRuleParams{RootID: id(s.root), ID: rule, Scope: scope, ReleaseAccount: draft.ReleaseAccount[:]}); e != nil {
					return e
				}
			} else if e != nil {
				return e
			} else {
				if r.Decisions >= 16 || draft.Change.Action == "restrict_processing" && r.Decisions >= 15 {
					return app.ErrCapacity
				}
				var retained value.ProcessingScope
				if json.Unmarshal(r.Scope, &retained) != nil || r.Revision != draft.Change.ExpectedRevision || retained != draft.Change.Scope || !bytes.Equal(r.ReleaseAccount, draft.ReleaseAccount[:]) {
					return value.ErrConflict
				}
			}
		}
		seed, output, e := processingSeed(draft)
		if e != nil {
			return e
		}
		var releaseAccount []byte
		if draft.Change.RuleID != "" {
			releaseAccount = draft.ReleaseAccount[:]
		}
		row, e = q.InsertProcessingDecision(ctx, custodydb.InsertProcessingDecisionParams{ID: id(draft.Change.RequestID), RootID: id(s.root), RuleID: rule, ExpectedRevision: draft.Change.ExpectedRevision, ReleaseAccount: releaseAccount, Actor: actor, RequestDigest: digest(draft.Change), Scope: scope, Action: draft.Change.Action, IntentSeed: seed, DecisionDigest: draft.DecisionDigest[:], CreatedAt: ts(draft.Intent.CreatedAt), RequestUntil: ts(draft.Intent.RequestUntil), OutcomeJson: output})
		if e != nil {
			return e
		}
		out.Decision, e = decodeProcessingDecision(row, a.Identity.Principal)
		return e
	})
	if errors.Is(e, app.ErrCapacity) {
		return app.ProcessingPrepared{}, app.ErrCapacity
	}
	if e != nil {
		return app.ProcessingPrepared{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ProcessingDecisions) ApplyProcessing(ctx context.Context, a value.ProcessingAuthority, d app.ProcessingDecision) (value.ProcessingReceipt, error) {
	var out value.ProcessingReceipt
	if s == nil || ctx == nil || ctx.Err() != nil || !d.Valid() || d.Intent.RootID != s.root || d.Intent.Actor != a.Identity.Principal || app.ProcessingDecisionDigest(d) != d.DecisionDigest {
		return out, value.ErrUnavailable
	}
	ctx, stop := context.WithDeadline(ctx, a.ValidUntil)
	defer stop()
	actor, _ := json.Marshal(a.Identity.Principal)
	e := s.transaction(ctx, a, func(ctx context.Context, q *custodydb.Queries, p custodydb.ProcessingRoot, now time.Time) error {
		row, e := q.LockProcessingDecision(ctx, custodydb.LockProcessingDecisionParams{RootID: id(s.root), ID: id(d.Change.RequestID), Actor: actor})
		if e != nil {
			return e
		}
		if !bytes.Equal(row.RequestDigest, digest(d.Change)) || !bytes.Equal(row.DecisionDigest, d.DecisionDigest[:]) {
			return value.ErrConflict
		}
		if !row.AppliedAt.Valid {
			if !now.Before(d.Intent.RequestUntil) {
				return value.ErrUnavailable
			}
			row, e = q.ApplyProcessingDecision(ctx, custodydb.ApplyProcessingDecisionParams{RootID: id(s.root), ID: row.ID})
			if e != nil {
				return e
			}
		}
		current, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		out, e = processingReceipt(row, p, a, current.Time)
		return e
	})
	if e != nil {
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	return out, nil
}
