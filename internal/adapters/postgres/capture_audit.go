package postgres

import (
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Private audit facets share the existing encrypted pair and positive joined
// writer protocol. They expose no normal/resolution rows and cannot reserve an
// unrelated audit operation: the exact capture admission transaction creates it.
type CaptureAuditJournal struct {
	ledger *Ledger
	policy value.OperationLifecyclePolicy
}
type CaptureAuditAcknowledgements struct {
	ledger *Ledger
	policy value.OperationLifecyclePolicy
}

var _ app.CaptureOperationJournal = (*CaptureAuditJournal)(nil)
var _ app.CaptureOperationAcknowledgements = (*CaptureAuditAcknowledgements)(nil)
var _ app.OperationCompletions = (*CaptureAuditAcknowledgements)(nil)

func captureAuditPolicy(p value.OperationLifecyclePolicy) bool {
	return value.CaptureOperationPolicy(p)
}
func NewCaptureAuditJournal(ctx context.Context, pool *pgxpool.Pool, p value.OperationLifecyclePolicy) (*CaptureAuditJournal, error) {
	if !captureAuditPolicy(p) {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	q := *p.History
	p.History = &q
	return &CaptureAuditJournal{l, p}, nil
}
func NewCaptureAuditAcknowledgements(ctx context.Context, pool *pgxpool.Pool, p value.OperationLifecyclePolicy) (*CaptureAuditAcknowledgements, error) {
	if !captureAuditPolicy(p) {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	q := *p.History
	p.History = &q
	return &CaptureAuditAcknowledgements{l, p}, nil
}
func captureAuditIntent(p value.OperationLifecyclePolicy, in value.OperationIntent) bool {
	return in.Valid() && in.Lifecycle != nil && in.RootID == p.RootID && in.Name == value.CaptureOperationName && in.Lifecycle.Policy.InstallationID == p.InstallationID && in.Lifecycle.Policy.StoreID == p.StoreID && value.CaptureOperationPolicy(in.Lifecycle.Policy)
}

type captureAuditReply struct {
	Snapshot   value.OperationSnapshot
	Fresh      bool
	Completion *value.OperationWriteCompletion
	ValidUntil time.Time
}

func decodeCaptureAuditReply(b []byte, in value.OperationIntent) (captureAuditReply, error) {
	var out captureAuditReply
	if len(b) > 64<<10 || json.Unmarshal(b, &out) != nil || out.ValidUntil.IsZero() || out.ValidUntil.After(in.WriteUntil) || !time.Now().Before(out.ValidUntil) || !sameAuditJSON(out.Snapshot.Intent, in) {
		return out, app.ErrUnavailable
	}
	snap := out.Snapshot
	if snap.IntentReceipt != nil && (!snap.IntentStarted || !snap.IntentReceipt.ValidOperation(in.RootID, in.ID, "intent")) {
		return out, app.ErrUnavailable
	}
	if snap.Outcome != nil && (!snap.Outcome.Valid() || !sameAuditJSON(snap.Outcome.Intent, in) || snap.IntentReceipt == nil) {
		return out, app.ErrUnavailable
	}
	if snap.OutcomeStarted && snap.Outcome == nil {
		return out, app.ErrUnavailable
	}
	if snap.OutcomeReceipt != nil && (!snap.OutcomeStarted || !snap.OutcomeReceipt.ValidOperation(in.RootID, in.ID, "outcome")) {
		return out, app.ErrUnavailable
	}
	return out, nil
}
func (s *CaptureAuditJournal) call(ctx context.Context, in value.OperationIntent, verb string, out *value.OperationOutcome) (captureAuditReply, error) {
	var reply captureAuditReply
	if s == nil || ctx == nil || ctx.Err() != nil || !captureAuditIntent(s.policy, in) {
		return reply, app.ErrUnavailable
	}
	until := in.WriteUntil
	// Lookup and already-spent intent claims remain recoverable through the
	// original WriteUntil; SQL alone grants a first PUT before RequestUntil.
	live, end := context.WithDeadline(ctx, minCaptureAuditTime(until, time.Now().Add(5*time.Second)))
	defer end()
	body, e := app.EncodeCaptureOperationIntent(in)
	if e != nil {
		return reply, app.ErrUnavailable
	}
	var result []byte
	if out != nil {
		result, e = app.EncodeCaptureOperationOutcome(*out)
		if e != nil {
			return reply, app.ErrUnavailable
		}
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		b, err := q.CaptureAuditJournal(live, custodydb.CaptureAuditJournalParams{RootID: id(in.RootID), IntentValue: body, Verb: verb, OutcomeValue: result})
		if err != nil {
			return err
		}
		reply, err = decodeCaptureAuditReply(b, in)
		return err
	})
	if e != nil || live.Err() != nil || !time.Now().Before(minCaptureAuditTime(until, reply.ValidUntil)) {
		return captureAuditReply{}, app.ErrUnavailable
	}
	return reply, nil
}
func (s *CaptureAuditJournal) ReserveOperation(ctx context.Context, in value.OperationIntent) (value.OperationSnapshot, error) {
	r, e := s.call(ctx, in, "reserve", nil)
	return r.Snapshot, e
}
func (s *CaptureAuditJournal) FreezeOperationOutcome(ctx context.Context, out value.OperationOutcome) (value.OperationSnapshot, error) {
	if !out.Valid() {
		return value.OperationSnapshot{}, app.ErrUnavailable
	}
	r, e := s.call(ctx, out.Intent, "freeze-outcome", &out)
	return r.Snapshot, e
}
func (s *CaptureAuditAcknowledgements) call(ctx context.Context, in value.OperationIntent, phase string, completion *value.OperationWriteCompletion, receipt *value.Receipt, claim *value.CaptureReconciliationClaim) (captureAuditReply, error) {
	var reply captureAuditReply
	if s == nil || ctx == nil || ctx.Err() != nil || !captureAuditIntent(s.policy, in) || (phase != "intent" && phase != "outcome") {
		return reply, app.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, minCaptureAuditTime(in.WriteUntil, time.Now().Add(5*time.Second)))
	defer end()
	body, e := app.EncodeCaptureOperationIntent(in)
	if e != nil {
		return reply, app.ErrUnavailable
	}
	var completed, received, readClaim []byte
	if claim != nil {
		if !claim.Valid() || !time.Now().Before(claim.Until) {
			return reply, app.ErrUnavailable
		}
		readClaim, _ = json.Marshal(claim)
	}
	if completion != nil {
		completed, e = json.Marshal(completion)
		if e != nil {
			return reply, app.ErrUnavailable
		}
	}
	if receipt != nil {
		received, e = json.Marshal(receipt)
		if e != nil {
			return reply, app.ErrUnavailable
		}
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		// Read the already frozen exact business record before admitting completion.
		// The acknowledgement role never writes an intent/outcome or starts a PUT.
		b, err := q.CaptureAuditAcknowledge(live, custodydb.CaptureAuditAcknowledgeParams{RootID: id(in.RootID), IntentValue: body, Phase: phase})
		if err != nil {
			return err
		}
		observed, err := decodeCaptureAuditReply(b, in)
		if err != nil {
			return err
		}
		var record any = in
		if phase == "outcome" {
			if observed.Snapshot.Outcome == nil {
				return app.ErrUnavailable
			}
			record = *observed.Snapshot.Outcome
		}
		if completion != nil && (!completion.Valid(in.RootID, in.ID, in.Lifecycle.Policy.StoreID, phase, in.CreatedAt, in.WriteUntil) || completion.RecordDigest != app.OperationLifecycleDigest(record)) {
			return app.ErrUnavailable
		}
		if receipt != nil && !receipt.ValidOperation(in.RootID, in.ID, phase) {
			return app.ErrUnavailable
		}
		if completion != nil || receipt != nil {
			b, err = q.CaptureAuditAcknowledge(live, custodydb.CaptureAuditAcknowledgeParams{RootID: id(in.RootID), IntentValue: body, Phase: phase, CompletionValue: completed, ReceiptValue: received, ReadClaim: readClaim})
			if err != nil {
				return err
			}
		}
		reply, err = decodeCaptureAuditReply(b, in)
		if err != nil {
			return err
		}
		if reply.Completion != nil && (!reply.Completion.Valid(in.RootID, in.ID, in.Lifecycle.Policy.StoreID, phase, in.CreatedAt, in.WriteUntil) || reply.Completion.RecordDigest != app.OperationLifecycleDigest(record)) {
			return app.ErrUnavailable
		}
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(minCaptureAuditTime(in.WriteUntil, reply.ValidUntil)) {
		return captureAuditReply{}, app.ErrUnavailable
	}
	return reply, nil
}
func (s *CaptureAuditAcknowledgements) AcknowledgeOperation(ctx context.Context, in value.OperationIntent, phase string, r value.Receipt) error {
	_, e := s.call(ctx, in, phase, nil, &r, nil)
	return e
}
func (s *CaptureAuditAcknowledgements) RecordOperationCompletion(ctx context.Context, in value.OperationIntent, phase string, c value.OperationWriteCompletion) error {
	_, e := s.call(ctx, in, phase, &c, nil, nil)
	return e
}
func (s *CaptureAuditAcknowledgements) ReadOperationCompletion(ctx context.Context, in value.OperationIntent, phase string) (value.OperationWriteCompletion, error) {
	r, e := s.call(ctx, in, phase, nil, nil, nil)
	if e != nil || r.Completion == nil {
		return value.OperationWriteCompletion{}, app.ErrUnavailable
	}
	return *r.Completion, nil
}

func minCaptureAuditTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Exact lookup supplies the original accepted typed payload; no caller supplies
// an actor, capture selector or replacement write interval here.
func (s *CaptureAuditJournal) ReadCaptureOperation(ctx context.Context, operation string) (value.OperationSnapshot, error) {
	var out value.OperationSnapshot
	var replyUntil time.Time
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(operation) {
		return out, app.ErrUnavailable
	}
	live, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	e := s.ledger.transaction(live, func(q *custodydb.Queries) error {
		b, err := q.ReadCaptureOperation(live, custodydb.ReadCaptureOperationParams{RootID: id(s.policy.RootID), OperationID: id(operation)})
		if err != nil {
			return err
		}
		var observed captureAuditReply
		if len(b) > 64<<10 || json.Unmarshal(b, &observed) != nil || !captureAuditIntent(s.policy, observed.Snapshot.Intent) || observed.Snapshot.Intent.ID != operation {
			return app.ErrUnavailable
		}
		parsed, err := decodeCaptureAuditReply(b, observed.Snapshot.Intent)
		if err != nil {
			return err
		}
		out = parsed.Snapshot
		replyUntil = parsed.ValidUntil
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(minCaptureAuditTime(out.Intent.WriteUntil, replyUntil)) {
		return value.OperationSnapshot{}, app.ErrUnavailable
	}
	return out, nil
}
func (s *CaptureAuditJournal) ClaimCaptureReconciliation(ctx context.Context, in value.OperationIntent, phase string) (value.CaptureReconciliationClaim, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !captureAuditIntent(s.policy, in) || (phase != "intent" && phase != "outcome") {
		return value.CaptureReconciliationClaim{}, app.ErrUnavailable
	}
	until := minCaptureAuditTime(in.WriteUntil, time.Now().Add(5*time.Second))
	live, end := context.WithDeadline(ctx, until)
	defer end()
	body, _ := app.EncodeCaptureOperationIntent(in)
	var granted value.CaptureReconciliationClaim
	e := s.ledger.transaction(live, func(q *custodydb.Queries) error {
		v, err := q.ClaimCaptureReconciliation(live, custodydb.ClaimCaptureReconciliationParams{RootID: id(in.RootID), IntentValue: body, Phase: phase})
		if err != nil {
			return err
		}
		if len(v) > 256 || json.Unmarshal(v, &granted) != nil || !granted.Valid() || granted.Until.After(in.WriteUntil) {
			return app.ErrUnavailable
		}
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(granted.Until) {
		return value.CaptureReconciliationClaim{}, app.ErrUnavailable
	}
	return granted, nil
}
func (s *CaptureAuditAcknowledgements) AcknowledgeCapturePair(ctx context.Context, in value.OperationIntent) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !captureAuditIntent(s.policy, in) {
		return app.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, minCaptureAuditTime(in.WriteUntil, time.Now().Add(5*time.Second)))
	defer end()
	body, _ := app.EncodeCaptureOperationIntent(in)
	until := in.WriteUntil
	e := s.ledger.transaction(live, func(q *custodydb.Queries) error {
		granted, err := q.AcknowledgeCapturePair(live, custodydb.AcknowledgeCapturePairParams{RootID: id(in.RootID), IntentValue: body})
		if err != nil {
			return err
		}
		if !granted.Valid {
			return app.ErrUnavailable
		}
		until = minCaptureAuditTime(until, granted.Time)
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(until) {
		return app.ErrUnavailable
	}
	return nil
}

func (s *CaptureAuditAcknowledgements) AcknowledgeReconciledCapture(ctx context.Context, in value.OperationIntent, phase string, r value.Receipt, c value.CaptureReconciliationClaim) error {
	if !c.Valid() || ctx == nil {
		return app.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	_, e := s.call(live, in, phase, nil, &r, &c)
	return e
}

func (s *CaptureAuditJournal) ClaimCaptureWrite(ctx context.Context, in value.OperationIntent, phase string) (value.CaptureWriteClaim, error) {
	if phase != "intent" && phase != "outcome" {
		return value.CaptureWriteClaim{}, app.ErrUnavailable
	}
	r, e := s.call(ctx, in, "claim-"+phase, nil)
	if e != nil {
		return value.CaptureWriteClaim{}, e
	}
	return value.CaptureWriteClaim{Fresh: r.Fresh, Until: r.ValidUntil}, nil
}
