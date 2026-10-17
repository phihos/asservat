package postgres

import (
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
// unrelated audit operation: the exact process/signing transaction creates it.
type ConnectorAuditJournal struct {
	ledger *Ledger
	policy value.OperationLifecyclePolicy
}
type ConnectorAuditAcknowledgements struct {
	ledger *Ledger
	policy value.OperationLifecyclePolicy
}

var _ app.OperationJournal = (*ConnectorAuditJournal)(nil)
var _ app.OperationAcknowledgements = (*ConnectorAuditAcknowledgements)(nil)
var _ app.OperationCompletions = (*ConnectorAuditAcknowledgements)(nil)

func connectorAuditPolicy(p value.OperationLifecyclePolicy) bool {
	return value.CompatibleConnectorPolicy(p, p)
}
func NewConnectorAuditJournal(ctx context.Context, pool *pgxpool.Pool, p value.OperationLifecyclePolicy) (*ConnectorAuditJournal, error) {
	if !connectorAuditPolicy(p) {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	q := *p.History
	p.History = &q
	return &ConnectorAuditJournal{l, p}, nil
}
func NewConnectorAuditAcknowledgements(ctx context.Context, pool *pgxpool.Pool, p value.OperationLifecyclePolicy) (*ConnectorAuditAcknowledgements, error) {
	if !connectorAuditPolicy(p) {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	q := *p.History
	p.History = &q
	return &ConnectorAuditAcknowledgements{l, p}, nil
}
func connectorAuditIntent(p value.OperationLifecyclePolicy, in value.OperationIntent) bool {
	return in.Valid() && in.Lifecycle != nil && in.RootID == p.RootID && value.OperationLane(in.Name) == "identity" && value.CompatibleConnectorPolicy(in.Lifecycle.Policy, p)
}

type connectorAuditReply struct {
	Snapshot   value.OperationSnapshot
	Fresh      bool
	Completion *value.OperationWriteCompletion
}

func decodeConnectorAuditReply(b []byte, in value.OperationIntent) (connectorAuditReply, error) {
	var out connectorAuditReply
	if len(b) > 48<<10 || json.Unmarshal(b, &out) != nil || !sameAuditJSON(out.Snapshot.Intent, in) {
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
func (s *ConnectorAuditJournal) call(ctx context.Context, in value.OperationIntent, verb string, out *value.OperationOutcome) (connectorAuditReply, error) {
	var reply connectorAuditReply
	if s == nil || ctx == nil || ctx.Err() != nil || !connectorAuditIntent(s.policy, in) {
		return reply, app.ErrUnavailable
	}
	until := in.WriteUntil
	if verb == "reserve" || verb == "claim-intent" {
		until = in.RequestUntil
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	body, e := json.Marshal(in)
	if e != nil {
		return reply, app.ErrUnavailable
	}
	var result []byte
	if out != nil {
		result, e = json.Marshal(out)
		if e != nil {
			return reply, app.ErrUnavailable
		}
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		b, err := q.ConnectorAuditJournal(live, custodydb.ConnectorAuditJournalParams{RootID: id(in.RootID), IntentValue: body, Verb: verb, OutcomeValue: result})
		if err != nil {
			return err
		}
		reply, err = decodeConnectorAuditReply(b, in)
		return err
	})
	if e != nil || live.Err() != nil || !time.Now().Before(until) {
		return connectorAuditReply{}, app.ErrUnavailable
	}
	return reply, nil
}
func (s *ConnectorAuditJournal) ReserveOperation(ctx context.Context, in value.OperationIntent) (value.OperationSnapshot, error) {
	r, e := s.call(ctx, in, "reserve", nil)
	return r.Snapshot, e
}
func (s *ConnectorAuditJournal) ClaimOperationWrite(ctx context.Context, in value.OperationIntent, phase string) (bool, error) {
	if phase != "intent" && phase != "outcome" {
		return false, app.ErrUnavailable
	}
	r, e := s.call(ctx, in, "claim-"+phase, nil)
	return r.Fresh, e
}
func (s *ConnectorAuditJournal) FreezeOperationOutcome(ctx context.Context, out value.OperationOutcome) (value.OperationSnapshot, error) {
	if !out.Valid() {
		return value.OperationSnapshot{}, app.ErrUnavailable
	}
	r, e := s.call(ctx, out.Intent, "freeze-outcome", &out)
	return r.Snapshot, e
}
func (s *ConnectorAuditAcknowledgements) call(ctx context.Context, in value.OperationIntent, phase string, completion *value.OperationWriteCompletion, receipt *value.Receipt) (connectorAuditReply, error) {
	var reply connectorAuditReply
	if s == nil || ctx == nil || ctx.Err() != nil || !connectorAuditIntent(s.policy, in) || (phase != "intent" && phase != "outcome") {
		return reply, app.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, in.WriteUntil)
	defer end()
	body, e := json.Marshal(in)
	if e != nil {
		return reply, app.ErrUnavailable
	}
	var completed, received []byte
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
		b, err := q.ConnectorAuditAcknowledge(live, custodydb.ConnectorAuditAcknowledgeParams{RootID: id(in.RootID), IntentValue: body, Phase: phase})
		if err != nil {
			return err
		}
		observed, err := decodeConnectorAuditReply(b, in)
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
		if completion != nil && (!completion.Valid(in.RootID, in.ID, s.policy.StoreID, phase, in.CreatedAt, in.WriteUntil) || completion.RecordDigest != app.OperationLifecycleDigest(record)) {
			return app.ErrUnavailable
		}
		if receipt != nil && !receipt.ValidOperation(in.RootID, in.ID, phase) {
			return app.ErrUnavailable
		}
		if completion != nil || receipt != nil {
			b, err = q.ConnectorAuditAcknowledge(live, custodydb.ConnectorAuditAcknowledgeParams{RootID: id(in.RootID), IntentValue: body, Phase: phase, CompletionValue: completed, ReceiptValue: received})
			if err != nil {
				return err
			}
		}
		reply, err = decodeConnectorAuditReply(b, in)
		if err != nil {
			return err
		}
		if reply.Completion != nil && (!reply.Completion.Valid(in.RootID, in.ID, s.policy.StoreID, phase, in.CreatedAt, in.WriteUntil) || reply.Completion.RecordDigest != app.OperationLifecycleDigest(record)) {
			return app.ErrUnavailable
		}
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(in.WriteUntil) {
		return connectorAuditReply{}, app.ErrUnavailable
	}
	return reply, nil
}
func (s *ConnectorAuditAcknowledgements) AcknowledgeOperation(ctx context.Context, in value.OperationIntent, phase string, r value.Receipt) error {
	_, e := s.call(ctx, in, phase, nil, &r)
	return e
}
func (s *ConnectorAuditAcknowledgements) RecordOperationCompletion(ctx context.Context, in value.OperationIntent, phase string, c value.OperationWriteCompletion) error {
	_, e := s.call(ctx, in, phase, &c, nil)
	return e
}
func (s *ConnectorAuditAcknowledgements) ReadOperationCompletion(ctx context.Context, in value.OperationIntent, phase string) (value.OperationWriteCompletion, error) {
	r, e := s.call(ctx, in, phase, nil, nil)
	if e != nil || r.Completion == nil {
		return value.OperationWriteCompletion{}, app.ErrUnavailable
	}
	return *r.Completion, nil
}
