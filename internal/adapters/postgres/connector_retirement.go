package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// No arbitrary ticket insertion is exposed. Original process/backing acceptance
// created the paid ticket; this journal only closes that exact retained cohort.
// Actual authenticated SQL login pins still decide every read/write operation.
type ConnectorRetirements struct {
	ledger  *Ledger
	root    string
	backing app.ConnectorIdentityBacking
	mac     *auditapp.OperationMAC
}

var _ app.ConnectorRetirementJournal = (*ConnectorRetirements)(nil)

func NewConnectorRetirements(ctx context.Context, pool *pgxpool.Pool, root string, backing app.ConnectorIdentityBacking, mac *auditapp.OperationMAC) (*ConnectorRetirements, error) {
	if !authorization.UUID(root) || !backing.Valid() || backing.Policy.RootID != root || backing.Policy.History.Layout != audit.ConnectorRetirementHistoryLayout || mac == nil || mac.AccountVersion() != backing.AccountVersion {
		return nil, value.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &ConnectorRetirements{l, root, backing.Clone(), mac}, nil
}
func (s *ConnectorRetirements) current(c app.ConnectorRetirementCurrent) bool {
	return s != nil && c.Valid(time.Now()) && c.Recovery.InstallationID == s.backing.Policy.InstallationID
}
func (s *ConnectorRetirements) record(raw []byte, c app.ConnectorRetirementCurrent) (app.ConnectorRetirementRecord, error) {
	var r app.ConnectorRetirementRecord
	if len(raw) == 0 || len(raw) > 48<<10 || json.Unmarshal(raw, &r) != nil || !r.Valid() || r.Ticket.RootID != s.root || r.Ticket.Binding.InstallationID != c.Recovery.InstallationID || r.Ticket.Binding.IssuerEpoch != c.Recovery.IssuerEpoch || r.Ticket.AccountVersion != s.mac.AccountVersion() || !audit.CompatibleConnectorPolicy(r.Ticket.Policy, s.backing.Policy) {
		return app.ConnectorRetirementRecord{}, value.ErrUnavailable
	}
	account, e := s.mac.ConnectorAccount(r.Ticket.Binding)
	if e != nil || account != r.Ticket.PrincipalDigest {
		return app.ConnectorRetirementRecord{}, value.ErrUnavailable
	}
	return r, nil
}
func (s *ConnectorRetirements) ReadConnectorRetirement(ctx context.Context, ticketID string, c app.ConnectorRetirementCurrent) (app.ConnectorRetirementRecord, error) {
	var out app.ConnectorRetirementRecord
	if ctx == nil || ctx.Err() != nil || !authorization.UUID(ticketID) || !s.current(c) {
		return out, value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	e := s.ledger.transaction(live, func(q *custodydb.Queries) error {
		raw, e := q.ReadConnectorRetirement(live, custodydb.ReadConnectorRetirementParams{RootID: id(s.root), TicketID: id(ticketID), ObservedAt: ts(c.ObservedAt), UntilTime: ts(c.Until)})
		if e != nil {
			return e
		}
		out, e = s.record(raw, c)
		return e
	})
	if e != nil || live.Err() != nil || !s.current(c) || out.Ticket.ID != ticketID {
		return app.ConnectorRetirementRecord{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ConnectorRetirements) RestrictConnectorRetirement(ctx context.Context, ticketID, cause string, c app.ConnectorRetirementCurrent) (app.ConnectorRetirementRecord, error) {
	var out app.ConnectorRetirementRecord
	if ctx == nil || ctx.Err() != nil || !authorization.UUID(ticketID) || !s.current(c) || cause != audit.ConnectorRetirementExpiry && cause != audit.ConnectorRetirementExplicit || (cause == audit.ConnectorRetirementExplicit) != (c.Proof != nil) {
		return out, value.ErrUnavailable
	}
	c = c.Clone()
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	body, e := json.Marshal(c)
	if e != nil || len(body) > 384<<10 {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		raw, e := q.RestrictConnectorRetirement(live, custodydb.RestrictConnectorRetirementParams{RootID: id(s.root), TicketID: id(ticketID), Cause: cause, CurrentValue: body})
		if e != nil {
			return e
		}
		out, e = s.record(raw, c)
		return e
	})
	if e != nil || live.Err() != nil || !s.current(c) || out.Ticket.ID != ticketID || out.Restriction == nil {
		return app.ConnectorRetirementRecord{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ConnectorRetirements) PrepareConnectorRetirement(ctx context.Context, expected app.ConnectorRetirementRecord, c app.ConnectorRetirementCurrent) (app.ConnectorRetirementRecord, error) {
	var out app.ConnectorRetirementRecord
	if ctx == nil || ctx.Err() != nil || !s.current(c) || !expected.Valid() || expected.Restriction == nil || expected.Ticket.RootID != s.root {
		return out, value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	e := s.ledger.transaction(live, func(q *custodydb.Queries) error {
		params := custodydb.ReadConnectorRetirementParams{RootID: id(s.root), TicketID: id(expected.Ticket.ID), ObservedAt: ts(c.ObservedAt), UntilTime: ts(c.Until)}
		raw, e := q.ReadConnectorRetirement(live, params)
		if e != nil {
			return e
		}
		original, e := s.record(raw, c)
		if e != nil || !sameAuditJSON(original.Ticket, expected.Ticket) || !sameAuditJSON(original.Restriction, expected.Restriction) || !original.RestrictedAt.Equal(expected.RestrictedAt) {
			return value.ErrUnavailable
		}
		if original.Snapshot != nil {
			out = original
			return nil
		}
		if !original.AdmissionOpen {
			return value.ErrUnavailable
		}
		until := c.Until
		if original.Ticket.ConsumeUntil.Before(until) {
			until = original.Ticket.ConsumeUntil
		}
		in, e := app.ConnectorRetirementIntent(original.Ticket, original.Restriction.Cause, original.Restriction.RetiringSource, original.Ticket.ID, c.ObservedAt.UTC().Truncate(time.Microsecond), until.UTC().Truncate(time.Microsecond), s.mac)
		if e != nil {
			return e
		}
		body, e := json.Marshal(in)
		if e != nil || len(body) > 8192 {
			return value.ErrUnavailable
		}
		// Unknown commits are rediscovered by the original ticket ID before this
		// constructor runs again. SQL also repeats lookup under its root lock.
		_, e = q.AdmitConnectorRetirement(live, custodydb.AdmitConnectorRetirementParams{RootID: id(s.root), TicketID: id(original.Ticket.ID), IntentValue: body, ObservedAt: ts(c.ObservedAt), UntilTime: ts(c.Until)})
		if e != nil {
			return e
		}
		raw, e = q.ReadConnectorRetirement(live, params)
		if e != nil {
			return e
		}
		out, e = s.record(raw, c)
		return e
	})
	if e != nil || live.Err() != nil || !s.current(c) || out.Snapshot == nil {
		return app.ConnectorRetirementRecord{}, value.ErrUnavailable
	}
	return out, nil
}

func (s *ConnectorRetirements) StoreConnectorRetirementOutcome(ctx context.Context, outcome audit.OperationOutcome, c app.ConnectorRetirementCurrent) (app.ConnectorRetirementRecord, error) {
	var out app.ConnectorRetirementRecord
	if ctx == nil || ctx.Err() != nil || !s.current(c) || !outcome.Valid() || outcome.Intent.RootID != s.root || outcome.Intent.Name != "connector_retirement" || outcome.Intent.RetirementOrigin == nil {
		return out, value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	body, e := json.Marshal(outcome)
	if e != nil || len(body) > 24<<10 {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		raw, e := q.StoreConnectorRetirementOutcome(live, custodydb.StoreConnectorRetirementOutcomeParams{RootID: id(s.root), TicketID: id(outcome.Intent.ID), OutcomeValue: body, ObservedAt: ts(c.ObservedAt), UntilTime: ts(c.Until)})
		if e != nil {
			return e
		}
		out, e = s.record(raw, c)
		return e
	})
	if e != nil || live.Err() != nil || !s.current(c) || out.Snapshot == nil || out.Snapshot.Outcome == nil || !sameAuditJSON(*out.Snapshot.Outcome, outcome) {
		return app.ConnectorRetirementRecord{}, value.ErrUnavailable
	}
	return out, nil
}
