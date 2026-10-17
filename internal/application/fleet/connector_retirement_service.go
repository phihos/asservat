package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// The historical branch deliberately has no proof. The explicit branch adds
// the separate live retirement-only attestation, never an issuance proof.
type ConnectorRetirementCurrent struct {
	Recovery          value.RecoveryState
	Proof             *value.ConnectorRetirementProof `json:",omitempty"`
	ObservedAt, Until time.Time
}

func (c ConnectorRetirementCurrent) Valid(now time.Time) bool {
	if !c.Recovery.Valid(now) || !identity.Fresh(c.ObservedAt, c.Until, now, 5*time.Second) || c.Until.After(c.Recovery.FreshUntil) {
		return false
	}
	return c.Proof == nil || c.Proof.Valid(now) && c.Proof.Process.Binding.InstallationID == c.Recovery.InstallationID && c.Proof.Process.Binding.IssuerEpoch == c.Recovery.IssuerEpoch && !c.Until.After(c.Proof.FreshUntil)
}
func (c ConnectorRetirementCurrent) Clone() ConnectorRetirementCurrent {
	if c.Proof != nil {
		p := c.Proof.Clone()
		c.Proof = &p
	}
	return c
}

type ConnectorRetirementRestriction struct {
	Cause          string
	RetiringSource *audit.ConnectorRetiringSource `json:",omitempty"`
}
type ConnectorRetirementRecord struct {
	Ticket        audit.ConnectorRetirementTicket
	RestrictedAt  time.Time
	Restriction   *ConnectorRetirementRestriction
	AdmissionOpen bool
	Snapshot      *audit.OperationSnapshot
}

func (r ConnectorRetirementRecord) Valid() bool {
	t := r.Ticket
	if !t.Valid() || (r.Restriction == nil) != r.RestrictedAt.IsZero() {
		return false
	}
	if r.Restriction != nil {
		if r.RestrictedAt.Before(t.ReservedAt) || r.RestrictedAt.Nanosecond()%1000 != 0 {
			return false
		}
		switch r.Restriction.Cause {
		case audit.ConnectorRetirementExpiry:
			if r.Restriction.RetiringSource != nil || r.RestrictedAt.Before(t.AdmissionUntil) {
				return false
			}
		case audit.ConnectorRetirementExplicit:
			s := r.Restriction.RetiringSource
			if s == nil || s.CompleteDigest == (artifact.Digest{}) || !s.Revision.Valid() || s.Revision.UID != t.Behavior.UID || s.Revision.Generation <= t.Behavior.Generation {
				return false
			}
		default:
			return false
		}
	}
	if r.Snapshot == nil {
		return true
	}
	a := r.Snapshot
	in := a.Intent
	if r.Restriction == nil || !in.Valid() || in.ID != t.ID || in.RootID != t.RootID || in.Name != "connector_retirement" || in.RetirementOrigin == nil || !sameConnectorJSON(in.RetirementOrigin.Ticket, t) || in.RetirementOrigin.Cause != r.Restriction.Cause || !sameConnectorJSON(in.RetirementOrigin.RetiringSource, r.Restriction.RetiringSource) {
		return false
	}
	_, d, e := CanonicalConnectorRetirementTicket(t)
	if e != nil || in.RetirementOrigin.TicketDigest != d {
		return false
	}
	if a.IntentReceipt != nil && (!a.IntentStarted || !a.IntentReceipt.ValidOperation(in.RootID, in.ID, "intent")) {
		return false
	}
	if a.Outcome == nil {
		return !a.OutcomeStarted && a.OutcomeReceipt == nil
	}
	if !a.Outcome.Valid() || !sameConnectorJSON(a.Outcome.Intent, in) || a.Outcome.Status != "success" || a.Outcome.Effect != "accepted" || a.IntentReceipt == nil {
		return false
	}
	return a.OutcomeReceipt == nil || a.OutcomeStarted && a.OutcomeReceipt.ValidOperation(in.RootID, in.ID, "outcome")
}

// This journal uses the purpose-bound SQL role. Restrict commits its narrow
// control fence independently; Prepare consumes only the original paid ticket.
// It cannot create another ticket, choose a peer or renew a backing interval.
type ConnectorRetirementJournal interface {
	ReadConnectorRetirement(context.Context, string, ConnectorRetirementCurrent) (ConnectorRetirementRecord, error)
	RestrictConnectorRetirement(context.Context, string, string, ConnectorRetirementCurrent) (ConnectorRetirementRecord, error)
	PrepareConnectorRetirement(context.Context, ConnectorRetirementRecord, ConnectorRetirementCurrent) (ConnectorRetirementRecord, error)
	StoreConnectorRetirementOutcome(context.Context, audit.OperationOutcome, ConnectorRetirementCurrent) (ConnectorRetirementRecord, error)
}

// Restricted is a positively observed control fence. AuditAcknowledged covers
// its exact encrypted pair only; neither field claims leaf/object/row cleanup.
// A non-nil error never undoes an already observed restriction.
type ConnectorRetirementResult struct {
	TicketID                      string
	Restricted, AuditAcknowledged bool
}
type ConnectorRetirementService struct {
	RootID   string
	Recovery RecoveryReader
	Proof    ConnectorRetirementProofReader
	Journal  ConnectorRetirementJournal
	Audit    ConnectorCredentialAudit
	MAC      *auditapp.OperationMAC
	Now      func() time.Time
}

func (s ConnectorRetirementService) Expire(ctx context.Context, ticketID string) (ConnectorRetirementResult, error) {
	return s.retire(ctx, ticketID, audit.ConnectorRetirementExpiry, nil)
}
func (s ConnectorRetirementService) Retire(ctx context.Context, ticketID string, request value.ConnectorProcessRequest) (ConnectorRetirementResult, error) {
	if !request.Valid() {
		return ConnectorRetirementResult{}, value.ErrUnavailable
	}
	request.ClientCSRDER = bytes.Clone(request.ClientCSRDER)
	request.ServerCSRDER = bytes.Clone(request.ServerCSRDER)
	return s.retire(ctx, ticketID, audit.ConnectorRetirementExplicit, &request)
}
func (s ConnectorRetirementService) retire(ctx context.Context, ticketID, cause string, request *value.ConnectorProcessRequest) (ConnectorRetirementResult, error) {
	result := ConnectorRetirementResult{TicketID: ticketID}
	if ctx == nil || ctx.Err() != nil || !authorization.UUID(s.RootID) || !authorization.UUID(ticketID) || s.Recovery == nil || s.Journal == nil || s.Audit == nil || s.MAC == nil || s.Now == nil {
		return result, value.ErrUnavailable
	}
	start := s.Now().UTC().Truncate(time.Microsecond)
	until := start.Add(5 * time.Second)
	if deadline, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, deadline)
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	current := func() (ConnectorRetirementCurrent, error) {
		recovery, e := s.Recovery.RecoveryState(live)
		if e != nil {
			return ConnectorRetirementCurrent{}, value.ErrUnavailable
		}
		c := ConnectorRetirementCurrent{Recovery: recovery, ObservedAt: start, Until: identity.Earlier(until, recovery.FreshUntil)}
		if live.Err() != nil || !c.Valid(s.Now()) {
			return ConnectorRetirementCurrent{}, value.ErrUnavailable
		}
		return c, nil
	}
	c, e := current()
	if e != nil {
		return result, e
	}
	until = c.Until
	bounded, cancel := context.WithDeadline(live, until)
	defer cancel()
	live = bounded
	record, e := s.Journal.ReadConnectorRetirement(live, ticketID, c)
	valid := func(r ConnectorRetirementRecord) bool {
		return r.Valid() && r.Ticket.ID == ticketID && r.Ticket.RootID == s.RootID && r.Ticket.Binding.InstallationID == c.Recovery.InstallationID && r.Ticket.Binding.IssuerEpoch == c.Recovery.IssuerEpoch && live.Err() == nil && c.Valid(s.Now())
	}
	if e != nil || !valid(record) {
		return result, value.ErrUnavailable
	}
	if record.Restriction == nil {
		if cause == audit.ConnectorRetirementExplicit {
			if s.Proof == nil || request == nil {
				return result, value.ErrUnavailable
			}
			p, err := s.Proof.ReadConnectorRetirementProof(live, *request)
			if err != nil || p.Process.Binding != record.Ticket.Binding || p.Process != request.Process || p.Configuration.Profile.RootID != s.RootID {
				return result, value.ErrUnavailable
			}
			p = p.Clone()
			c.Proof = &p
			c.Until = identity.Earlier(c.Until, p.FreshUntil)
			until = c.Until
			narrower, close := context.WithDeadline(live, until)
			defer close()
			live = narrower
			if !c.Valid(s.Now()) || live.Err() != nil {
				return result, value.ErrUnavailable
			}
		}
		record, e = s.Journal.RestrictConnectorRetirement(live, ticketID, cause, c)
		if e != nil || !valid(record) || record.Restriction == nil {
			return result, value.ErrUnavailable
		}
	}
	result.Restricted = true
	// Once positively recorded, only the original ticket/recovery is needed to
	// finish its restrictive audit; losing the original Pod never invents a new
	// live actor or recreates a serving process.
	c, e = current()
	if e != nil {
		return result, e
	}
	until = c.Until
	bounded, cancel = context.WithDeadline(live, until)
	defer cancel()
	live = bounded
	if record.Snapshot == nil {
		if !record.AdmissionOpen || !s.Now().Before(record.Ticket.ConsumeUntil) {
			return result, value.ErrUnavailable
		}
		record, e = s.Journal.PrepareConnectorRetirement(live, record, c)
		if e != nil || !valid(record) || record.Snapshot == nil {
			return result, value.ErrUnavailable
		}
	}
	snap := record.Snapshot
	if snap.OutcomeReceipt == nil {
		if !s.Now().Before(snap.Intent.WriteUntil) {
			return result, value.ErrUnavailable
		}
		if snap.IntentReceipt == nil {
			if e = s.Audit.Begin(live, snap.Intent); e != nil {
				return result, e
			}
		}
		if live.Err() != nil || !c.Valid(s.Now()) {
			return result, value.ErrUnavailable
		}
		var out audit.OperationOutcome
		if snap.Outcome != nil {
			out = *snap.Outcome
		} else {
			payload, err := json.Marshal(struct {
				TicketID     string
				RestrictedAt time.Time
			}{ticketID, record.RestrictedAt})
			if err != nil {
				return result, value.ErrUnavailable
			}
			digest, err := s.MAC.Digest("connector-result/v1", payload)
			if err != nil {
				return result, err
			}
			out = audit.OperationOutcome{Intent: snap.Intent, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: digest, OutputBytes: int64(len(payload)), MetadataUntil: identity.Earlier(snap.Intent.RequestUntil, c.Until), RecordedAt: s.Now().UTC().Truncate(time.Microsecond)}
		}
		if !out.Valid() {
			return result, value.ErrUnavailable
		}
		if snap.Outcome == nil {
			c, e = current()
			if e != nil {
				return result, e
			}
			until = c.Until
			out.MetadataUntil = identity.Earlier(out.MetadataUntil, c.Until)
			if !out.Valid() {
				return result, value.ErrUnavailable
			}
			storedContext, stopStore := context.WithDeadline(live, until)
			defer stopStore()
			live = storedContext
			stored, err := s.Journal.StoreConnectorRetirementOutcome(live, out, c)
			if err != nil || !valid(stored) || stored.Snapshot == nil || stored.Snapshot.Outcome == nil || !sameConnectorJSON(*stored.Snapshot.Outcome, out) {
				return result, value.ErrUnavailable
			}
		}
		if live.Err() != nil || !c.Valid(s.Now()) {
			return result, value.ErrUnavailable
		}
		if e = s.Audit.Finish(live, out); e != nil {
			return result, e
		}
	}
	c, e = current()
	if e != nil {
		return result, e
	}
	until = c.Until
	bounded, cancel = context.WithDeadline(live, until)
	defer cancel()
	live = bounded
	final, e := s.Journal.ReadConnectorRetirement(live, ticketID, c)
	if e != nil || !valid(final) || final.Snapshot == nil || final.Snapshot.OutcomeReceipt == nil || !sameConnectorJSON(final.Snapshot.Intent, snap.Intent) {
		return result, value.ErrUnavailable
	}
	result.AuditAcknowledged = true
	return result, nil
}
