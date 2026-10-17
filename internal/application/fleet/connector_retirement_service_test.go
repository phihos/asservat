package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Every authority/storage port here is explicitly synthetic. Native SQL must
// separately establish that paid reservations, roles and locks enforce them.
type retirementServiceFixture struct {
	now                                           time.Time
	record                                        ConnectorRetirementRecord
	mac                                           *auditapp.OperationMAC
	recoveryUntil                                 time.Time
	denyRecovery                                  bool
	restricts, prepares, begins, stores, finishes int
	loseRestriction, losePreparation, loseStore   bool
	auditFailure, finishUnavailable               bool
	prepareHook                                   func(context.Context)
	storeHook                                     func(context.Context)
	finishHook                                    func()
}

func retirementService(t *testing.T) (*retirementServiceFixture, ConnectorRetirementService) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := connectorTicketPlan(t)
	p.AcceptanceCreatedAt = now.Add(-1801 * time.Second)
	p.AcceptanceRetainUntil = p.AcceptanceCreatedAt.Add(2100 * time.Second)
	p.AcceptancePurgeAt = p.AcceptanceCreatedAt.Add(1860 * time.Second)
	p.Backing.Policy.ValidUntil = p.AcceptanceCreatedAt.Add(1800 * time.Second)
	ticket, e := p.Ticket()
	if e != nil {
		t.Fatal(e)
	}
	f := &retirementServiceFixture{now: now, record: ConnectorRetirementRecord{Ticket: ticket, AdmissionOpen: true}, mac: retirementMAC(t, ticket.AccountVersion)}
	s := ConnectorRetirementService{RootID: ticket.RootID, Recovery: f, Journal: f, Audit: f, MAC: f.mac, Now: func() time.Time { return f.now }}
	return f, s
}
func (f *retirementServiceFixture) RecoveryState(context.Context) (value.RecoveryState, error) {
	if f.denyRecovery {
		return value.RecoveryState{}, value.ErrUnavailable
	}
	until := f.now.Add(5 * time.Second)
	if !f.recoveryUntil.IsZero() && f.recoveryUntil.Before(until) {
		until = f.recoveryUntil
	}
	return value.RecoveryState{InstallationID: f.record.Ticket.Binding.InstallationID, IssuerEpoch: f.record.Ticket.Binding.IssuerEpoch, Revision: f.record.Ticket.Behavior, ObservedAt: f.now, FreshUntil: until}, nil
}
func (f *retirementServiceFixture) ReadConnectorRetirement(context.Context, string, ConnectorRetirementCurrent) (ConnectorRetirementRecord, error) {
	return f.record, nil
}
func (f *retirementServiceFixture) RestrictConnectorRetirement(_ context.Context, _ string, cause string, _ ConnectorRetirementCurrent) (ConnectorRetirementRecord, error) {
	f.restricts++
	f.record.RestrictedAt = f.now
	f.record.Restriction = &ConnectorRetirementRestriction{Cause: cause}
	if f.loseRestriction {
		f.loseRestriction = false
		return ConnectorRetirementRecord{}, errors.New("synthetic lost restrictive commit reply")
	}
	return f.record, nil
}
func (f *retirementServiceFixture) PrepareConnectorRetirement(ctx context.Context, r ConnectorRetirementRecord, c ConnectorRetirementCurrent) (ConnectorRetirementRecord, error) {
	f.prepares++
	if f.prepareHook != nil {
		f.prepareHook(ctx)
	}
	if f.record.Snapshot == nil {
		in, e := ConnectorRetirementIntent(r.Ticket, r.Restriction.Cause, r.Restriction.RetiringSource, r.Ticket.ID, c.ObservedAt, c.Until, f.mac)
		if e != nil {
			return ConnectorRetirementRecord{}, e
		}
		f.record.Snapshot = &audit.OperationSnapshot{Intent: in}
	}
	if f.losePreparation {
		f.losePreparation = false
		return ConnectorRetirementRecord{}, errors.New("synthetic lost original admission reply")
	}
	return f.record, nil
}
func (f *retirementServiceFixture) Begin(_ context.Context, in audit.OperationIntent) error {
	f.begins++
	if f.auditFailure {
		return errors.New("synthetic audit unavailable")
	}
	r := audit.Receipt{Key: audit.OperationAuditKey(in.RootID, in.ID, "intent"), ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{11}}
	f.record.Snapshot.IntentStarted = true
	f.record.Snapshot.IntentReceipt = &r
	return nil
}
func (f *retirementServiceFixture) StoreConnectorRetirementOutcome(ctx context.Context, out audit.OperationOutcome, _ ConnectorRetirementCurrent) (ConnectorRetirementRecord, error) {
	f.stores++
	if f.storeHook != nil {
		f.storeHook(ctx)
	}
	f.record.Snapshot.Outcome = &out
	if f.loseStore {
		f.loseStore = false
		return ConnectorRetirementRecord{}, errors.New("synthetic lost business outcome reply")
	}
	return f.record, nil
}
func (f *retirementServiceFixture) Finish(_ context.Context, out audit.OperationOutcome) error {
	if f.record.Snapshot.Outcome == nil || !sameConnectorJSON(*f.record.Snapshot.Outcome, out) {
		return errors.New("exact business outcome not frozen before provider work")
	}
	f.finishes++
	if f.finishUnavailable {
		f.finishUnavailable = false
		return errors.New("synthetic outcome service unavailable before provider admission")
	}
	f.record.Snapshot.OutcomeStarted = true
	r := audit.Receipt{Key: audit.OperationAuditKey(out.Intent.RootID, out.Intent.ID, "outcome"), ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{12}}
	f.record.Snapshot.OutcomeReceipt = &r
	if f.finishHook != nil {
		f.finishHook()
	}
	return nil
}
func TestConnectorRetirementExpiryUsesOriginalTicketWithoutLiveActor(t *testing.T) {
	f, s := retirementService(t)
	original := f.record.Ticket.Clone()
	result, e := s.Expire(context.Background(), original.ID)
	if e != nil || !result.Restricted || !result.AuditAcknowledged || f.restricts != 1 || f.prepares != 1 || f.begins != 1 || f.finishes != 1 {
		t.Fatalf("bounded retirement: %+v %v counts %d/%d/%d/%d", result, e, f.restricts, f.prepares, f.begins, f.finishes)
	}
	in := f.record.Snapshot.Intent
	if !sameConnectorJSON(original, f.record.Ticket) || in.Process != nil || in.Peer != nil || in.RetirementOrigin == nil || !in.Lifecycle.OriginalPurgeAt.Equal(original.OriginalPurgeAt()) || !in.RetainUntil.Equal(original.RetainUntil) {
		t.Fatal("retirement fabricated a live actor or shifted original dates")
	}
	f.now = f.now.Add(6 * time.Second)
	result, e = s.Expire(context.Background(), original.ID)
	if e != nil || !result.AuditAcknowledged || f.restricts != 1 || f.prepares != 1 || f.begins != 1 || f.finishes != 1 {
		t.Fatal("acknowledged replay repeated effects", result, e)
	}
}
func TestConnectorRetirementUnknownCommitsKeepOriginalTicket(t *testing.T) {
	for _, which := range []string{"restriction", "admission", "business outcome"} {
		t.Run(which, func(t *testing.T) {
			f, s := retirementService(t)
			f.loseRestriction = which == "restriction"
			f.losePreparation = which == "admission"
			f.loseStore = which == "business outcome"
			first, e := s.Expire(context.Background(), f.record.Ticket.ID)
			if e == nil || first.AuditAcknowledged {
				t.Fatal("lost reply became success")
			}
			var original *audit.OperationIntent
			if f.record.Snapshot != nil {
				v := f.record.Snapshot.Intent
				original = &v
			}
			f.now = f.now.Add(time.Second)
			next, e := s.Expire(context.Background(), f.record.Ticket.ID)
			if e != nil || !next.Restricted || !next.AuditAcknowledged || f.restricts != 1 || f.prepares != 1 || f.begins != 1 || f.finishes != 1 {
				t.Fatal("same-ticket reconciliation repeated admission", next, e)
			}
			if original != nil && !sameConnectorJSON(*original, f.record.Snapshot.Intent) {
				t.Fatal("unknown original admission got new dates or identity")
			}
		})
	}
}
func TestConnectorRetirementAuditFailureKeepsRestrictionExplicit(t *testing.T) {
	f, s := retirementService(t)
	f.auditFailure = true
	result, e := s.Expire(context.Background(), f.record.Ticket.ID)
	if e == nil || !result.Restricted || result.AuditAcknowledged || f.record.Restriction == nil || f.record.Snapshot == nil || f.finishes != 0 {
		t.Fatal("audit failure erased fence or claimed completion", result, e)
	}
}
func TestConnectorRetirementLateRestrictionStartsNoAudit(t *testing.T) {
	f, s := retirementService(t)
	f.now = f.record.Ticket.ConsumeUntil.Add(time.Second)
	f.record.AdmissionOpen = false
	result, e := s.Expire(context.Background(), f.record.Ticket.ID)
	if e == nil || !result.Restricted || result.AuditAcknowledged || f.restricts != 1 || f.prepares != 0 || f.begins != 0 || f.finishes != 0 {
		t.Fatal("expired paid writer was renewed", result, e)
	}
}
func TestConnectorRetirementPreparationCannotOutliveShortenedRecovery(t *testing.T) {
	f, s := retirementService(t)
	f.recoveryUntil = f.now.Add(100 * time.Millisecond)
	f.prepareHook = func(ctx context.Context) {
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(f.recoveryUntil) {
			t.Error("preparation lost shortened original deadline", deadline)
		}
		f.now = f.recoveryUntil
	}
	result, e := s.Expire(context.Background(), f.record.Ticket.ID)
	if e == nil || !result.Restricted || result.AuditAcknowledged || f.begins != 0 || f.finishes != 0 {
		t.Fatal("provider work began after shortened proof expired", result, e)
	}
}
func TestConnectorRetirementKnownRecoveryLossBlocksFinalAcknowledgement(t *testing.T) {
	f, s := retirementService(t)
	f.finishHook = func() { f.denyRecovery = true }
	result, e := s.Expire(context.Background(), f.record.Ticket.ID)
	if e == nil || !result.Restricted || result.AuditAcknowledged || f.finishes != 1 {
		t.Fatal("final known recovery loss ignored", result, e)
	}
}

func TestConnectorRetirementStoresExactBusinessOutcomeBeforeAudit(t *testing.T) {
	f, s := retirementService(t)
	result, err := s.Expire(context.Background(), f.record.Ticket.ID)
	if err != nil || !result.AuditAcknowledged || f.stores != 1 || f.finishes != 1 {
		t.Fatal("business outcome not frozen exactly once before outcome writer", result, err, f.stores, f.finishes)
	}
}
func TestConnectorRetirementStoredOutcomeCannotExtendShortenedProof(t *testing.T) {
	f, s := retirementService(t)
	f.recoveryUntil = f.now.Add(100 * time.Millisecond)
	f.storeHook = func(ctx context.Context) {
		d, ok := ctx.Deadline()
		if !ok || !d.Equal(f.recoveryUntil) {
			t.Error("Store lost original shortened deadline", d)
		}
		f.now = f.recoveryUntil
	}
	result, err := s.Expire(context.Background(), f.record.Ticket.ID)
	if err == nil || !result.Restricted || result.AuditAcknowledged || f.stores != 1 || f.finishes != 0 {
		t.Fatal("outcome provider started after current proof expired", result, err)
	}
}

func TestConnectorRetirementUnknownStoredOutcomeCannotRenewWriter(t *testing.T) {
	f, s := retirementService(t)
	f.loseStore = true
	first, err := s.Expire(context.Background(), f.record.Ticket.ID)
	if err == nil || !first.Restricted || first.AuditAcknowledged || f.record.Snapshot == nil || f.record.Snapshot.Outcome == nil {
		t.Fatal("lost stored outcome was not retained as uncertain", first, err)
	}
	original := f.record.Snapshot.Intent
	f.now = original.WriteUntil
	second, err := s.Expire(context.Background(), f.record.Ticket.ID)
	if err == nil || !second.Restricted || second.AuditAcknowledged || f.stores != 1 || f.begins != 1 || f.finishes != 0 || !sameConnectorJSON(original, f.record.Snapshot.Intent) {
		t.Fatal("expired uncertain writer was restarted", second, err)
	}
}

func TestConnectorRetirementRetryAfterStoredOutcomeKeepsOriginalRecord(t *testing.T) {
	f, s := retirementService(t)
	f.finishUnavailable = true
	first, err := s.Expire(context.Background(), f.record.Ticket.ID)
	if err == nil || !first.Restricted || first.AuditAcknowledged || f.record.Snapshot.Outcome == nil {
		t.Fatal("provider outage lost committed business outcome", first, err)
	}
	original := *f.record.Snapshot.Outcome
	f.now = f.now.Add(6 * time.Second)
	second, err := s.Expire(context.Background(), f.record.Ticket.ID)
	if err != nil || !second.AuditAcknowledged || f.stores != 1 || f.prepares != 1 || f.begins != 1 || f.finishes != 2 || !sameConnectorJSON(original, *f.record.Snapshot.Outcome) {
		t.Fatal("retry renewed or replaced original stored outcome", second, err)
	}
}
