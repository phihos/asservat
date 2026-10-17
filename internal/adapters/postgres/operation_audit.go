package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// Each lane is composed with its own bounded SQL pool and provider clients so
// ordinary poll traffic cannot occupy all protected resolution resources.
// Journal and acknowledgements use separate roles; neither provisions backing.
type OperationJournal struct {
	ledger     *Ledger
	root, lane string
	recovery   *RecoveryTransactionGuard
	lifecycle  *audit.OperationLifecyclePolicy
}
type OperationAcknowledgements struct{ journal *OperationJournal }

var _ app.OperationJournal = (*OperationJournal)(nil)
var _ app.OperationAcknowledgements = (*OperationAcknowledgements)(nil)

func NewOperationJournal(ctx context.Context, pool *pgxpool.Pool, root, lane string, recovery *RecoveryTransactionGuard) (*OperationJournal, error) {
	if !authorization.UUID(root) || (lane != "normal" && lane != "resolution") || recovery == nil || recovery.root != root {
		return nil, app.ErrUnavailable
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, app.ErrUnavailable
	}
	return &OperationJournal{ledger: l, root: root, lane: lane, recovery: recovery}, nil
}
func NewOperationAcknowledgements(ctx context.Context, pool *pgxpool.Pool, root, lane string, recovery *RecoveryTransactionGuard) (*OperationAcknowledgements, error) {
	j, err := NewOperationJournal(ctx, pool, root, lane, recovery)
	if err != nil {
		return nil, app.ErrUnavailable
	}
	return &OperationAcknowledgements{j}, nil
}
func (s *OperationJournal) valid(in audit.OperationIntent) bool {
	return s != nil && s.ledger != nil && s.recovery != nil && in.Valid() && in.RootID == s.root && audit.OperationLane(in.Name) == s.lane
}

// Recovery is read from the accepted SQL projection, locked before the journal.
// These are audit effects only. It supplies no human/capture authority, and new
// writes cannot cross the original database/issuer incarnation after restore.
func (s *OperationJournal) trust(ctx context.Context, q *custodydb.Queries) (custodydb.FleetCurrentTrust, time.Time, error) {
	start, e := q.CurrentTime(ctx)
	if e != nil {
		return custodydb.FleetCurrentTrust{}, time.Time{}, e
	}
	row, e := q.ShareFleetTrust(ctx, id(s.recovery.installation))
	if e != nil {
		return row, time.Time{}, e
	}
	now, e := q.CurrentTime(ctx)
	if e != nil {
		return row, start.Time, e
	}
	_, e = recoveryState(row, start.Time, now.Time)
	return row, start.Time, e
}
func auditRow(row custodydb.OperationAudit, in audit.OperationIntent) (audit.OperationSnapshot, error) {
	var out audit.OperationSnapshot
	if json.Unmarshal(row.Intent, &out.Intent) != nil || !sameAuditJSON(out.Intent, in) || uid(row.ID) != in.ID || uid(row.RootID) != in.RootID || row.Lane != audit.OperationLane(in.Name) || !bytes.Equal(row.PrincipalDigest, in.PrincipalDigest[:]) || !row.RequestUntil.Time.Equal(in.RequestUntil) || !row.WriteUntil.Time.Equal(in.WriteUntil) || !row.RetainUntil.Time.Equal(in.RetainUntil) {
		return out, app.ErrUnavailable
	}
	out.IntentStarted = row.IntentStarted
	out.OutcomeStarted = row.OutcomeStarted
	if len(row.IntentReceipt) > 0 {
		var v audit.Receipt
		if json.Unmarshal(row.IntentReceipt, &v) != nil || !v.ValidOperation(in.RootID, in.ID, "intent") {
			return out, app.ErrUnavailable
		}
		out.IntentReceipt = &v
	}
	if len(row.Outcome) > 0 {
		var v audit.OperationOutcome
		if json.Unmarshal(row.Outcome, &v) != nil || !v.Valid() || !sameAuditJSON(v.Intent, in) {
			return out, app.ErrUnavailable
		}
		out.Outcome = &v
	}
	if len(row.OutcomeReceipt) > 0 {
		var v audit.Receipt
		if json.Unmarshal(row.OutcomeReceipt, &v) != nil || !v.ValidOperation(in.RootID, in.ID, "outcome") {
			return out, app.ErrUnavailable
		}
		out.OutcomeReceipt = &v
	}
	return out, nil
}
func sameAuditJSON(a, b any) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && bytes.Equal(x, y)
}
func auditCurrent(ctx context.Context, q *custodydb.Queries, trust custodydb.FleetCurrentTrust, start, until time.Time) error {
	now, e := q.CurrentTime(ctx)
	if e != nil {
		return e
	}
	if ctx.Err() != nil || !now.Time.Before(until) {
		return app.ErrUnavailable
	}
	_, e = recoveryState(trust, start, now.Time)
	return e
}
func (s *OperationJournal) ReserveOperation(ctx context.Context, in audit.OperationIntent) (audit.OperationSnapshot, error) {
	var out audit.OperationSnapshot
	if !s.valid(in) || ctx == nil || ctx.Err() != nil {
		return out, app.ErrUnavailable
	}
	if (in.Lifecycle == nil) != (s.lifecycle == nil) || in.Lifecycle != nil && !sameAuditJSON(in.Lifecycle.Policy, *s.lifecycle) {
		return out, app.ErrUnavailable
	}
	b, e := json.Marshal(in)
	if e != nil || len(b) > 8<<10 {
		return out, app.ErrUnavailable
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := s.trust(ctx, q)
		if e != nil {
			return e
		}
		pool, e := q.LockOperationAuditPool(ctx, custodydb.LockOperationAuditPoolParams{RootID: id(s.root), Lane: s.lane})
		if e != nil {
			return e
		}
		row, e := q.LockOperationAudit(ctx, custodydb.LockOperationAuditParams{ID: id(in.ID), RootID: id(s.root)})
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		reservationUntil := in.RequestUntil
		if errors.Is(e, pgx.ErrNoRows) {
			// A new record retains its original backing deadline after INSERT,
			// including waits in the per-principal charging trigger. Exact
			// historical replay does not acquire a new backing entitlement.
			reservationUntil = identity.Earlier(reservationUntil, pool.ValidUntil.Time)
			if in.Lifecycle != nil {
				policy := in.Lifecycle.Policy
				reservationUntil = identity.Earlier(reservationUntil, policy.ValidUntil)
				if policy.InstallationID != s.recovery.installation || policy.BackingRevision != pool.Revision || policy.MetadataSlots < pool.AccountLimit*pool.RecordsPerAccount {
					return app.ErrUnavailable
				}
			}
			if pool.Paused || pool.AccountVersion != in.AccountVersion || !in.CreatedAt.Before(pool.ValidUntil.Time) || in.RetainUntil.After(in.CreatedAt.Add(time.Duration(pool.RetainedSeconds)*time.Second)) {
				return app.ErrUnavailable
			}
			if e = auditCurrent(ctx, q, trust, start, reservationUntil); e != nil {
				return e
			}
			row, e = q.InsertOperationAudit(ctx, custodydb.InsertOperationAuditParams{ID: id(in.ID), RootID: id(s.root), Lane: s.lane, PrincipalDigest: in.PrincipalDigest[:], Intent: b, RequestUntil: ts(in.RequestUntil), WriteUntil: ts(in.WriteUntil), RetainUntil: ts(in.RetainUntil), IssuerEpoch: trust.IssuerEpoch})
			if e != nil {
				return e
			}
		}
		if row.IssuerEpoch != trust.IssuerEpoch {
			return app.ErrUnavailable
		}
		out, e = auditRow(row, in)
		if e != nil {
			return e
		}
		return auditCurrent(ctx, q, trust, start, reservationUntil)
	})
	if err != nil || ctx.Err() != nil {
		return audit.OperationSnapshot{}, app.ErrUnavailable
	}
	return out, nil
}
func (s *OperationJournal) ClaimOperationWrite(ctx context.Context, in audit.OperationIntent, phase string) (bool, error) {
	if !s.valid(in) || ctx == nil || (phase != "intent" && phase != "outcome") {
		return false, app.ErrUnavailable
	}
	fresh := false
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		fresh = false
		trust, start, e := s.trust(ctx, q)
		if e != nil {
			return e
		}
		row, e := q.LockOperationAudit(ctx, custodydb.LockOperationAuditParams{ID: id(in.ID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		snap, e := auditRow(row, in)
		if e != nil || row.IssuerEpoch != trust.IssuerEpoch {
			return app.ErrUnavailable
		}
		until := in.WriteUntil
		if phase == "intent" {
			until = in.RequestUntil
		}
		if e = auditCurrent(ctx, q, trust, start, until); e != nil {
			return e
		}
		var n int64
		if phase == "intent" {
			if !snap.IntentStarted {
				n, e = q.ClaimOperationIntent(ctx, custodydb.ClaimOperationIntentParams{ID: id(in.ID), RootID: id(s.root)})
			}
		} else {
			if snap.Outcome == nil || snap.IntentReceipt == nil {
				return app.ErrUnavailable
			}
			if !snap.OutcomeStarted {
				n, e = q.ClaimOperationOutcome(ctx, custodydb.ClaimOperationOutcomeParams{ID: id(in.ID), RootID: id(s.root)})
			}
		}
		if e != nil {
			return e
		}
		fresh = n == 1
		return auditCurrent(ctx, q, trust, start, until)
	})
	if err != nil || ctx.Err() != nil {
		return false, app.ErrUnavailable
	}
	return fresh, nil
}
func (s *OperationJournal) FreezeOperationOutcome(ctx context.Context, in audit.OperationOutcome) (audit.OperationSnapshot, error) {
	var out audit.OperationSnapshot
	if !s.valid(in.Intent) || !in.Valid() || ctx == nil {
		return out, app.ErrUnavailable
	}
	b, e := json.Marshal(in)
	if e != nil || len(b) > 16<<10 {
		return out, app.ErrUnavailable
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := s.trust(ctx, q)
		if e != nil {
			return e
		}
		row, e := q.LockOperationAudit(ctx, custodydb.LockOperationAuditParams{ID: id(in.Intent.ID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		out, e = auditRow(row, in.Intent)
		if e != nil || row.IssuerEpoch != trust.IssuerEpoch || out.IntentReceipt == nil {
			return app.ErrUnavailable
		}
		if e = auditCurrent(ctx, q, trust, start, in.Intent.WriteUntil); e != nil {
			return e
		}
		if out.Outcome != nil {
			if !sameAuditJSON(*out.Outcome, in) {
				return app.ErrUnavailable
			}
		} else {
			row, e = q.FreezeOperationOutcome(ctx, custodydb.FreezeOperationOutcomeParams{ID: id(in.Intent.ID), RootID: id(s.root), Outcome: b})
			if e != nil {
				return e
			}
			out, e = auditRow(row, in.Intent)
			if e != nil {
				return e
			}
		}
		return auditCurrent(ctx, q, trust, start, in.Intent.WriteUntil)
	})
	if err != nil || ctx.Err() != nil {
		return audit.OperationSnapshot{}, app.ErrUnavailable
	}
	return out, nil
}
func (s *OperationAcknowledgements) AcknowledgeOperation(ctx context.Context, in audit.OperationIntent, phase string, receipt audit.Receipt) error {
	if s == nil || !s.journal.valid(in) || ctx == nil || !receipt.ValidOperation(in.RootID, in.ID, phase) {
		return app.ErrUnavailable
	}
	j := s.journal
	b, e := json.Marshal(receipt)
	if e != nil || len(b) > 4096 {
		return app.ErrUnavailable
	}
	err := j.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := j.trust(ctx, q)
		if e != nil {
			return e
		}
		row, e := q.LockOperationAudit(ctx, custodydb.LockOperationAuditParams{ID: id(in.ID), RootID: id(j.root)})
		if e != nil {
			return e
		}
		snap, e := auditRow(row, in)
		if e != nil || row.IssuerEpoch != trust.IssuerEpoch {
			return app.ErrUnavailable
		}
		if e = auditCurrent(ctx, q, trust, start, in.WriteUntil); e != nil {
			return e
		}
		var n int64
		if phase == "intent" {
			if snap.IntentReceipt != nil {
				if !sameAuditJSON(*snap.IntentReceipt, receipt) {
					return app.ErrUnavailable
				}
				return nil
			}
			n, e = q.AckOperationIntent(ctx, custodydb.AckOperationIntentParams{ID: id(in.ID), RootID: id(j.root), IntentReceipt: b})
		} else {
			if snap.OutcomeReceipt != nil {
				if !sameAuditJSON(*snap.OutcomeReceipt, receipt) {
					return app.ErrUnavailable
				}
				return nil
			}
			n, e = q.AckOperationOutcome(ctx, custodydb.AckOperationOutcomeParams{ID: id(in.ID), RootID: id(j.root), OutcomeReceipt: b})
		}
		if e != nil || n != 1 {
			return app.ErrUnavailable
		}
		return auditCurrent(ctx, q, trust, start, in.WriteUntil)
	})
	if err != nil || ctx.Err() != nil {
		return app.ErrUnavailable
	}
	return nil
}

// ProvisionOperationAuditPool is called only by protected configuration
// composition with a separate SQL credential; it is not a public admin API.
func (l *Ledger) ProvisionOperationAuditPool(ctx context.Context, in app.OperationAuditPool) error {
	if in.Lane != "normal" && in.Lane != "resolution" {
		return app.ErrUnavailable
	}
	return l.provisionOperationAuditPool(ctx, in)
}

func (l *Ledger) provisionOperationAuditPool(ctx context.Context, in app.OperationAuditPool) error {
	if l == nil || ctx == nil || !authorization.UUID(in.RootID) || (in.Lane != "normal" && in.Lane != "resolution" && in.Lane != "processing") || !identity.Text(in.AccountVersion, 64) || in.ExpectedRevision < 0 || in.ExpectedRevision > 1<<60 || in.Accounts < 1 || in.Accounts > 1000000 || in.RecordsPerAccount < 1 || in.RecordsPerAccount > 1000000 || in.RetainedSeconds < 60 || in.RetainedSeconds > 316224000 || !identity.Fresh(in.ObservedAt, in.FreshUntil, in.ObservedAt, 5*time.Second) || !in.ValidUntil.After(in.ObservedAt) {
		return app.ErrUnavailable
	}
	err := l.transaction(ctx, func(q *custodydb.Queries) error {
		if _, e := q.LockPermissionStream(ctx, id(in.RootID)); e != nil {
			return e
		}
		old, e := q.LockOperationAuditPool(ctx, custodydb.LockOperationAuditPoolParams{RootID: id(in.RootID), Lane: in.Lane})
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		missing := errors.Is(e, pgx.ErrNoRows)
		if !missing && old.Revision == in.ExpectedRevision+1 {
			if old.AccountVersion != in.AccountVersion || old.AccountLimit != in.Accounts || old.RecordsPerAccount != in.RecordsPerAccount || old.RetainedSeconds != in.RetainedSeconds || old.Paused != in.Paused || !old.ValidUntil.Time.Equal(in.ValidUntil) {
				return app.ErrUnavailable
			}
			now, e := q.CurrentTime(ctx)
			if e != nil || !identity.Fresh(in.ObservedAt, in.FreshUntil, now.Time, 5*time.Second) || !now.Time.Before(in.ValidUntil) {
				return app.ErrUnavailable
			}
			return ctx.Err()
		}
		if missing && in.ExpectedRevision != 0 || !missing && (old.Revision != in.ExpectedRevision || old.AccountVersion != in.AccountVersion || old.Accounts > in.Accounts) {
			return app.ErrUnavailable
		}
		check := func() error {
			now, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			if !identity.Fresh(in.ObservedAt, in.FreshUntil, now.Time, 5*time.Second) || !now.Time.Before(in.ValidUntil) {
				return app.ErrUnavailable
			}
			return ctx.Err()
		}
		if e = check(); e != nil {
			return e
		}
		if missing {
			e = q.InsertOperationAuditPool(ctx, custodydb.InsertOperationAuditPoolParams{RootID: id(in.RootID), Lane: in.Lane, AccountVersion: in.AccountVersion, ValidUntil: ts(in.ValidUntil), AccountLimit: in.Accounts, RecordsPerAccount: in.RecordsPerAccount, RetainedSeconds: in.RetainedSeconds, Paused: in.Paused})
		} else {
			var n int64
			n, e = q.ConfigureOperationAuditPool(ctx, custodydb.ConfigureOperationAuditPoolParams{RootID: id(in.RootID), Lane: in.Lane, ExpectedRevision: in.ExpectedRevision, RecordsPerAccount: in.RecordsPerAccount, ValidUntil: ts(in.ValidUntil), AccountLimit: in.Accounts, RetainedSeconds: in.RetainedSeconds, Paused: in.Paused})
			if e == nil && n != 1 {
				return app.ErrUnavailable
			}
		}
		if e != nil {
			return e
		}
		return check()
	})
	if err != nil {
		return app.ErrUnavailable
	}
	return nil
}

// The optional lifecycle can only be selected by accepted private composition.
// Legacy construction rejects lifecycle-bearing admission; exact later reads
// and acknowledgements still consume the immutable stored binding.
func NewHealthyOperationJournal(ctx context.Context, pool *pgxpool.Pool, policy audit.OperationLifecyclePolicy, recovery *RecoveryTransactionGuard) (*OperationJournal, error) {
	if !policy.CertificateVerificationBacked() || recovery == nil || policy.InstallationID != recovery.installation {
		return nil, app.ErrUnavailable
	}
	j, e := NewOperationJournal(ctx, pool, policy.RootID, policy.Lane, recovery)
	if e != nil {
		return nil, e
	}
	if policy.History != nil {
		q := *policy.History
		policy.History = &q
	}
	j.lifecycle = &policy
	return j, nil
}
