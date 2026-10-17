package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InitialInstallationReader has only SELECT credentials. Historical completion
// is readable after the original claim/Pod expires, including while recovery is
// blocked. Neither absence nor an old success supplies activation authority.
type InitialInstallationReader struct {
	ledger    *Ledger
	scope     value.InstallationWitnessScope
	plan      artifact.Digest
	authority app.InitialInstallationReadAuthority
	now       func() time.Time
}

var _ app.InitialInstallationHistory = (*InitialInstallationReader)(nil)

func NewInitialInstallationReader(ctx context.Context, pool *pgxpool.Pool, scope value.InstallationWitnessScope, plan artifact.Digest, authority app.InitialInstallationReadAuthority) (*InitialInstallationReader, error) {
	if ctx == nil || !scope.Valid() || plan == (artifact.Digest{}) || authority == nil {
		return nil, value.ErrInvalid
	}
	ledger, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &InitialInstallationReader{ledger: ledger, scope: scope, plan: plan, authority: authority, now: time.Now}, nil
}

func strictInitialHistoryJSON(raw []byte, out any) bool {
	if len(raw) == 0 || len(raw) > 8192 {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return false
	}
	return errors.Is(d.Decode(new(any)), io.EOF)
}

func initialInstallationObservation(raw, receipt []byte, at pgtype.Timestamptz, scope value.InstallationWitnessScope, plan artifact.Digest) (app.InitialInstallationObservation, error) {
	var out app.InitialInstallationObservation
	var r audit.InitialInstallation
	if !strictInitialHistoryJSON(raw, &r) || !r.Valid() || r.Scope != scope || r.Claim.PlanDigest != plan {
		return out, value.ErrDenied
	}
	out.Disposition = app.InitialInstallationPrepared
	out.Record = &r
	if receipt != nil {
		var ack audit.Receipt
		if !strictInitialHistoryJSON(receipt, &ack) || !ack.ValidInitialInstallation(scope.InstallationID, r.Claim.ID) {
			return app.InitialInstallationObservation{}, value.ErrDenied
		}
		out.Disposition = app.InitialInstallationAudited
		out.AuditReceipt = &ack
	}
	if at.Valid {
		if out.AuditReceipt == nil || at.InfinityModifier != pgtype.Finite || at.Time.Before(r.Claim.NotBefore) || !at.Time.Before(r.Claim.NotAfter) || at.Time.Nanosecond()%1000 != 0 {
			return app.InitialInstallationObservation{}, value.ErrDenied
		}
		out.Disposition = app.InitialInstallationActivated
		out.ActivatedAt = at.Time
	}
	return out, nil
}

func (s *InitialInstallationReader) ObserveInitialInstallation(ctx context.Context) (app.InitialInstallationObservation, error) {
	var zero app.InitialInstallationObservation
	if s == nil || s.ledger == nil || s.authority == nil || s.now == nil || ctx == nil {
		return zero, value.ErrInvalid
	}
	start := s.now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer cancel()
	until, err := s.authority.CheckInitialInstallationRead(ctx, s.scope, s.plan)
	if err != nil {
		return zero, err
	}
	until = identity.Earlier(until, start.Add(5*time.Second))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if until.IsZero() || ctx.Err() != nil || !s.now().Before(until) {
		return zero, value.ErrUnavailable
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	// One MVCC SELECT: no row lock, new attempt, witness read/consume or mutation.
	var raw, receipt []byte
	var at pgtype.Timestamptz
	var claimID pgtype.UUID
	err = s.ledger.pool.QueryRow(ctx, `SELECT record_json,audit_receipt_json,activated_at,claim_id
 FROM public.fleet_initial_activation WHERE installation_id=$1`, s.scope.InstallationID).Scan(&raw, &receipt, &at, &claimID)
	var out app.InitialInstallationObservation
	if errors.Is(err, pgx.ErrNoRows) {
		out.Disposition = app.InitialInstallationMissing
	} else if err != nil {
		return zero, value.ErrUnavailable
	} else if out, err = initialInstallationObservation(raw, receipt, at, s.scope, s.plan); err != nil {
		return zero, err
	} else if out.Record.Claim.ID != uid(claimID) {
		return zero, value.ErrDenied
	}
	// Final current checks can shorten, never replace the first deadline.
	final, err := s.authority.CheckInitialInstallationRead(ctx, s.scope, s.plan)
	until = identity.Earlier(until, final)
	if err != nil || until.IsZero() || ctx.Err() != nil || !s.now().Before(until) {
		return zero, value.ErrUnavailable
	}
	out.ValidUntil = until
	return out, nil
}
