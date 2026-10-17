package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Stop, audit acknowledgement and configuration use separate role-bound pools.
// This safe-stop facet does not read catalog/native metadata or current permits.
type DownloadStops struct {
	ledger   *Ledger
	root     string
	recovery *RecoveryTransactionGuard
}

func NewDownloadStops(ctx context.Context, pool *pgxpool.Pool, root string, guards ...*RecoveryTransactionGuard) (*DownloadStops, error) {
	if !authorization.UUID(root) || len(guards) > 1 || len(guards) == 1 && (guards[0] == nil || guards[0].root != root) {
		return nil, artifact.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	out := &DownloadStops{ledger: l, root: root}
	if len(guards) == 1 {
		out.recovery = guards[0]
	}
	return out, nil
}
func stopSnapshot(row custodydb.DownloadStop, observed, until time.Time) (evidence.DownloadStopSnapshot, error) {
	var out evidence.DownloadStopSnapshot
	if len(row.Decision) == 0 || json.Unmarshal(row.Decision, &out.Decision) != nil || !out.Decision.Valid() || out.Decision.DownloadID != uid(row.DownloadID) || out.Decision.RootID != uid(row.RootID) || out.Decision.RequestID != uid(row.RequestID) || out.Decision.StoreID != uid(row.StoreID) || !bytes.Equal(out.Decision.KeyDigest[:], row.KeyDigest) || !out.Decision.RequestedAt.Equal(row.RequestedAt.Time) || !out.Decision.WriteUntil.Equal(row.WriteUntil.Time) || !out.Decision.RetainUntil.Equal(row.RetainUntil.Time) {
		return out, artifact.ErrDownloadUnavailable
	}
	out.WriteStarted = row.WriteStarted
	out.ObservedAt = observed
	out.ValidUntil = until
	if len(row.Receipt) > 0 {
		var receipt audit.Receipt
		if json.Unmarshal(row.Receipt, &receipt) != nil || !stopReceipt(out.Decision, receipt) {
			return out, artifact.ErrDownloadUnavailable
		}
		out.Receipt = &receipt
	}
	return out, nil
}
func stopReceipt(d artifact.DownloadStopDecision, r audit.Receipt) bool {
	return r.Key == artifact.DownloadStopKey(d.RootID, d.DownloadID) && r.Bytes > 0 && r.Bytes <= artifact.DownloadStopCipherLimit && r.SHA256 != (artifact.Digest{}) && identity.Text(r.ETag, 256) && (r.Version == "" || identity.Text(r.Version, 1024))
}

func (s *DownloadStops) StopDownload(ctx context.Context, i identity.Identity, downloadID string, key artifact.Digest, requestID string) (evidence.DownloadStopSnapshot, error) {
	var out evidence.DownloadStopSnapshot
	started := time.Now()
	until := identity.Earlier(started.Add(artifact.DownloadLease), i.ValidUntil)
	if s == nil || ctx == nil || !i.Valid(started) || !authorization.UUID(downloadID) || !authorization.UUID(requestID) || key == (artifact.Digest{}) {
		return out, artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	e := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, e := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(downloadID), RootID: id(s.root)})
		if e != nil || !bytes.Equal(row.ActorKey, digest(i.Principal)) {
			return artifact.ErrDownloadUnavailable
		}
		session, e := decodeDownload(row)
		if e != nil || session.Scope.Principal != i.Principal {
			return artifact.ErrDownloadUnavailable
		}
		stop, e := q.LockDownloadStop(ctx, custodydb.LockDownloadStopParams{DownloadID: row.ID, RootID: row.RootID})
		if e != nil {
			return artifact.ErrDownloadUnavailable
		}
		n, e := q.CurrentTime(ctx)
		if e != nil || !i.Valid(n.Time) || !n.Time.Before(until) || ctx.Err() != nil {
			return artifact.ErrDownloadUnavailable
		}
		if !n.Time.Before(stop.RetainUntil.Time) {
			return artifact.ErrDownloadUnavailable
		}
		until = identity.Earlier(until, stop.RetainUntil.Time)
		if len(stop.Decision) > 0 {
			if !bytes.Equal(stop.KeyDigest, key[:]) {
				return artifact.ErrDownloadConflict
			}
		} else {
			state := "AlreadyTerminal"
			if !session.State.Terminal() && n.Time.Before(session.Deadline) {
				state = "Cancelled"
				session.State = artifact.DownloadCancelled
			} else if !session.State.Terminal() {
				session.State = artifact.DownloadExpired
			}
			// Cancellation fences active generations through the existing terminal
			// state checks. Historical byte accounting may still finish, never refund.
			if _, e = q.FenceDownloadStopState(ctx, custodydb.FenceDownloadStopStateParams{ID: row.ID, RootID: row.RootID, State: string(session.State)}); e != nil {
				return e
			}
			writeUntil := identity.Earlier(n.Time.Add(30*time.Second), stop.RetainUntil.Time.Add(-time.Microsecond))
			decision := artifact.DownloadStopDecision{Protocol: artifact.DownloadStopProtocol, RootID: s.root, DownloadID: downloadID, RequestID: requestID, StoreID: uid(stop.StoreID), Actor: i.Principal, KeyDigest: key, State: state, RequestedAt: n.Time, WriteUntil: writeUntil, RetainUntil: stop.RetainUntil.Time}
			if !decision.Valid() {
				return artifact.ErrDownloadUnavailable
			}
			body, e := json.Marshal(decision)
			if e != nil {
				return e
			}
			stop, e = q.FreezeDownloadStop(ctx, custodydb.FreezeDownloadStopParams{DownloadID: row.ID, RootID: row.RootID, KeyDigest: key[:], RequestID: id(requestID), RequestedAt: ts(n.Time), WriteUntil: ts(writeUntil), Decision: body})
			if e != nil {
				return e
			}
		}
		n, e = q.CurrentTime(ctx)
		if e != nil || !i.Valid(n.Time) || !n.Time.Before(until) || ctx.Err() != nil {
			return artifact.ErrDownloadUnavailable
		}
		out, e = stopSnapshot(stop, started, until)
		return e
	})
	if e != nil {
		return evidence.DownloadStopSnapshot{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

// Audit I/O uses current independently accepted recovery, before the Stop row
// lock. Restriction itself deliberately does not require this effect authority.
func (s *DownloadStops) auditTrust(ctx context.Context, q *custodydb.Queries) (custodydb.FleetCurrentTrust, time.Time, error) {
	start, e := q.CurrentTime(ctx)
	if e != nil {
		return custodydb.FleetCurrentTrust{}, time.Time{}, e
	}
	trust, e := q.ShareFleetTrust(ctx, id(s.recovery.installation))
	if e != nil {
		return trust, start.Time, e
	}
	now, e := q.CurrentTime(ctx)
	if e != nil {
		return trust, start.Time, e
	}
	_, e = recoveryState(trust, start.Time, now.Time)
	return trust, start.Time, e
}

func (s *DownloadStops) ClaimDownloadStopWrite(ctx context.Context, d artifact.DownloadStopDecision) (bool, error) {
	if s == nil || s.recovery == nil || !d.Valid() || d.RootID != s.root {
		return false, artifact.ErrDownloadUnavailable
	}
	fresh := false
	e := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := s.auditTrust(ctx, q)
		if e != nil {
			return e
		}
		row, e := q.LockDownloadStop(ctx, custodydb.LockDownloadStopParams{DownloadID: id(d.DownloadID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		if uid(row.InstallationID) != s.recovery.installation || row.IssuerEpoch != trust.IssuerEpoch {
			return artifact.ErrDownloadUnavailable
		}
		body, e := json.Marshal(d)
		if e != nil {
			return e
		}
		snap, e := stopSnapshot(row, time.Now(), time.Now().Add(time.Second))
		if e != nil || !sameStopDecision(snap.Decision, d) {
			return artifact.ErrDownloadUnavailable
		}
		if len(row.Receipt) > 0 {
			return artifact.ErrDownloadConflict
		}
		var changed int64
		if !row.WriteStarted {
			changed, e = q.ClaimDownloadStopWrite(ctx, custodydb.ClaimDownloadStopWriteParams{DownloadID: row.DownloadID, RootID: row.RootID, Decision: body})
			fresh = true
		} else {
			changed, e = q.ChargeDownloadStopLookup(ctx, custodydb.ChargeDownloadStopLookupParams{DownloadID: row.DownloadID, RootID: row.RootID, Decision: body})
		}
		if e != nil {
			return e
		}
		if changed != 1 {
			return artifact.ErrDownloadUnavailable
		}
		return auditCurrent(ctx, q, trust, start, identity.Earlier(start.Add(5*time.Second), d.RetainUntil))
	})
	if e != nil {
		return false, artifact.ErrDownloadUnavailable
	}
	return fresh, nil
}
func (s *DownloadStops) AcknowledgeDownloadStop(ctx context.Context, d artifact.DownloadStopDecision, r audit.Receipt) error {
	if s == nil || s.recovery == nil || !d.Valid() || d.RootID != s.root || !stopReceipt(d, r) {
		return artifact.ErrDownloadUnavailable
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := s.auditTrust(ctx, q)
		if e != nil {
			return e
		}
		row, e := q.LockDownloadStop(ctx, custodydb.LockDownloadStopParams{DownloadID: id(d.DownloadID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		if uid(row.InstallationID) != s.recovery.installation || row.IssuerEpoch != trust.IssuerEpoch {
			return artifact.ErrDownloadUnavailable
		}
		snap, e := stopSnapshot(row, time.Now(), time.Now().Add(time.Second))
		if e != nil || !sameStopDecision(snap.Decision, d) || !snap.WriteStarted {
			return artifact.ErrDownloadUnavailable
		}
		if snap.Receipt != nil {
			if *snap.Receipt != r {
				return artifact.ErrDownloadUnavailable
			}
			return auditCurrent(ctx, q, trust, start, identity.Earlier(start.Add(5*time.Second), d.RetainUntil))
		}
		decision, e := json.Marshal(d)
		if e != nil {
			return e
		}
		receipt, e := json.Marshal(r)
		if e != nil {
			return e
		}
		n, e := q.AcknowledgeDownloadStop(ctx, custodydb.AcknowledgeDownloadStopParams{DownloadID: row.DownloadID, RootID: row.RootID, Decision: decision, Receipt: receipt})
		if e != nil {
			return e
		}
		if n != 1 {
			return artifact.ErrDownloadUnavailable
		}
		return auditCurrent(ctx, q, trust, start, identity.Earlier(start.Add(5*time.Second), d.RetainUntil))
	})
}

// Installation configuration provides independently accepted finite backing;
// no public caller can provision or rotate it. Renewal preserves every charge.
func (s *Downloads) BindDownloadStopBacking(ctx context.Context, b artifact.DownloadStopBacking) error {
	if s == nil || s.recovery == nil || !b.Valid() || b.RootID != s.root || b.InstallationID != s.recovery.installation {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, e := q.LockPermissionStream(ctx, id(s.root)); e != nil {
			return e
		}
		pool, e := q.ReadDownloadStopPool(ctx, id(s.root))
		if errors.Is(e, pgx.ErrNoRows) {
			if b.ExpectedRevision != 0 {
				return artifact.ErrDownloadConflict
			}
			e = q.InsertDownloadStopPool(ctx, custodydb.InsertDownloadStopPoolParams{RootID: id(s.root), InstallationID: id(b.InstallationID), StoreID: id(b.StoreID), PolicyID: id(b.PolicyID), BackupProfileID: id(b.BackupProfileID), PolicyDigest: b.PolicyDigest[:], BackupProfileDigest: b.BackupProfileDigest[:], Slots: b.Slots, CipherBytes: b.CipherBytes, KeyAttempts: b.KeyAttempts, BackupBytes: b.BackupBytes, WalBytes: b.WALBytes, RetainedSeconds: b.RetainedSeconds, BackupHorizonSeconds: b.BackupHorizonSeconds, ValidUntil: ts(b.ValidUntil)})
		} else if e == nil {
			if uid(pool.InstallationID) != b.InstallationID || uid(pool.StoreID) != b.StoreID || uid(pool.PolicyID) != b.PolicyID || uid(pool.BackupProfileID) != b.BackupProfileID || !bytes.Equal(pool.PolicyDigest, b.PolicyDigest[:]) || !bytes.Equal(pool.BackupProfileDigest, b.BackupProfileDigest[:]) || pool.Slots != b.Slots || pool.CipherBytes != b.CipherBytes || pool.KeyAttempts != b.KeyAttempts || pool.BackupBytes != b.BackupBytes || pool.WalBytes != b.WALBytes || pool.RetainedSeconds != b.RetainedSeconds || pool.BackupHorizonSeconds != b.BackupHorizonSeconds {
				return artifact.ErrDownloadConflict
			}
			if !pool.ValidUntil.Time.Equal(b.ValidUntil) {
				if pool.Revision != b.ExpectedRevision {
					return artifact.ErrDownloadConflict
				}
				var n int64
				n, e = q.RenewDownloadStopPool(ctx, custodydb.RenewDownloadStopPoolParams{RootID: id(s.root), Revision: b.ExpectedRevision, ValidUntil: ts(b.ValidUntil)})
				if e == nil && n != 1 {
					return artifact.ErrDownloadConflict
				}
			}
		}
		if e != nil {
			return e
		}
		old, e := q.ReadDownloadStopBacking(ctx, custodydb.ReadDownloadStopBackingParams{AllocationID: id(b.AllocationID), RootID: id(s.root)})
		if e == nil {
			if old.Slots != b.AllocationSlots {
				return artifact.ErrDownloadConflict
			}
		} else if errors.Is(e, pgx.ErrNoRows) {
			e = q.InsertDownloadStopBacking(ctx, custodydb.InsertDownloadStopBackingParams{AllocationID: id(b.AllocationID), RootID: id(s.root), Slots: b.AllocationSlots})
		}
		if e != nil {
			return e
		}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !identity.Fresh(b.ObservedAt, b.ObservedAt.Add(5*time.Second), n.Time, 5*time.Second) || !n.Time.Before(b.ValidUntil) {
			return artifact.ErrDownloadUnavailable
		}
		return ctx.Err()
	})
}

func sameStopDecision(a, b artifact.DownloadStopDecision) bool {
	at, aw, ar := a.RequestedAt, a.WriteUntil, a.RetainUntil
	bt, bw, br := b.RequestedAt, b.WriteUntil, b.RetainUntil
	a.RequestedAt = time.Time{}
	a.WriteUntil = time.Time{}
	a.RetainUntil = time.Time{}
	b.RequestedAt = time.Time{}
	b.WriteUntil = time.Time{}
	b.RetainUntil = time.Time{}
	return a == b && at.Equal(bt) && aw.Equal(bw) && ar.Equal(br)
}

func (s *DownloadStops) PendingDownloadStops(ctx context.Context) ([]evidence.DownloadStopSnapshot, error) {
	if s == nil || ctx == nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	started := time.Now()
	until := started.Add(artifact.DownloadLease)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	rows, e := custodydb.New(s.ledger.pool).ListPendingDownloadStops(ctx, id(s.root))
	if e != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	out := make([]evidence.DownloadStopSnapshot, 0, len(rows))
	for _, row := range rows {
		v, e := stopSnapshot(row, started, until)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	if ctx.Err() != nil || !time.Now().Before(until) {
		return nil, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
