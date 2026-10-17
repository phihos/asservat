package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Construct distinct instances with producer, cleanup, verifier and finalizer
// SQL credentials. None provisions policy or accepts a database recovery.
type DownloadStopLifecycles struct{ stop *DownloadStops }

func NewDownloadStopLifecycles(ctx context.Context, pool *pgxpool.Pool, root string, recovery *RecoveryTransactionGuard) (*DownloadStopLifecycles, error) {
	if recovery == nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	s, e := NewDownloadStops(ctx, pool, root, recovery)
	if e != nil {
		return nil, e
	}
	return &DownloadStopLifecycles{s}, nil
}

var _ app.DownloadStopCompletions = (*DownloadStopLifecycles)(nil)
var _ app.DownloadStopLifecycleJournal = (*DownloadStopLifecycles)(nil)
var _ app.DownloadStopLifecycleAcknowledgements = (*DownloadStopLifecycles)(nil)
var _ app.DownloadStopLifecycleFinalizer = (*DownloadStopLifecycles)(nil)
var _ app.DownloadStopHistoryJournal = (*DownloadStopLifecycles)(nil)

func stopLifecycleState(s custodydb.DownloadStop, l custodydb.DownloadStopLifecycle) (value.DownloadStopLifecycleSnapshot, error) {
	var out value.DownloadStopLifecycleSnapshot
	if json.Unmarshal(l.Binding, &out.Binding) != nil || !out.Binding.Valid() {
		return out, artifact.ErrDownloadUnavailable
	}
	b := out.Binding
	if b.DownloadID != uid(s.DownloadID) || b.RootID != uid(s.RootID) || b.AllocationID != uid(s.AllocationID) || b.Policy.StoreID != uid(s.StoreID) || b.Policy.InstallationID != uid(s.InstallationID) || b.IssuerEpoch != uid(s.IssuerEpoch) || !b.ReservedAt.Equal(s.ReservedAt.Time) || !b.HardDeleteBy.Equal(s.RetainUntil.Time) || l.DownloadID != s.DownloadID || l.RootID != s.RootID || l.AllocationID != s.AllocationID || l.InstallationID != s.InstallationID || l.IssuerEpoch != s.IssuerEpoch || !b.OriginalPurgeAt.Equal(l.OriginalPurgeAt.Time) || !b.CertificatePurgeAt.Equal(l.CertificatePurgeAt.Time) || !b.LiveRetireBy.Equal(l.LiveRetireBy.Time) {
		return out, artifact.ErrDownloadUnavailable
	}
	decode := func(raw []byte, v any) bool { return len(raw) == 0 || json.Unmarshal(raw, v) == nil }
	if !decode(s.Decision, &out.Decision) || !decode(s.Receipt, &out.OriginalReceipt) || !decode(l.OriginalCompletion, &out.Writer) || !decode(l.Lease, &out.Lease) || !decode(l.Retirement, &out.Retirement) || !decode(l.CertificateCompletion, &out.CertificateWriter) || !decode(l.CertificateReceipt, &out.CertificateReceipt) || !decode(l.TerminalPurge, &out.Terminal) {
		return out, artifact.ErrDownloadUnavailable
	}
	out.ClosedAt = l.ClosedAt.Time
	out.Mode = l.Mode.String
	out.OverdueSelectedAt = l.OverdueSelectedAt.Time
	out.CertificateStarted = l.CertificateStarted
	out.CertificateVerifyAttempts = l.CertificateVerifyAttempts
	if l.CertificateVerifyAttempts < 0 || l.CertificateVerifyAttempts > 2 || l.CertificateVerifyAttempts > 0 && len(l.CertificateCompletion) == 0 {
		return out, artifact.ErrDownloadUnavailable
	}
	out.TerminalAcknowledged = l.TerminalAcknowledgedAt.Valid
	if out.Decision != nil {
		d := out.Decision
		if !d.Valid() || d.RootID != b.RootID || d.DownloadID != b.DownloadID || d.StoreID != b.Policy.StoreID || !d.RetainUntil.Equal(b.HardDeleteBy) || !d.WriteUntil.Before(b.OriginalPurgeAt) || d.RequestedAt.Before(b.ReservedAt) {
			return out, artifact.ErrDownloadUnavailable
		}
	}
	if out.Writer != nil {
		c := out.Writer
		if out.Decision == nil || !s.WriteStarted || !c.Valid(b, "decision", out.Decision.RequestedAt, out.Decision.WriteUntil) || c.BindingDigest != auditapp.OperationLifecycleDigest(b) || c.RecordDigest != auditapp.OperationLifecycleDigest(*out.Decision) {
			return out, artifact.ErrDownloadUnavailable
		}
	}
	if out.OriginalReceipt != nil && (out.Writer == nil || *out.OriginalReceipt != out.Writer.Receipt) {
		return out, artifact.ErrDownloadUnavailable
	}
	if !out.ClosedAt.IsZero() {
		if out.ClosedAt.Before(b.OriginalPurgeAt) || out.Mode != "unused" && out.Mode != "written" && out.Mode != "unwritten" || out.Mode == "unused" && (out.Decision != nil || s.WriteStarted || out.Writer != nil || out.OriginalReceipt != nil) || out.Mode == "written" && (out.Writer == nil || out.OriginalReceipt == nil) || out.Mode == "unwritten" && (out.Decision == nil || s.WriteStarted || out.Writer != nil || out.OriginalReceipt != nil || out.ClosedAt.Before(out.Decision.WriteUntil)) {
			return out, artifact.ErrDownloadUnavailable
		}
	}
	if !out.OverdueSelectedAt.IsZero() && (out.ClosedAt.IsZero() || out.CertificateStarted || out.CertificateWriter != nil || out.CertificateReceipt != nil || out.OverdueSelectedAt.Before(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second))) {
		return out, artifact.ErrDownloadUnavailable
	}
	if out.Retirement != nil {
		r := out.Retirement
		objects, writers := stopLifecycleDigests(out, false)
		if !r.Valid() || r.RootID != b.RootID || r.DownloadID != b.DownloadID || r.InstallationID != b.Policy.InstallationID || r.IssuerEpoch != b.IssuerEpoch || r.StoreID != b.Policy.StoreID || r.BindingDigest != auditapp.OperationLifecycleDigest(b) || r.Mode != out.Mode || r.ObjectsDigest != objects || r.WritersDigest != writers || !r.CertificatePurgeAt.Equal(b.CertificatePurgeAt) || !r.LiveRetireBy.Equal(b.LiveRetireBy) || r.CertificateWriteUntil.After(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second)) {
			return out, artifact.ErrDownloadUnavailable
		}
	}
	if out.CertificateWriter != nil {
		c := out.CertificateWriter
		if out.Retirement == nil || !out.CertificateStarted || !c.Valid(b, "certificate", out.Retirement.PurgedAt, out.Retirement.CertificateWriteUntil) || c.BindingDigest != auditapp.OperationLifecycleDigest(b) || c.RecordDigest != auditapp.OperationLifecycleDigest(*out.Retirement) {
			return out, artifact.ErrDownloadUnavailable
		}
	}
	if out.CertificateReceipt != nil && (out.CertificateWriter == nil || *out.CertificateReceipt != out.CertificateWriter.Receipt || !l.CertificateAcknowledgedAt.Valid) {
		return out, artifact.ErrDownloadUnavailable
	}
	if out.Lease != nil {
		lease := out.Lease
		objects, writers := stopLifecycleDigests(out, lease.Phase == "terminal")
		if !lease.Valid() || lease.RootID != b.RootID || lease.DownloadID != b.DownloadID || lease.StoreID != b.Policy.StoreID || lease.InstallationID != b.Policy.InstallationID || lease.IssuerEpoch != b.IssuerEpoch || lease.BindingDigest != auditapp.OperationLifecycleDigest(b) || lease.Fence != l.LeaseFence || lease.ObjectsDigest != objects || lease.WritersDigest != writers || out.ClosedAt.IsZero() {
			return out, artifact.ErrDownloadUnavailable
		}
	}
	if out.Terminal != nil && (out.Lease == nil || !out.Terminal.Valid(*out.Lease)) {
		return out, artifact.ErrDownloadUnavailable
	}
	if out.TerminalAcknowledged && out.Terminal == nil {
		return out, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
func stopLifecycleDigests(s value.DownloadStopLifecycleSnapshot, certificate bool) (artifact.Digest, artifact.Digest) {
	objects := []value.Receipt{}
	writers := []value.DownloadStopWriteCompletion{}
	if s.OriginalReceipt != nil {
		objects = append(objects, *s.OriginalReceipt)
	}
	if s.Writer != nil {
		writers = append(writers, *s.Writer)
	}
	if certificate && s.CertificateReceipt != nil {
		objects = append(objects, *s.CertificateReceipt)
	}
	if certificate && s.CertificateWriter != nil {
		writers = append(writers, *s.CertificateWriter)
	}
	return auditapp.OperationLifecycleDigest(objects), auditapp.OperationLifecycleDigest(writers)
}

type stopLifecycleCall func(context.Context, *custodydb.Queries, custodydb.DownloadStop, custodydb.DownloadStopLifecycle, value.DownloadStopLifecycleSnapshot, time.Time) (time.Time, error)

func (s *DownloadStopLifecycles) transaction(ctx context.Context, download string, fn stopLifecycleCall) error {
	if s == nil || s.stop == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(download) {
		return artifact.ErrDownloadUnavailable
	}
	started := time.Now()
	until := started.Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	e := s.stop.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := s.stop.auditTrust(ctx, q)
		if e != nil {
			return e
		}
		locator, e := q.ReadDownloadStop(ctx, custodydb.ReadDownloadStopParams{DownloadID: id(download), RootID: id(s.stop.root)})
		if e != nil {
			return e
		}
		if _, e = q.LockDownloadStopPool(ctx, id(s.stop.root)); e != nil {
			return e
		}
		if _, e = q.LockDownloadStopBacking(ctx, custodydb.LockDownloadStopBackingParams{AllocationID: locator.AllocationID, RootID: locator.RootID}); e != nil {
			return e
		}
		row, e := q.LockDownloadStop(ctx, custodydb.LockDownloadStopParams{DownloadID: locator.DownloadID, RootID: locator.RootID})
		if e != nil {
			return e
		}
		l, e := q.LockDownloadStopLifecycle(ctx, custodydb.LockDownloadStopLifecycleParams{DownloadID: row.DownloadID, RootID: row.RootID})
		if e != nil {
			return e
		}
		state, e := stopLifecycleState(row, l)
		if e != nil || l.InstallationID != trust.InstallationID || l.IssuerEpoch != trust.IssuerEpoch {
			return artifact.ErrDownloadUnavailable
		}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if e = auditCurrent(ctx, q, trust, start, until); e != nil {
			return e
		}
		bound, e := fn(ctx, q, row, l, state, n.Time)
		if e != nil {
			return e
		}
		if !bound.IsZero() {
			until = identity.Earlier(until, bound)
		}
		return auditCurrent(ctx, q, trust, start, until)
	})
	if e != nil {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func (s *DownloadStopLifecycles) ReadDownloadStopLifecycle(ctx context.Context, download string) (value.DownloadStopLifecycleSnapshot, error) {
	var out value.DownloadStopLifecycleSnapshot
	e := s.transaction(ctx, download, func(ctx context.Context, _ *custodydb.Queries, _ custodydb.DownloadStop, _ custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, _ time.Time) (time.Time, error) {
		out = v
		return time.Time{}, nil
	})
	return out, e
}
func (s *DownloadStopLifecycles) ReadDownloadStopBinding(ctx context.Context, d artifact.DownloadStopDecision) (value.DownloadStopLifecycleBinding, error) {
	v, e := s.ReadDownloadStopLifecycle(ctx, d.DownloadID)
	if e != nil || v.Decision == nil || !sameStopDecision(*v.Decision, d) || !v.ClosedAt.IsZero() {
		return value.DownloadStopLifecycleBinding{}, artifact.ErrDownloadUnavailable
	}
	return v.Binding, nil
}
func (s *DownloadStopLifecycles) ReadDownloadStopCompletion(ctx context.Context, d artifact.DownloadStopDecision) (value.DownloadStopWriteCompletion, error) {
	v, e := s.ReadDownloadStopLifecycle(ctx, d.DownloadID)
	if e != nil || v.Decision == nil || !sameStopDecision(*v.Decision, d) || v.Writer == nil || !v.ClosedAt.IsZero() {
		return value.DownloadStopWriteCompletion{}, artifact.ErrDownloadUnavailable
	}
	return *v.Writer, nil
}
func (s *DownloadStopLifecycles) RecordDownloadStopCompletion(ctx context.Context, d artifact.DownloadStopDecision, c value.DownloadStopWriteCompletion) error {
	return s.transaction(ctx, d.DownloadID, func(ctx context.Context, q *custodydb.Queries, row custodydb.DownloadStop, _ custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, _ time.Time) (time.Time, error) {
		if v.Decision == nil || !sameStopDecision(*v.Decision, d) || !row.WriteStarted || !v.ClosedAt.IsZero() || !c.Valid(v.Binding, "decision", d.RequestedAt, d.WriteUntil) || c.BindingDigest != auditapp.OperationLifecycleDigest(v.Binding) || c.RecordDigest != auditapp.OperationLifecycleDigest(d) {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		if v.Writer != nil {
			if !sameAuditJSON(*v.Writer, c) {
				return time.Time{}, artifact.ErrDownloadUnavailable
			}
			return d.WriteUntil, nil
		}
		b, _ := json.Marshal(c)
		n, e := q.RecordDownloadStopCompletion(ctx, custodydb.RecordDownloadStopCompletionParams{DownloadID: row.DownloadID, RootID: row.RootID, OriginalCompletion: b})
		if e != nil || n != 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		return d.WriteUntil, nil
	})
}

func (s *DownloadStopLifecycles) BeginDownloadStopPurge(ctx context.Context, download, phase string) (value.DownloadStopPurgeLease, error) {
	var out value.DownloadStopPurgeLease
	if phase != "original" && phase != "terminal" && phase != "overdue" {
		return out, artifact.ErrDownloadUnavailable
	}
	e := s.transaction(ctx, download, func(ctx context.Context, q *custodydb.Queries, row custodydb.DownloadStop, l custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, now time.Time) (time.Time, error) {
		b := v.Binding
		if now.Before(b.OriginalPurgeAt) {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		if v.ClosedAt.IsZero() {
			mode := "unused"
			if v.Decision != nil {
				mode = "written"
				if !row.WriteStarted && v.Writer == nil && v.OriginalReceipt == nil && !now.Before(v.Decision.WriteUntil) {
					mode = "unwritten"
				} else if v.Writer == nil || v.OriginalReceipt == nil {
					return time.Time{}, artifact.ErrDownloadUnavailable
				}
			} else if row.WriteStarted || v.Writer != nil || v.OriginalReceipt != nil {
				return time.Time{}, artifact.ErrDownloadUnavailable
			}
			n, e := q.CloseDownloadStopLifecycle(ctx, custodydb.CloseDownloadStopLifecycleParams{DownloadID: row.DownloadID, RootID: row.RootID, ClosedAt: ts(now), Mode: pgtype.Text{String: mode, Valid: true}})
			if e != nil || n != 1 {
				return time.Time{}, artifact.ErrDownloadUnavailable
			}
			v.ClosedAt = now
			v.Mode = mode
		}
		proofEnd := b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds) * time.Second)
		if phase == "overdue" {
			if now.Before(proofEnd) || v.CertificateStarted || v.CertificateWriter != nil || v.CertificateReceipt != nil {
				return time.Time{}, artifact.ErrDownloadUnavailable
			}
			if v.OverdueSelectedAt.IsZero() {
				n, e := q.SelectOverdueDownloadStop(ctx, custodydb.SelectOverdueDownloadStopParams{DownloadID: row.DownloadID, RootID: row.RootID, OverdueSelectedAt: ts(now)})
				if e != nil || n != 1 {
					return time.Time{}, artifact.ErrDownloadUnavailable
				}
				v.OverdueSelectedAt = now
			}
		} else if !v.OverdueSelectedAt.IsZero() {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		if phase == "original" && (v.Retirement != nil || !now.Before(proofEnd)) || phase == "terminal" && (now.Before(b.CertificatePurgeAt) || v.CertificateReceipt == nil || v.CertificateWriter == nil) {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		// A replay cannot reset the original lease. Return its exact value while live.
		if v.Lease != nil && now.Before(v.Lease.Until) {
			if v.Lease.Phase != phase {
				return time.Time{}, artifact.ErrDownloadUnavailable
			}
			out = *v.Lease
			return out.Until, nil
		}
		if l.LeaseFence >= b.Policy.MaxPurgeLeases {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		objects, writers := stopLifecycleDigests(v, phase == "terminal")
		until := now.Add(5 * time.Second)
		if phase == "original" {
			until = identity.Earlier(until, proofEnd)
		}
		if deadline, ok := ctx.Deadline(); ok {
			until = identity.Earlier(until, deadline)
		}
		until = until.UTC().Truncate(time.Microsecond)
		out = value.DownloadStopPurgeLease{RootID: b.RootID, DownloadID: b.DownloadID, StoreID: b.Policy.StoreID, InstallationID: b.Policy.InstallationID, IssuerEpoch: b.IssuerEpoch, Phase: phase, BindingDigest: auditapp.OperationLifecycleDigest(b), ObjectsDigest: objects, WritersDigest: writers, Fence: l.LeaseFence + 1, StartedAt: now, Until: until}
		if !out.Valid() {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		raw, _ := json.Marshal(out)
		n, e := q.LeaseDownloadStopPurge(ctx, custodydb.LeaseDownloadStopPurgeParams{DownloadID: row.DownloadID, RootID: row.RootID, Lease: raw})
		if e != nil || n != 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		return until, nil
	})
	if e != nil {
		return value.DownloadStopPurgeLease{}, e
	}
	return out, nil
}
func (s *DownloadStopLifecycles) RecordOriginalDownloadStopPurge(ctx context.Context, l value.DownloadStopPurgeLease) (value.DownloadStopRetirement, error) {
	var out value.DownloadStopRetirement
	if !l.Valid() || l.Phase != "original" {
		return out, artifact.ErrDownloadUnavailable
	}
	e := s.transaction(ctx, l.DownloadID, func(ctx context.Context, q *custodydb.Queries, row custodydb.DownloadStop, _ custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, now time.Time) (time.Time, error) {
		if v.Lease == nil || !sameAuditJSON(*v.Lease, l) || !now.Before(l.Until) || !v.OverdueSelectedAt.IsZero() {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		if v.Retirement != nil {
			out = *v.Retirement
			return l.Until, nil
		}
		b := v.Binding
		until := identity.Earlier(now.Add(30*time.Second), b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second))
		out = value.DownloadStopRetirement{RootID: b.RootID, DownloadID: b.DownloadID, StoreID: b.Policy.StoreID, InstallationID: b.Policy.InstallationID, IssuerEpoch: b.IssuerEpoch, Mode: v.Mode, BindingDigest: l.BindingDigest, ObjectsDigest: l.ObjectsDigest, WritersDigest: l.WritersDigest, PurgeFence: l.Fence, PurgedAt: now, CertificateWriteUntil: until, CertificatePurgeAt: b.CertificatePurgeAt, LiveRetireBy: b.LiveRetireBy}
		if !out.Valid() {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		raw, _ := json.Marshal(out)
		n, e := q.RecordDownloadStopRetirement(ctx, custodydb.RecordDownloadStopRetirementParams{DownloadID: row.DownloadID, RootID: row.RootID, Retirement: raw})
		if e != nil || n != 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		return l.Until, nil
	})
	if e != nil {
		return value.DownloadStopRetirement{}, e
	}
	return out, nil
}
func (s *DownloadStopLifecycles) ClaimDownloadStopCertificate(ctx context.Context, r value.DownloadStopRetirement) (bool, error) {
	fresh := false
	if !r.Valid() {
		return false, artifact.ErrDownloadUnavailable
	}
	e := s.transaction(ctx, r.DownloadID, func(ctx context.Context, q *custodydb.Queries, row custodydb.DownloadStop, _ custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, now time.Time) (time.Time, error) {
		if v.Retirement == nil || !sameAuditJSON(*v.Retirement, r) || !v.OverdueSelectedAt.IsZero() || !now.Before(r.CertificateWriteUntil) {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		if v.CertificateStarted {
			return r.CertificateWriteUntil, nil
		}
		raw, _ := json.Marshal(r)
		n, e := q.ClaimDownloadStopCertificate(ctx, custodydb.ClaimDownloadStopCertificateParams{DownloadID: row.DownloadID, RootID: row.RootID, Retirement: raw})
		if e != nil || n != 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		fresh = true
		return r.CertificateWriteUntil, nil
	})
	if e != nil {
		return false, e
	}
	return fresh, nil
}
func (s *DownloadStopLifecycles) RecordDownloadStopCertificateCompletion(ctx context.Context, r value.DownloadStopRetirement, c value.DownloadStopWriteCompletion) error {
	if !r.Valid() {
		return artifact.ErrDownloadUnavailable
	}
	return s.transaction(ctx, r.DownloadID, func(ctx context.Context, q *custodydb.Queries, row custodydb.DownloadStop, _ custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, _ time.Time) (time.Time, error) {
		if v.Retirement == nil || !sameAuditJSON(*v.Retirement, r) || !v.CertificateStarted || !c.Valid(v.Binding, "certificate", r.PurgedAt, r.CertificateWriteUntil) || c.BindingDigest != auditapp.OperationLifecycleDigest(v.Binding) || c.RecordDigest != auditapp.OperationLifecycleDigest(r) {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		if v.CertificateWriter != nil {
			if !sameAuditJSON(*v.CertificateWriter, c) {
				return time.Time{}, artifact.ErrDownloadUnavailable
			}
			return r.CertificateWriteUntil, nil
		}
		raw, _ := json.Marshal(c)
		n, e := q.RecordDownloadStopCertificateCompletion(ctx, custodydb.RecordDownloadStopCertificateCompletionParams{DownloadID: row.DownloadID, RootID: row.RootID, CertificateCompletion: raw})
		if e != nil || n != 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		return r.CertificateWriteUntil, nil
	})
}
func (s *DownloadStopLifecycles) ClaimDownloadStopCertificateVerification(ctx context.Context, r value.DownloadStopRetirement) (bool, error) {
	fresh := false
	if !r.Valid() {
		return false, artifact.ErrDownloadUnavailable
	}
	e := s.transaction(ctx, r.DownloadID, func(ctx context.Context, q *custodydb.Queries, row custodydb.DownloadStop, _ custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, now time.Time) (time.Time, error) {
		if v.Retirement == nil || !sameAuditJSON(*v.Retirement, r) || v.CertificateWriter == nil || v.CertificateReceipt != nil || v.CertificateVerifyAttempts >= 2 || !now.Before(r.CertificateWriteUntil) {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		raw, _ := json.Marshal(r)
		count, e := q.ClaimDownloadStopCertificateVerification(ctx, custodydb.ClaimDownloadStopCertificateVerificationParams{DownloadID: row.DownloadID, RootID: row.RootID, Retirement: raw})
		if e != nil || count != 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		fresh = true
		return r.CertificateWriteUntil, nil
	})
	if e != nil {
		return false, e
	}
	return fresh, nil
}
func (s *DownloadStopLifecycles) AcknowledgeDownloadStopCertificate(ctx context.Context, r value.DownloadStopRetirement, receipt value.Receipt) error {
	if !r.Valid() {
		return artifact.ErrDownloadUnavailable
	}
	return s.transaction(ctx, r.DownloadID, func(ctx context.Context, q *custodydb.Queries, row custodydb.DownloadStop, _ custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, now time.Time) (time.Time, error) {
		if v.Retirement == nil || !sameAuditJSON(*v.Retirement, r) || v.CertificateWriter == nil || v.CertificateWriter.Receipt != receipt || v.CertificateVerifyAttempts < 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		if v.CertificateReceipt != nil {
			if *v.CertificateReceipt != receipt {
				return time.Time{}, artifact.ErrDownloadUnavailable
			}
			return r.CertificateWriteUntil, nil
		}
		raw, _ := json.Marshal(receipt)
		n, e := q.AcknowledgeDownloadStopCertificate(ctx, custodydb.AcknowledgeDownloadStopCertificateParams{DownloadID: row.DownloadID, RootID: row.RootID, CertificateReceipt: raw, CertificateAcknowledgedAt: ts(now)})
		if e != nil || n != 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		return r.CertificateWriteUntil, nil
	})
}
func (s *DownloadStopLifecycles) RecordTerminalDownloadStopPurge(ctx context.Context, l value.DownloadStopPurgeLease) (value.DownloadStopPurgeResult, error) {
	var out value.DownloadStopPurgeResult
	if !l.Valid() || l.Phase != "terminal" && l.Phase != "overdue" {
		return out, artifact.ErrDownloadUnavailable
	}
	e := s.transaction(ctx, l.DownloadID, func(ctx context.Context, q *custodydb.Queries, row custodydb.DownloadStop, _ custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, now time.Time) (time.Time, error) {
		if v.Lease == nil || !sameAuditJSON(*v.Lease, l) || !now.Before(l.Until) {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		if v.Terminal != nil {
			out = *v.Terminal
			return l.Until, nil
		}
		out = value.DownloadStopPurgeResult{RootID: l.RootID, DownloadID: l.DownloadID, Phase: l.Phase, BindingDigest: l.BindingDigest, ObjectsDigest: l.ObjectsDigest, WritersDigest: l.WritersDigest, Fence: l.Fence, PurgedAt: now, LeaseUntil: l.Until}
		if !out.Valid(l) {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		raw, _ := json.Marshal(out)
		n, e := q.RecordTerminalDownloadStopPurge(ctx, custodydb.RecordTerminalDownloadStopPurgeParams{DownloadID: row.DownloadID, RootID: row.RootID, TerminalPurge: raw})
		if e != nil || n != 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		return l.Until, nil
	})
	if e != nil {
		return value.DownloadStopPurgeResult{}, e
	}
	return out, nil
}
func (s *DownloadStopLifecycles) AcknowledgeDownloadStopAbsence(ctx context.Context, l value.DownloadStopPurgeLease, p value.DownloadStopPurgeResult) error {
	if !p.Valid(l) {
		return artifact.ErrDownloadUnavailable
	}
	return s.transaction(ctx, l.DownloadID, func(ctx context.Context, q *custodydb.Queries, row custodydb.DownloadStop, _ custodydb.DownloadStopLifecycle, v value.DownloadStopLifecycleSnapshot, now time.Time) (time.Time, error) {
		if v.Lease == nil || !sameAuditJSON(*v.Lease, l) || v.Terminal == nil || !sameAuditJSON(*v.Terminal, p) {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		if v.TerminalAcknowledged {
			return l.Until, nil
		}
		n, e := q.AcknowledgeDownloadStopAbsence(ctx, custodydb.AcknowledgeDownloadStopAbsenceParams{DownloadID: row.DownloadID, RootID: row.RootID, TerminalAcknowledgedAt: ts(now)})
		if e != nil || n != 1 {
			return time.Time{}, artifact.ErrDownloadUnavailable
		}
		return l.Until, nil
	})
}
func (s *DownloadStopLifecycles) RetireDownloadStop(ctx context.Context, download string) error {
	if s == nil || s.stop == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(download) {
		return artifact.ErrDownloadUnavailable
	}
	until := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	return s.stop.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := s.stop.auditTrust(ctx, q)
		if e != nil {
			return e
		}
		_, e = q.FinishDownloadStopRetirement(ctx, custodydb.FinishDownloadStopRetirementParams{R: id(s.stop.root), I: id(download), Installation: id(s.stop.recovery.installation)})
		if e != nil {
			return e
		}
		return auditCurrent(ctx, q, trust, start, until)
	})
}
func (s *DownloadStopLifecycles) DueDownloadStopHistory(ctx context.Context) ([]value.DownloadStopHistoryKey, error) {
	if s == nil || s.stop == nil || ctx == nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	until := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	var out []value.DownloadStopHistoryKey
	e := s.stop.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := s.stop.auditTrust(ctx, q)
		if e != nil {
			return e
		}
		rows, e := q.ListDueDownloadStopHistory(ctx, id(s.stop.root))
		if e != nil || len(rows) > 16 {
			return artifact.ErrDownloadUnavailable
		}
		for _, r := range rows {
			k := value.DownloadStopHistoryKey{RootID: uid(r.RootID), AllocationID: uid(r.AllocationID), ReleaseAt: r.ReleaseAt.Time, DeleteBy: r.DeleteBy.Time}
			if len(r.PolicyDigest) != 32 || r.InstallationID != trust.InstallationID || r.IssuerEpoch != trust.IssuerEpoch {
				return artifact.ErrDownloadUnavailable
			}
			copy(k.PolicyDigest[:], r.PolicyDigest)
			if !k.Valid() {
				return artifact.ErrDownloadUnavailable
			}
			out = append(out, k)
		}
		return auditCurrent(ctx, q, trust, start, until)
	})
	if e != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
func (s *DownloadStopLifecycles) ReleaseDownloadStopHistory(ctx context.Context, k value.DownloadStopHistoryKey) (value.OperationHistoryRelease, error) {
	var out value.OperationHistoryRelease
	if s == nil || s.stop == nil || ctx == nil || !k.Valid() || k.RootID != s.stop.root {
		return out, artifact.ErrDownloadUnavailable
	}
	until := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	e := s.stop.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := s.stop.auditTrust(ctx, q)
		if e != nil {
			return e
		}
		r, e := q.FinishDownloadStopHistory(ctx, custodydb.FinishDownloadStopHistoryParams{R: id(k.RootID), A: id(k.AllocationID), P: k.PolicyDigest[:], Releases: ts(k.ReleaseAt), Deletes: ts(k.DeleteBy), Installation: id(s.stop.recovery.installation)})
		if e != nil || r.Records < 0 {
			return artifact.ErrDownloadUnavailable
		}
		out = value.OperationHistoryRelease{Records: r.Records, Overdue: r.Overdue}
		return auditCurrent(ctx, q, trust, start, until)
	})
	if e != nil {
		return value.OperationHistoryRelease{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

// Accepted installation source only. Configure before the first download; no
// historical row is upgraded. Source renewal remains BindDownloadStopBacking.
func (s *DownloadStopLifecycles) Configure(ctx context.Context, p value.DownloadStopLifecyclePolicy, observed, validUntil time.Time) error {
	if s == nil || s.stop == nil || ctx == nil || !p.Valid() || p.RootID != s.stop.root || p.InstallationID != s.stop.recovery.installation {
		return artifact.ErrDownloadUnavailable
	}
	until := identity.Earlier(observed.Add(5*time.Second), validUntil)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	return s.stop.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := s.stop.auditTrust(ctx, q)
		if e != nil {
			return e
		}
		pool, e := q.LockDownloadStopPool(ctx, id(s.stop.root))
		if e != nil {
			return e
		}
		if len(pool.LifecyclePolicy) > 0 {
			var old value.DownloadStopLifecyclePolicy
			if json.Unmarshal(pool.LifecyclePolicy, &old) != nil || !sameAuditJSON(old, p) {
				return artifact.ErrDownloadConflict
			}
		} else {
			raw, _ := json.Marshal(p)
			n, e := q.ConfigureDownloadStopLifecycle(ctx, custodydb.ConfigureDownloadStopLifecycleParams{RootID: id(s.stop.root), LifecyclePolicy: raw})
			if e != nil || n != 1 {
				return artifact.ErrDownloadUnavailable
			}
		}
		return auditCurrent(ctx, q, trust, start, until)
	})
}
