package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

var _ evidence.DownloadResponses = (*Downloads)(nil)
var _ evidence.DownloadWindowAcknowledgements = (*Downloads)(nil)

func downloadControl(r custodydb.DownloadControlAllocation) artifact.DownloadControlAllocation {
	return artifact.DownloadControlAllocation{ID: uid(r.ID), RootID: uid(r.RootID), AuditStoreID: uid(r.AuditStoreID), ResponseLimit: r.ResponseLimit, WindowLimit: r.WindowLimit, AuditByteLimit: r.AuditByteLimit, ValidUntil: r.ValidUntil.Time, AuditWriteUntil: r.AuditWriteUntil.Time}
}

// This configuration facet uses separately scoped installation credentials.
// It does not accept a public transfer request or create evidence authority.
func (s *Downloads) BindDownloadControlAllocation(ctx context.Context, a artifact.DownloadControlAllocation) error {
	a.ValidUntil = a.ValidUntil.UTC().Truncate(time.Microsecond)
	a.AuditWriteUntil = a.AuditWriteUntil.UTC().Truncate(time.Microsecond)
	if !a.Valid() || a.RootID != s.root {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, e := q.LockPermissionStream(ctx, id(s.root)); e != nil {
			return e
		}
		parent, e := q.LockDownloadAllocation(ctx, custodydb.LockDownloadAllocationParams{ID: id(a.ID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		old, e := q.ReadDownloadControlAllocation(ctx, custodydb.ReadDownloadControlAllocationParams{ID: id(a.ID), RootID: id(s.root)})
		if e == nil {
			v := downloadControl(old)
			if v.ID != a.ID || v.RootID != a.RootID || v.AuditStoreID != a.AuditStoreID || v.ResponseLimit != a.ResponseLimit || v.WindowLimit != a.WindowLimit || v.AuditByteLimit != a.AuditByteLimit || !v.ValidUntil.Equal(a.ValidUntil) || !v.AuditWriteUntil.Equal(a.AuditWriteUntil) {
				return privacy.ErrConflict
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !n.Time.Before(a.ValidUntil) || a.ValidUntil.After(parent.ValidUntil.Time) || a.WindowLimit > (parent.OutputLimit-1)/artifact.DownloadWindowBytes+1+a.ResponseLimit {
			return artifact.ErrInvalid
		}
		_, e = q.InsertDownloadControlAllocation(ctx, custodydb.InsertDownloadControlAllocationParams{ID: id(a.ID), RootID: id(s.root), AuditStoreID: id(a.AuditStoreID), ResponseLimit: a.ResponseLimit, WindowLimit: a.WindowLimit, AuditByteLimit: a.AuditByteLimit, ValidUntil: ts(a.ValidUntil), AuditWriteUntil: ts(a.AuditWriteUntil)})
		return e
	})
}
func decodeResponse(r custodydb.DownloadResponse) (artifact.DownloadResponse, error) {
	var p artifact.DownloadResponsePlan
	if json.Unmarshal(r.PlanJson, &p) != nil {
		return artifact.DownloadResponse{}, privacy.ErrFence
	}
	v := artifact.DownloadResponse{ID: uid(r.ID), SessionID: uid(r.SessionID), OwnerID: uid(r.OwnerID), Generation: r.Generation, Plan: p, StartedAt: r.StartedAt.Time, Until: r.UntilAt.Time, WindowCount: r.WindowCount, CompletedWindows: r.CompletedWindows, EmittedBytes: r.EmittedBytes, LeaseSequence: r.LeaseSequence, LeaseUntil: r.LeaseUntil.Time, Closed: r.Closed}
	if r.ActiveWindow.Valid {
		v.ActiveWindowID = uid(r.ActiveWindow)
	}
	if !v.Valid() || v.Plan.Windows() != r.ReservedWindows {
		return artifact.DownloadResponse{}, privacy.ErrFence
	}
	return v, nil
}

// Uses the same existing context publication fence. This does not fabricate a
// generic core/packet catalog authority; that source adapter remains pending.
func (s *Downloads) responseTransaction(ctx context.Context, sessionID string, a artifact.DownloadAuthority, fn func(*custodydb.Queries, artifact.DownloadSession, time.Time) error) error {
	if !authorization.UUID(sessionID) || a.Scope.RootID != s.root {
		return artifact.ErrInvalid
	}
	topology, e := s.retention.observe(ctx, a.Scope.ClusterID)
	if e != nil {
		return e
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		recovery, e := s.recovery.lock(ctx, q, s.root, a.Environment.Recovery())
		if e != nil {
			return e
		}
		p, e := q.LockPermissionStream(ctx, id(s.root))
		if e != nil {
			return e
		}
		row, e := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(sessionID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		current, e := loadDownload(ctx, q, row)
		if e != nil {
			return e
		}
		if current.Scope != a.Scope {
			return privacy.ErrFence
		}
		if e = s.downloadFence(ctx, q, p, a, topology, recovery); e != nil {
			return e
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e = fn(q, current, now.Time.UTC()); e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return s.downloadFence(ctx, q, p, a, topology, recovery)
	})
}
func responseBusy(ctx context.Context, q *custodydb.Queries, s artifact.DownloadSession, now time.Time) error {
	r, e := q.CurrentDownloadResponse(ctx, custodydb.CurrentDownloadResponseParams{SessionID: id(s.ID), RootID: id(s.Scope.RootID)})
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if r.Generation == s.Generation && !r.Closed && now.Before(r.LeaseUntil.Time) {
		return artifact.ErrDownloadConflict
	}
	return nil
}
func (s *Downloads) BeginDownloadResponse(ctx context.Context, sessionID string, a artifact.DownloadAuthority, r artifact.DownloadResponse) (artifact.DownloadResponse, error) {
	return s.beginDownloadResponse(ctx, sessionID, a, r, false)
}
func (s *Downloads) beginDownloadResponse(ctx context.Context, sessionID string, a artifact.DownloadAuthority, r artifact.DownloadResponse, firstContext bool) (artifact.DownloadResponse, error) {
	var out artifact.DownloadResponse
	e := s.responseTransaction(ctx, sessionID, a, func(q *custodydb.Queries, current artifact.DownloadSession, now time.Time) error {
		if e := responseBusy(ctx, q, current, now); e != nil {
			return e
		}
		if firstContext {
			if current.StopProtocol != artifact.DownloadStopProtocol {
				return artifact.ErrDownloadUnavailable
			}
			w, e := q.LatestDownloadWorker(ctx, custodydb.LatestDownloadWorkerParams{SessionID: id(sessionID), RootID: id(s.root)})
			if e != nil {
				return e
			}
			worker, e := currentAuditedWorker(w)
			if e != nil || worker.Intent.Generation != 1 || worker.Intent.Authority.Scope != a.Scope || w.TerminationJson != nil || w.RetiredProofJson != nil {
				return artifact.ErrDownloadUnavailable
			}
			control, e := readContextNativeControl(ctx, q, current, worker.Intent.ID)
			if e != nil {
				return e
			}
			if !control.canRespond() {
				return artifact.ErrDownloadUnavailable
			}
		}
		streams, e := q.DownloadStreams(ctx, custodydb.DownloadStreamsParams{RootID: id(s.root), PrincipalKey: principalKey(a.Scope.Principal)})
		if e != nil {
			return e
		}
		if streams.Total >= 16 || streams.Principal >= 2 {
			return artifact.ErrDownloadCapacity
		}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		current, out, e = current.BeginResponse(a, r, n.Time.UTC())
		if e != nil {
			return e
		}
		out.StartedAt = out.StartedAt.UTC().Truncate(time.Microsecond)
		out.Until = out.Until.UTC().Truncate(time.Microsecond)
		out.LeaseUntil = out.LeaseUntil.UTC().Truncate(time.Microsecond)
		encoded, e := json.Marshal(out.Plan)
		if e != nil {
			return e
		}
		stored, e := q.InsertDownloadResponse(ctx, custodydb.InsertDownloadResponseParams{ID: id(out.ID), RootID: id(s.root), SessionID: id(sessionID), OwnerID: id(out.OwnerID), Generation: out.Generation, PlanJson: encoded, ReservedWindows: out.Plan.Windows(), StartedAt: ts(out.StartedAt), UntilAt: ts(out.Until), LeaseUntil: ts(out.LeaseUntil)})
		if e != nil {
			return e
		}
		out, e = decodeResponse(stored)
		if e != nil {
			return e
		}
		return updateDownload(ctx, q, current)
	})
	if e != nil {
		return artifact.DownloadResponse{}, e
	}
	return out, nil
}

// Close is monotonic historical cleanup after the owning writer joined. It
// neither authorizes new bytes nor refunds any response/window reservation.
func (s *Downloads) CloseDownloadResponse(ctx context.Context, sessionID, responseID, ownerID string) error {
	if !authorization.UUID(sessionID) || !authorization.UUID(responseID) || !authorization.UUID(ownerID) {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, e := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(sessionID), RootID: id(s.root)}); e != nil {
			return e
		}
		_, e := q.CloseDownloadResponse(ctx, custodydb.CloseDownloadResponseParams{ID: id(responseID), SessionID: id(sessionID), RootID: id(s.root), OwnerID: id(ownerID)})
		return e
	})
}
func sameJSON(a, b any) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && bytes.Equal(x, y)
}
