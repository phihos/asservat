package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DownloadStops stops a download for its original caller and client. It does
// not read catalog/native metadata or current evidence permits.
type DownloadStops struct {
	ledger *Ledger
	root   string
}

func NewDownloadStops(ctx context.Context, pool *pgxpool.Pool, root string) (*DownloadStops, error) {
	if !authorization.UUID(root) {
		return nil, artifact.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &DownloadStops{ledger: l, root: root}, nil
}

// StopDownload fences the session, stores the stop and writes its audit row
// in one transaction (ADR-330 D6). The stored stop is the idempotent outcome
// for the same key (D7); another key conflicts. Stop never refunds spend.
func (s *DownloadStops) StopDownload(ctx context.Context, i identity.Identity, downloadID string, key artifact.Digest, requestID string) (artifact.DownloadStop, error) {
	var out artifact.DownloadStop
	if s == nil || ctx == nil || !i.Valid(time.Now()) || !authorization.UUID(downloadID) || !authorization.UUID(requestID) || key == (artifact.Digest{}) {
		return out, artifact.ErrDownloadUnavailable
	}
	conflict := false
	e := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, e := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(downloadID), RootID: id(s.root)})
		if e != nil || !bytes.Equal(row.ActorKey, digest(i.Principal)) {
			return artifact.ErrDownloadUnavailable
		}
		session, e := decodeDownload(row)
		if e != nil || session.Scope.Principal != i.Principal {
			return artifact.ErrDownloadUnavailable
		}
		n, e := q.CurrentTime(ctx)
		if e != nil || !i.Valid(n.Time) {
			return artifact.ErrDownloadUnavailable
		}
		stored, e := q.ReadDownloadStop(ctx, custodydb.ReadDownloadStopParams{DownloadID: row.ID, RootID: row.RootID})
		if e == nil {
			if !bytes.Equal(stored.KeyDigest, key[:]) {
				conflict = true
				return artifact.ErrDownloadConflict
			}
			out = artifact.DownloadStop{RootID: s.root, DownloadID: downloadID, RequestID: uid(stored.RequestID), Actor: i.Principal, KeyDigest: key, State: stored.State}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		state := "AlreadyTerminal"
		if !session.State.Terminal() && n.Time.Before(session.Deadline) {
			state = "Cancelled"
			session.State = artifact.DownloadCancelled
		} else if !session.State.Terminal() {
			session.State = artifact.DownloadExpired
		}
		// The terminal state fences active generations through the existing
		// session checks. Historical byte accounting may still finish, never refund.
		if _, e = q.FenceDownloadStopState(ctx, custodydb.FenceDownloadStopStateParams{ID: row.ID, RootID: row.RootID, State: string(session.State)}); e != nil {
			return e
		}
		if _, e = q.InsertDownloadStop(ctx, custodydb.InsertDownloadStopParams{DownloadID: row.ID, RootID: row.RootID, RequestID: id(requestID), KeyDigest: key[:], State: state}); e != nil {
			return e
		}
		out = artifact.DownloadStop{RootID: s.root, DownloadID: downloadID, RequestID: requestID, Actor: i.Principal, KeyDigest: key, State: state}
		return InsertAuditEvent(ctx, q, audit.Event{ID: uuid.NewString(), OperationID: requestID, Kind: "download.stop", Operation: "cancel_artifact_download",
			Actor: i.Principal, Status: "success", Effect: "accepted", ArtifactIDs: []string{session.Scope.ArtifactID}})
	})
	if conflict {
		return artifact.DownloadStop{}, artifact.ErrDownloadConflict
	}
	if e != nil || !out.Valid() {
		return artifact.DownloadStop{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
