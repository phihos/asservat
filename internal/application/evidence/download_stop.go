package evidence

import (
	"context"
	"crypto/sha256"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// DownloadStopLedger fences the session, stores the stop and writes its audit
// row in one SQL transaction (ADR-330 D6). A retry with the same key returns
// the stored stop; another key conflicts.
type DownloadStopLedger interface {
	StopDownload(context.Context, identity.Identity, string, artifact.Digest, string) (artifact.DownloadStop, error)
}

// ContextDownloadStopCoordinator stops a download for its original caller and
// client. Stop needs no evidence-read scope and spends no transfer allowance.
type ContextDownloadStopCoordinator struct {
	Ledger DownloadStopLedger
	Now    func() time.Time
	// Required in installed composition; nil when no native runtime exists.
	Active DownloadActiveTransfers
}

func DownloadStopKeyDigest(key string) artifact.Digest {
	return sha256.Sum256([]byte("download-stop-key/v1\x00" + key))
}

func (s ContextDownloadStopCoordinator) CancelContextDownload(ctx context.Context, current identities.CurrentIdentity, downloadID, key, requestID string) (artifact.DownloadStopReceipt, error) {
	var zero artifact.DownloadStopReceipt
	if ctx == nil || current == nil || s.Ledger == nil || s.Now == nil || !authorization.UUID(downloadID) || !authorization.UUID(requestID) || !identity.Text(key, 128) {
		return zero, artifact.ErrDownloadUnavailable
	}
	i, e := current.ResolveIdentity(ctx)
	observed := s.Now()
	if e != nil || !i.Valid(observed) || ctx.Err() != nil {
		return zero, identity.ErrDenied
	}
	until := identity.Earlier(i.ValidUntil, observed.Add(artifact.DownloadLease))
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	stop, e := s.Ledger.StopDownload(ctx, i, downloadID, DownloadStopKeyDigest(key), requestID)
	if e != nil || !stop.Valid() || stop.Actor != i.Principal || stop.DownloadID != downloadID || stop.KeyDigest != DownloadStopKeyDigest(key) {
		return zero, artifact.ErrDownloadUnavailable
	}
	// The SQL stop already fences every later content check; this only ends
	// local responses early.
	if s.Active != nil {
		if e = s.Active.CancelDownloadTransfers(ctx, stop); e != nil {
			return zero, artifact.ErrDownloadUnavailable
		}
	}
	out := artifact.DownloadStopReceipt{DownloadID: downloadID, RequestID: stop.RequestID, State: stop.State, ObservedAt: observed, ValidUntil: until}
	if !out.Valid(s.Now()) {
		return zero, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
