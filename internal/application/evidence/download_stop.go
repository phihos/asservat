package evidence

import (
	"context"
	"crypto/sha256"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type DownloadStopSnapshot struct {
	Decision               artifact.DownloadStopDecision
	WriteStarted           bool
	Receipt                *audit.Receipt
	ObservedAt, ValidUntil time.Time
}
type DownloadStopLedger interface {
	StopDownload(context.Context, identity.Identity, string, artifact.Digest, string) (DownloadStopSnapshot, error)
	ClaimDownloadStopWrite(context.Context, artifact.DownloadStopDecision) (bool, error)
}
type DownloadStopPending interface {
	PendingDownloadStops(context.Context) ([]DownloadStopSnapshot, error)
}
type DownloadStopAcknowledgements interface {
	AcknowledgeDownloadStop(context.Context, artifact.DownloadStopDecision, audit.Receipt) error
}
type DownloadStopObjects interface {
	CreateDownloadStop(context.Context, artifact.DownloadStopDecision) (audit.Receipt, error)
	FindDownloadStop(context.Context, artifact.DownloadStopDecision) (audit.Receipt, error)
}

// The SQL restriction commits before provider I/O. Every accepted download
// already owns its bounded write/metadata obligation; Stop never enters normal
// operation-audit admission or spends a new transfer/collection allowance.
type ContextDownloadStopCoordinator struct {
	Ledger           DownloadStopLedger
	Acknowledgements DownloadStopAcknowledgements
	Objects          DownloadStopObjects
	Now              func() time.Time
	// Required in installed composition; nil preserves legacy component callers.
	Active DownloadActiveTransfers
}

func DownloadStopKeyDigest(key string) artifact.Digest {
	return sha256.Sum256([]byte("download-stop-key/v1\x00" + key))
}
func (s ContextDownloadStopCoordinator) CancelContextDownload(ctx context.Context, current identities.CurrentIdentity, downloadID, key, requestID string) (artifact.DownloadStopReceipt, error) {
	var zero artifact.DownloadStopReceipt
	if ctx == nil || current == nil || s.Ledger == nil || s.Acknowledgements == nil || s.Objects == nil || s.Now == nil || !authorization.UUID(downloadID) || !authorization.UUID(requestID) || !identity.Text(key, 128) {
		return zero, artifact.ErrDownloadUnavailable
	}
	initial, e := current.ResolveIdentity(ctx)
	if e != nil || !initial.Valid(s.Now()) || ctx.Err() != nil {
		return zero, identity.ErrDenied
	}
	until := identity.Earlier(initial.ValidUntil, s.Now().Add(artifact.DownloadLease))
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	snap, e := s.Ledger.StopDownload(ctx, initial, downloadID, DownloadStopKeyDigest(key), requestID)
	if e != nil || !snap.Decision.Valid() || snap.Decision.Actor != initial.Principal || snap.Decision.DownloadID != downloadID || snap.Decision.KeyDigest != DownloadStopKeyDigest(key) || !identity.Fresh(snap.ObservedAt, snap.ValidUntil, s.Now(), artifact.DownloadLease) {
		return zero, artifact.ErrDownloadUnavailable
	}
	until = identity.Earlier(until, snap.ValidUntil)
	if s.Active != nil {
		local, end := context.WithDeadline(ctx, until)
		e = s.Active.CancelDownloadTransfers(local, snap.Decision)
		end()
		if e != nil || ctx.Err() != nil || !s.Now().Before(until) {
			return zero, artifact.ErrDownloadUnavailable
		}
	}
	state := "pending"
	if snap.Receipt != nil && validDownloadStopReceipt(snap.Decision, *snap.Receipt) {
		state = "recorded"
	} else if !s.Now().Before(snap.Decision.WriteUntil) {
		state = "overdue"
	} else if s.record(ctx, snap) == nil {
		state = "recorded"
	}
	final, e := current.ResolveIdentity(ctx)
	if e != nil || !downloadSameIdentity(initial, final, s.Now()) || ctx.Err() != nil {
		return zero, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	out := artifact.DownloadStopReceipt{DownloadID: downloadID, RequestID: snap.Decision.RequestID, State: snap.Decision.State, AuditState: state, ObservedAt: snap.ObservedAt, ValidUntil: until}
	if !out.Valid(s.Now()) {
		return zero, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

func validDownloadStopReceipt(d artifact.DownloadStopDecision, r audit.Receipt) bool {
	return r.Key == artifact.DownloadStopKey(d.RootID, d.DownloadID) && r.Bytes > 0 && r.Bytes <= artifact.DownloadStopCipherLimit && r.SHA256 != (artifact.Digest{}) && identity.Text(r.ETag, 256) && (r.Version == "" || identity.Text(r.Version, 1024))
}
func (s ContextDownloadStopCoordinator) record(ctx context.Context, snap DownloadStopSnapshot) error {
	d := snap.Decision
	if !d.Valid() || !s.Now().Before(d.RetainUntil) || !snap.WriteStarted && !s.Now().Before(d.WriteUntil) {
		return artifact.ErrDownloadUnavailable
	}
	until := identity.Earlier(d.RetainUntil, s.Now().Add(artifact.DownloadLease))
	if !snap.WriteStarted {
		until = identity.Earlier(until, d.WriteUntil)
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	fresh, e := s.Ledger.ClaimDownloadStopWrite(ctx, d)
	if e != nil {
		return artifact.ErrDownloadUnavailable
	}
	var receipt audit.Receipt
	if fresh {
		receipt, e = s.Objects.CreateDownloadStop(ctx, d)
	} else {
		receipt, e = s.Objects.FindDownloadStop(ctx, d)
	}
	if e != nil || !validDownloadStopReceipt(d, receipt) {
		return artifact.ErrDownloadUnavailable
	}
	return s.Acknowledgements.AcknowledgeDownloadStop(ctx, d, receipt)
}

// ReconcilePending performs at most sixteen exact historical acknowledgements.
// It never creates a decision or resets its single write attempt. A missed
// creation window remains overdue and charged; a prior uncertain write permits
// at most the prepaid exact-object lookup attempts before the original cutoff.
func (s ContextDownloadStopCoordinator) ReconcilePending(ctx context.Context, pending DownloadStopPending) error {
	if ctx == nil || pending == nil || s.Ledger == nil || s.Acknowledgements == nil || s.Objects == nil || s.Now == nil {
		return artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, s.Now().Add(artifact.DownloadLease))
	defer cancel()
	snapshots, e := pending.PendingDownloadStops(ctx)
	if e != nil || len(snapshots) > 16 {
		return artifact.ErrDownloadUnavailable
	}
	var failed bool
	for _, snapshot := range snapshots {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !snapshot.Decision.Valid() || snapshot.Receipt != nil {
			return artifact.ErrDownloadUnavailable
		}
		// No retry of a creation whose original opportunity has ended.
		if !snapshot.WriteStarted && !s.Now().Before(snapshot.Decision.WriteUntil) {
			continue
		}
		if e = s.record(ctx, snapshot); e != nil {
			// A single unknown provider result must not prevent independent
			// prepaid obligations from using the remainder of this same pass.
			failed = true
		}
	}
	if failed {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
