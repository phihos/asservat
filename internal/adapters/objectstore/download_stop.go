package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"time"
)

// Separate stop-audit store/key credentials keep normal operation audit load
// from consuming the prepaid restrictive-action provider budget.
type DownloadStopObjects struct {
	Store   *Store
	Seal    evidence.KeySealer
	Open    evidence.KeyOpener
	StoreID string
}

func (s *DownloadStopObjects) CreateDownloadStop(ctx context.Context, d artifact.DownloadStopDecision) (audit.Receipt, error) {
	return s.record(ctx, d, true)
}
func (s *DownloadStopObjects) FindDownloadStop(ctx context.Context, d artifact.DownloadStopDecision) (audit.Receipt, error) {
	return s.record(ctx, d, false)
}
func (s *DownloadStopObjects) record(ctx context.Context, d artifact.DownloadStopDecision, create bool) (audit.Receipt, error) {
	if s == nil || s.Store == nil || s.Seal == nil || s.Open == nil || ctx == nil || ctx.Err() != nil || !d.Valid() || s.StoreID != d.StoreID {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	until := d.RetainUntil
	if create {
		until = d.WriteUntil
	}
	if !time.Now().Before(until) {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	var o Object
	var b []byte
	var e error
	key := artifact.DownloadStopKey(d.RootID, d.DownloadID)
	if create {
		ciphertext, sealErr := framed.SealDownloadStop(ctx, s.Seal, d)
		if sealErr != nil || int64(len(ciphertext)) > artifact.DownloadStopCipherLimit {
			return audit.Receipt{}, artifact.ErrDownloadUnavailable
		}
		defer clear(ciphertext)
		o, b, e = s.Store.putControlAudit(ctx, key, ciphertext, artifact.DownloadStopCipherLimit)
	} else {
		o, b, e = s.Store.readControlAudit(ctx, key, artifact.DownloadStopCipherLimit)
	}
	if e != nil {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	defer clear(b)
	if e = framed.VerifyDownloadStop(ctx, s.Open, d, b); e != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	return audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}, nil
}
