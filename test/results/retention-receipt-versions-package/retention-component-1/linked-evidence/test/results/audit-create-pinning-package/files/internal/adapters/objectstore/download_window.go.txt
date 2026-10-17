package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// This purpose-bound synchronous owner creates at most one conditional PUT per
// invocation. Its exact SQL window reservation must precede Create. Unknown
// replies, 412 and Find never create a writer-completion fact.
type DownloadWindowAuditObjects struct {
	store   *Store
	storeID string
	seal    evidence.KeySealer
	open    evidence.KeyOpener
}

func NewDownloadWindowAuditObjects(s *Store, id string, k evidence.KeySealer, o evidence.KeyOpener) (*DownloadWindowAuditObjects, error) {
	if s == nil || !authorization.UUID(id) || k == nil || o == nil {
		return nil, artifact.ErrInvalid
	}
	return &DownloadWindowAuditObjects{s, id, k, o}, nil
}

var _ app.DownloadWindowObjects = (*DownloadWindowAuditObjects)(nil)

func (s *DownloadWindowAuditObjects) CreateDownloadWindowIntent(ctx context.Context, i audit.DownloadWindowIntent) (audit.DownloadWindowWriteResult, error) {
	return s.write(ctx, i, nil, true)
}
func (s *DownloadWindowAuditObjects) FindDownloadWindowIntent(ctx context.Context, i audit.DownloadWindowIntent) (audit.Receipt, error) {
	r, e := s.write(ctx, i, nil, false)
	return r.Receipt, e
}
func (s *DownloadWindowAuditObjects) CreateDownloadWindowOutcome(ctx context.Context, o audit.DownloadWindowAuditOutcome) (audit.DownloadWindowWriteResult, error) {
	return s.write(ctx, o.Intent, &o, true)
}
func (s *DownloadWindowAuditObjects) FindDownloadWindowOutcome(ctx context.Context, o audit.DownloadWindowAuditOutcome) (audit.Receipt, error) {
	r, e := s.write(ctx, o.Intent, &o, false)
	return r.Receipt, e
}
func (s *DownloadWindowAuditObjects) write(ctx context.Context, i audit.DownloadWindowIntent, o *audit.DownloadWindowAuditOutcome, create bool) (audit.DownloadWindowWriteResult, error) {
	var zero audit.DownloadWindowWriteResult
	if s == nil || ctx == nil || ctx.Err() != nil || !i.Valid() || i.Window.AuditStoreID != s.storeID || o != nil && (!o.Valid() || o.Intent != i) || !time.Now().Before(i.Window.WriteUntil) {
		return zero, artifact.ErrInvalid
	}
	call, cancel := context.WithDeadline(ctx, i.Window.WriteUntil)
	defer cancel()
	phase := "intent"
	if o != nil {
		phase = "outcome"
	}
	key := audit.DownloadWindowAuditKey(i.Window.Authority.Scope.RootID, i.Response.ID, i.Window.ID, phase)
	var put Object
	if create {
		var b []byte
		var e error
		if o == nil {
			b, e = framed.SealDownloadWindowIntent(call, s.seal, i)
		} else {
			b, e = framed.SealDownloadWindowOutcome(call, s.seal, *o)
		}
		if e != nil || len(b) == 0 || len(b) > int(artifact.DownloadWindowAuditBytes) {
			return zero, artifact.ErrDownloadUnavailable
		}
		defer clear(b)
		put, e = s.store.PutSmall(call, key, b)
		if e != nil {
			return zero, e
		}
	}
	var obj Object
	var b []byte
	var e error
	if create {
		obj, b, e = s.store.readAcknowledgedControlAudit(call, put, artifact.DownloadWindowAuditBytes)
	} else {
		obj, b, e = s.store.readControlAudit(call, key, artifact.DownloadWindowAuditBytes)
	}
	if e != nil {
		return zero, e
	}
	defer clear(b)
	if create && obj != put {
		return zero, artifact.ErrIntegrity
	}
	if o == nil {
		e = framed.VerifyDownloadWindowIntent(call, s.open, i, b)
	} else {
		e = framed.VerifyDownloadWindowOutcome(call, s.open, *o, b)
	}
	if e != nil || call.Err() != nil || ctx.Err() != nil {
		return zero, artifact.ErrIntegrity
	}
	receipt := audit.Receipt{Key: key, Version: obj.VersionID, ETag: obj.ETag, Bytes: obj.Bytes, SHA256: obj.SHA256}
	if !receipt.ValidDownloadWindow(i, phase) {
		return zero, artifact.ErrIntegrity
	}
	result := audit.DownloadWindowWriteResult{Receipt: receipt}
	if create {
		finished := time.Now().UTC()
		if !finished.Before(i.Window.WriteUntil) {
			return zero, artifact.ErrDownloadExpired
		}
		closed := finished.Truncate(time.Microsecond)
		cancel()
		c := audit.DownloadWindowWriteCompletion{RootID: i.Window.Authority.Scope.RootID, ResponseID: i.Response.ID, WindowID: i.Window.ID, StoreID: s.storeID, Phase: phase, RecordDigest: app.DownloadWindowRecordDigest(i, o), Receipt: receipt, CompletedAt: closed}
		if !app.ValidDownloadWindowCompletion(c, i, o) || ctx.Err() != nil {
			return zero, artifact.ErrIntegrity
		}
		result.Completion = &c
	}
	return result, nil
}
