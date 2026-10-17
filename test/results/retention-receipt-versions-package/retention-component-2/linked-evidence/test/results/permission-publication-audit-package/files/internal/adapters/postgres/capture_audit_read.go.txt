package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"bytes"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// CaptureOperationIntents has only the purpose-pinned filtered SELECT view.
// Historical acknowledgement grants neither writer closure nor current start.
type CaptureOperationIntents struct {
	ledger *Ledger
	root   string
}

var _ app.CaptureOperationIntentReader = (*CaptureOperationIntents)(nil)

func NewCaptureOperationIntents(ctx context.Context, pool *pgxpool.Pool, root string) (*CaptureOperationIntents, error) {
	if !authorization.UUID(root) {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &CaptureOperationIntents{l, root}, nil
}
func (s *CaptureOperationIntents) ReadCaptureOperationIntent(ctx context.Context, captureID string) (app.CaptureOperationIntentSnapshot, error) {
	var out app.CaptureOperationIntentSnapshot
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(captureID) {
		return out, app.ErrUnavailable
	}
	until := time.Now().Add(5 * time.Second)
	call, close := context.WithDeadline(ctx, until)
	defer close()
	e := s.ledger.transaction(call, func(q *custodydb.Queries) error {
		row, e := q.ReadCaptureOperationIntent(call, custodydb.ReadCaptureOperationIntentParams{RootID: id(s.root), ID: id(captureID)})
		if e != nil {
			return e
		}
		out, e = exactCaptureOperationIntent(custodydb.ContextCapture(row))
		return e
	})
	if e != nil || call.Err() != nil || !time.Now().Before(until) {
		return app.CaptureOperationIntentSnapshot{}, app.ErrUnavailable
	}
	return out, nil
}
func exactCaptureOperationIntent(row custodydb.ContextCapture) (app.CaptureOperationIntentSnapshot, error) {
	var out app.CaptureOperationIntentSnapshot
	if !row.IntentOperationID.Valid || row.IntentOperationID != row.ID {
		return out, app.ErrUnavailable
	}
	intent, e := captureIntent(row)
	if e != nil {
		return out, e
	}
	out.Intent = intent
	out.OperationID = uid(row.IntentOperationID)
	if !row.IntentAcknowledgedAt.Valid {
		if row.State != capture.PendingAudit || row.IntentDigest != nil || row.IntentObjectKey.Valid || row.IntentObjectVersion.Valid || row.IntentObjectEtag.Valid || row.IntentObjectBytes.Valid || row.IntentObjectSha256 != nil {
			return app.CaptureOperationIntentSnapshot{}, app.ErrUnavailable
		}
		return out, nil
	}
	receipt := value.Receipt{Key: row.IntentObjectKey.String, Version: row.IntentObjectVersion.String, ETag: row.IntentObjectEtag.String, Bytes: row.IntentObjectBytes.Int64}
	copy(receipt.SHA256[:], row.IntentObjectSha256)
	if row.State != capture.IntentAudited || row.IntentAcknowledgedAt.Time.Before(intent.CreatedAt) || !row.IntentAcknowledgedAt.Time.Before(minCaptureAuditTime(intent.Deadline, intent.CreatedAt.Add(30*time.Second))) || !bytes.Equal(row.IntentDigest, digest(intent)) || !row.IntentObjectKey.Valid || !row.IntentObjectVersion.Valid || !row.IntentObjectEtag.Valid || !row.IntentObjectBytes.Valid || len(row.IntentObjectSha256) != 32 || !receipt.ValidOperation(intent.RootID, intent.CaptureID, "intent") || receipt.Version == "" || receipt.Version == "null" {
		return app.CaptureOperationIntentSnapshot{}, app.ErrUnavailable
	}
	out.Receipt = &receipt
	return out, nil
}
