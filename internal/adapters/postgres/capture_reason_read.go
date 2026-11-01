package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

var _ captureapp.CaptureReasonRecords = (*CaptureAuditJournal)(nil)

// ReadCaptureReasonRecord is historical control metadata, never a writer or
// reconciliation lookup. It preserves its own original SQL read interval and
// audit body retirement boundary without extending the capture's WriteUntil.
func (s *CaptureAuditJournal) ReadCaptureReasonRecord(ctx context.Context, captureID string) (captureapp.CaptureReasonRecord, error) {
	var zero captureapp.CaptureReasonRecord
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(captureID) {
		return zero, value.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var reply captureapp.CaptureReasonRecord
	err := s.ledger.transaction(call, func(q *custodydb.Queries) error {
		raw, err := q.ReadCaptureReason(call, custodydb.ReadCaptureReasonParams{RootID: id(s.policy.RootID), CaptureID: id(captureID)})
		if err != nil {
			return err
		}
		if len(raw) == 0 || len(raw) > 64<<10 {
			return value.ErrUnavailable
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&reply) != nil || !reply.Capture.Valid() || reply.Capture.RootID != s.policy.RootID || reply.Capture.CaptureID != captureID || reply.Capture.ReasonRef == nil || !auditapp.CaptureReasonEnvelopeMatches(*reply.Capture.ReasonRef, reply.Envelope) {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil || call.Err() != nil || !time.Now().Before(reply.ValidUntil) {
		return zero, value.ErrUnavailable
	}
	return reply, nil
}
