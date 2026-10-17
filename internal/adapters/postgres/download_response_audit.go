package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"encoding/json"
)

// The audit facet has separate SQL credentials. Receipt acknowledgement never
// renews a delivery lease or releases uncertain output/control spend.
func (s *Downloads) AcknowledgeDownloadWindowIntent(ctx context.Context, i audit.DownloadWindowIntent, v audit.DownloadWindowWriteResult) error {
	return s.acknowledgeWindow(ctx, i, nil, v)
}
func (s *Downloads) AcknowledgeDownloadWindowOutcome(ctx context.Context, o audit.DownloadWindowAuditOutcome, v audit.DownloadWindowWriteResult) error {
	return s.acknowledgeWindow(ctx, o.Intent, &o, v)
}
func (s *Downloads) acknowledgeWindow(ctx context.Context, i audit.DownloadWindowIntent, o *audit.DownloadWindowAuditOutcome, v audit.DownloadWindowWriteResult) error {
	phase := "intent"
	if o != nil {
		phase = "outcome"
	}
	if !i.Valid() || i.Window.Authority.Scope.RootID != s.root || !v.Receipt.ValidDownloadWindow(i, phase) || o != nil && (!o.Valid() || !sameJSON(i, o.Intent)) || v.Completion != nil && (!auditapp.ValidDownloadWindowCompletion(*v.Completion, i, o) || v.Completion.Receipt != v.Receipt) {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		sr, e := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(i.Window.SessionID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		if _, e = q.LockDownloadResponse(ctx, custodydb.LockDownloadResponseParams{ID: id(i.Response.ID), SessionID: sr.ID, RootID: id(s.root)}); e != nil {
			return e
		}
		wr, e := q.LockDownloadWindow(ctx, custodydb.LockDownloadWindowParams{ID: id(i.Window.ID), ResponseID: id(i.Response.ID), SessionID: sr.ID})
		if e != nil {
			return e
		}
		stored, w, e := decodeWindow(wr)
		if e != nil {
			return e
		}
		if !sameJSON(i, stored) {
			return privacy.ErrConflict
		}
		receipt, e := json.Marshal(v.Receipt)
		if e != nil {
			return e
		}
		var completion []byte
		if v.Completion != nil {
			completion, e = json.Marshal(v.Completion)
			if e != nil {
				return e
			}
		}
		old, oldCompletion := wr.IntentReceipt, wr.IntentCompletion
		if o != nil {
			if w.Outcome == nil || !sameJSON(o.Outcome, *w.Outcome) {
				return privacy.ErrConflict
			}
			old, oldCompletion = wr.OutcomeReceipt, wr.OutcomeCompletion
		}
		if len(old) > 0 {
			var existing audit.Receipt
			if json.Unmarshal(old, &existing) != nil || existing != v.Receipt {
				return privacy.ErrConflict
			}
			if v.Completion != nil {
				var prior audit.DownloadWindowWriteCompletion
				if json.Unmarshal(oldCompletion, &prior) != nil || !sameJSON(prior, *v.Completion) {
					return privacy.ErrConflict
				}
			}
			return nil
		}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !n.Time.Before(i.Window.WriteUntil) || ctx.Err() != nil {
			return artifact.ErrDownloadExpired
		}
		var affected int64
		if o == nil {
			affected, e = q.AcknowledgeDownloadWindowIntent(ctx, custodydb.AcknowledgeDownloadWindowIntentParams{ID: wr.ID, ResponseID: wr.ResponseID, SessionID: sr.ID, IntentReceipt: receipt, IntentCompletion: completion})
		} else {
			affected, e = q.AcknowledgeDownloadWindowOutcome(ctx, custodydb.AcknowledgeDownloadWindowOutcomeParams{ID: wr.ID, ResponseID: wr.ResponseID, SessionID: sr.ID, OutcomeReceipt: receipt, OutcomeCompletion: completion})
		}
		if e == nil && affected != 1 {
			return privacy.ErrConflict
		}
		return e
	})
}
