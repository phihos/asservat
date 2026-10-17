package audit

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/audit"
)

type CaptureIntentLedger interface {
	PendingCaptureIntents(context.Context) ([]value.CaptureIntent, error)
	AcknowledgeCaptureIntent(context.Context, value.CaptureIntent, value.Receipt) error
}
type CaptureIntentWriter interface {
	WriteCaptureIntent(context.Context, value.CaptureIntent) (value.Receipt, error)
}
type CaptureIntentPublisher struct {
	Ledger  CaptureIntentLedger
	Objects CaptureIntentWriter
}

func (p CaptureIntentPublisher) PublishCaptureIntents(ctx context.Context) error {
	if p.Ledger == nil || p.Objects == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := p.Ledger.PendingCaptureIntents(ctx)
	if err != nil {
		return err
	}
	if len(rows) > 2 {
		return ErrUnavailable
	}
	for _, r := range rows {
		if !r.Valid() || ctx.Err() != nil {
			return ErrUnavailable
		}
		receipt, err := p.Objects.WriteCaptureIntent(ctx, r)
		if err != nil {
			return err
		}
		if !receipt.ValidCaptureIntent(r.RootID, r.CaptureID) {
			return ErrUnavailable
		}
		if err = p.Ledger.AcknowledgeCaptureIntent(ctx, r, receipt); err != nil {
			return err
		}
	}
	return nil
}
