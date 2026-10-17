package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"context"
	"time"
)

type PolicyAcceptanceLedger interface {
	PendingPolicyAcceptances(context.Context) ([]value.PolicyAcceptance, error)
	AcknowledgePolicyAcceptance(context.Context, value.PolicyAcceptance, value.Receipt) error
}
type PolicyAcceptanceWriter interface {
	WritePolicyAcceptance(context.Context, value.PolicyAcceptance) (value.Receipt, error)
}
type PolicyAcceptancePublisher struct {
	Ledger  PolicyAcceptanceLedger
	Objects PolicyAcceptanceWriter
}

func (p PolicyAcceptancePublisher) PublishPolicyAcceptances(ctx context.Context) error {
	if p.Ledger == nil || p.Objects == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := p.Ledger.PendingPolicyAcceptances(ctx)
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
		receipt, err := p.Objects.WritePolicyAcceptance(ctx, r)
		if err != nil {
			return err
		}
		if !receipt.ValidPolicyAcceptance(r.RootID, r.ID) {
			return ErrUnavailable
		}
		if err = p.Ledger.AcknowledgePolicyAcceptance(ctx, r, receipt); err != nil {
			return err
		}
	}
	return nil
}
