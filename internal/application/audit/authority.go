package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"context"
)

type AuthorityLedger interface {
	PendingAuthorityAudits(context.Context) ([]value.AuthorityRecord, error)
	AcknowledgeAuthorityAudit(context.Context, value.AuthorityRecord, value.Receipt) error
}

// The writer verifies an immutable encrypted object before returning its pinned
// receipt. A database outbox insertion cannot implement this port.
type AuthorityWriter interface {
	WriteAuthorityAudit(context.Context, value.AuthorityRecord) (value.Receipt, error)
}
type AuthorityPublisher struct {
	Ledger  AuthorityLedger
	Objects AuthorityWriter
}

func (p AuthorityPublisher) PublishAuthority(ctx context.Context) error {
	if p.Ledger == nil || p.Objects == nil {
		return ErrUnavailable
	}
	rows, err := p.Ledger.PendingAuthorityAudits(ctx)
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
		receipt, err := p.Objects.WriteAuthorityAudit(ctx, r)
		if err != nil {
			return err
		}
		if err = p.Ledger.AcknowledgeAuthorityAudit(ctx, r, receipt); err != nil {
			return err
		}
	}
	return nil
}
