package audit

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/audit"
)

type BootstrapIssueLedger interface {
	PendingBootstrapIssues(context.Context) ([]value.BootstrapIssue, error)
	AcknowledgeBootstrapIssue(context.Context, value.BootstrapIssue, value.Receipt) error
}
type BootstrapIssueWriter interface {
	WriteBootstrapIssue(context.Context, value.BootstrapIssue) (value.Receipt, error)
}
type BootstrapIssuePublisher struct {
	Ledger  BootstrapIssueLedger
	Objects BootstrapIssueWriter
}

func (p BootstrapIssuePublisher) PublishBootstrapIssues(ctx context.Context) error {
	if p.Ledger == nil || p.Objects == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := p.Ledger.PendingBootstrapIssues(ctx)
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
		receipt, err := p.Objects.WriteBootstrapIssue(ctx, r)
		if err != nil {
			return err
		}
		if !receipt.ValidBootstrapIssue(r.Binding.InstallationID, r.ID) {
			return ErrUnavailable
		}
		if err = p.Ledger.AcknowledgeBootstrapIssue(ctx, r, receipt); err != nil {
			return err
		}
	}
	return nil
}
