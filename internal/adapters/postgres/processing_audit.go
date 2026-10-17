package postgres

import (
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These constructors deliberately cannot name another lane. Separate producer,
// acknowledgement, cleanup and finalizer credentials retain the existing audit
// facets; SQL additionally requires the exact prepared privacy decision and
// retained rule/account reserve. They do not grant a human privacy permission.
func NewProcessingReleaseJournal(ctx context.Context, pool *pgxpool.Pool, policy value.OperationLifecyclePolicy, recovery *RecoveryTransactionGuard) (*OperationJournal, error) {
	if !policy.CertificateVerificationBacked() || policy.Lane != "processing" || policy.History.Layout != value.ProcessingReleaseHistoryLayout || recovery == nil || recovery.root != policy.RootID || recovery.installation != policy.InstallationID {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, app.ErrUnavailable
	}
	copied := *policy.History
	policy.History = &copied
	return &OperationJournal{ledger: l, root: policy.RootID, lane: "processing", recovery: recovery, lifecycle: &policy}, nil
}
func NewProcessingReleaseAcknowledgements(ctx context.Context, pool *pgxpool.Pool, policy value.OperationLifecyclePolicy, recovery *RecoveryTransactionGuard) (*OperationAcknowledgements, error) {
	j, e := NewProcessingReleaseJournal(ctx, pool, policy, recovery)
	if e != nil {
		return nil, e
	}
	return &OperationAcknowledgements{j}, nil
}
func NewProcessingReleaseLifecycles(ctx context.Context, pool *pgxpool.Pool, policy value.OperationLifecyclePolicy, recovery *RecoveryTransactionGuard) (*OperationLifecycles, error) {
	j, e := NewProcessingReleaseJournal(ctx, pool, policy, recovery)
	if e != nil {
		return nil, e
	}
	return &OperationLifecycles{journal: j}, nil
}

// Protected backing acceptance supplies both values. No ordinary audit caller
// can widen its lane or reserve, and an existing rule's reserve cannot shrink.
func (l *Ledger) ProvisionProcessingReleaseAuditPool(ctx context.Context, in app.OperationAuditPool, policy value.OperationLifecyclePolicy) error {
	if in.Accounts < 1 || in.Accounts > 1000000 || in.RecordsPerAccount < 16 || in.RecordsPerAccount > 1000000 || !policy.CertificateVerificationBacked() || policy.Lane != "processing" || policy.History.Layout != value.ProcessingReleaseHistoryLayout || in.Lane != "processing" || in.RootID != policy.RootID || policy.BackingRevision != in.ExpectedRevision+1 || policy.MetadataSlots < in.Accounts*in.RecordsPerAccount || policy.ValidUntil.Before(in.ValidUntil) || in.RecordsPerAccount < 16 || in.RetainedSeconds <= 30+2*policy.BackupHorizonSeconds+3*policy.CleanupBudgetSeconds+policy.ProofWindowSeconds {
		return app.ErrUnavailable
	}
	return l.provisionOperationAuditPool(ctx, in)
}
