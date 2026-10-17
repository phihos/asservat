package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

type captureLifecycleQueries struct{ *custodydb.Queries }

// Capture cleanup uses only the private filtered views and the existing fixed
// retirement functions. Source acceptance and role grants are separate duties.
func NewCaptureOperationLifecycles(ctx context.Context, pool *pgxpool.Pool, policy value.OperationLifecyclePolicy, recovery *RecoveryTransactionGuard) (*OperationLifecycles, error) {
	if !value.CaptureOperationPolicy(policy) {
		return nil, app.ErrUnavailable
	}
	return NewScopedCaptureOperationLifecycles(ctx, pool, policy.RootID, policy.InstallationID, policy.StoreID, recovery)
}

// The installed cleanup compartment pins storage and recovery identity, not a
// newly selected policy. Every historical row still supplies and validates its
// own original immutable lifecycle in the existing locked transaction.
func NewScopedCaptureOperationLifecycles(ctx context.Context, pool *pgxpool.Pool, root, installation, store string, recovery *RecoveryTransactionGuard) (*OperationLifecycles, error) {
	scope := captureLifecycleScope{root, installation, store}
	if !scope.valid() || recovery == nil || recovery.root != root || recovery.installation != installation {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	j := &OperationJournal{ledger: l, root: root, lane: "capture", recovery: recovery}
	return &OperationLifecycles{journal: j, capture: true, captureScope: scope}, nil
}

type captureLifecycleScope struct{ root, installation, store string }

func (s captureLifecycleScope) valid() bool {
	return authorization.UUID(s.root) && authorization.UUID(s.installation) && authorization.UUID(s.store)
}

func (s captureLifecycleScope) matches(in value.OperationIntent) bool {
	return s.valid() && in.Valid() && in.Lifecycle != nil && in.RootID == s.root &&
		in.Name == value.CaptureOperationName && value.CaptureOperationPolicy(in.Lifecycle.Policy) &&
		in.Lifecycle.Policy.RootID == s.root && in.Lifecycle.Policy.InstallationID == s.installation && in.Lifecycle.Policy.StoreID == s.store
}

func (q captureLifecycleQueries) AckOperationCertificate(ctx context.Context, arg custodydb.AckOperationCertificateParams) (int64, error) {
	return q.Queries.CaptureAckOperationCertificate(ctx, custodydb.CaptureAckOperationCertificateParams(arg))
}

func (q captureLifecycleQueries) AckTerminalOperationPurge(ctx context.Context, arg custodydb.AckTerminalOperationPurgeParams) (int64, error) {
	return q.Queries.CaptureAckTerminalOperationPurge(ctx, custodydb.CaptureAckTerminalOperationPurgeParams(arg))
}

func (q captureLifecycleQueries) ClaimOperationCertificate(ctx context.Context, arg custodydb.ClaimOperationCertificateParams) (int64, error) {
	return q.Queries.CaptureClaimOperationCertificate(ctx, custodydb.CaptureClaimOperationCertificateParams(arg))
}

func (q captureLifecycleQueries) ClaimOperationCertificateVerification(ctx context.Context, arg custodydb.ClaimOperationCertificateVerificationParams) (int64, error) {
	return q.Queries.CaptureClaimOperationCertificateVerification(ctx, custodydb.CaptureClaimOperationCertificateVerificationParams(arg))
}

func (q captureLifecycleQueries) CompleteOperationCertificate(ctx context.Context, arg custodydb.CompleteOperationCertificateParams) (int64, error) {
	return q.Queries.CaptureCompleteOperationCertificate(ctx, custodydb.CaptureCompleteOperationCertificateParams(arg))
}

func (q captureLifecycleQueries) CompleteOperationIntent(ctx context.Context, arg custodydb.CompleteOperationIntentParams) (int64, error) {
	return q.Queries.CaptureCompleteOperationIntent(ctx, custodydb.CaptureCompleteOperationIntentParams(arg))
}

func (q captureLifecycleQueries) CompleteOperationOutcome(ctx context.Context, arg custodydb.CompleteOperationOutcomeParams) (int64, error) {
	return q.Queries.CaptureCompleteOperationOutcome(ctx, custodydb.CaptureCompleteOperationOutcomeParams(arg))
}

func (q captureLifecycleQueries) DueOperationAuditHistory(ctx context.Context, arg custodydb.DueOperationAuditHistoryParams) ([]custodydb.DueOperationAuditHistoryRow, error) {
	rows, e := q.Queries.CaptureDueOperationAuditHistory(ctx, custodydb.CaptureDueOperationAuditHistoryParams(arg))
	if e != nil {
		return nil, e
	}
	out := make([]custodydb.DueOperationAuditHistoryRow, len(rows))
	for i, v := range rows {
		out[i] = custodydb.DueOperationAuditHistoryRow(v)
	}
	return out, nil
}

func (q captureLifecycleQueries) LeaseOperationPurge(ctx context.Context, arg custodydb.LeaseOperationPurgeParams) (int64, error) {
	return q.Queries.CaptureLeaseOperationPurge(ctx, custodydb.CaptureLeaseOperationPurgeParams(arg))
}

func (q captureLifecycleQueries) LeaseOverdueOperationPurge(ctx context.Context, arg custodydb.LeaseOverdueOperationPurgeParams) (int64, error) {
	return q.Queries.CaptureLeaseOverdueOperationPurge(ctx, custodydb.CaptureLeaseOverdueOperationPurgeParams(arg))
}

func (q captureLifecycleQueries) LockOperationAudit(ctx context.Context, arg custodydb.LockOperationAuditParams) (custodydb.OperationAudit, error) {
	row, e := q.Queries.CaptureLockOperationAudit(ctx, custodydb.CaptureLockOperationAuditParams(arg))
	return custodydb.OperationAudit(row), e
}

func (q captureLifecycleQueries) LockOperationAuditPool(ctx context.Context, arg custodydb.LockOperationAuditPoolParams) (custodydb.OperationAuditPool, error) {
	row, e := q.Queries.CaptureLockOperationAuditPool(ctx, custodydb.CaptureLockOperationAuditPoolParams(arg))
	return custodydb.OperationAuditPool(row), e
}

func (q captureLifecycleQueries) LockOperationLifecycle(ctx context.Context, arg custodydb.LockOperationLifecycleParams) (custodydb.OperationAuditLifecycle, error) {
	row, e := q.Queries.CaptureLockOperationLifecycle(ctx, custodydb.CaptureLockOperationLifecycleParams(arg))
	return custodydb.OperationAuditLifecycle(row), e
}

func (q captureLifecycleQueries) LockOperationLifecycleAccount(ctx context.Context, arg custodydb.LockOperationLifecycleAccountParams) (custodydb.OperationAuditAccount, error) {
	row, e := q.Queries.CaptureLockOperationLifecycleAccount(ctx, custodydb.CaptureLockOperationLifecycleAccountParams(arg))
	return custodydb.OperationAuditAccount(row), e
}

func (q captureLifecycleQueries) ReadOperationForLifecycle(ctx context.Context, arg custodydb.ReadOperationForLifecycleParams) (custodydb.OperationAudit, error) {
	row, e := q.Queries.CaptureReadOperationForLifecycle(ctx, custodydb.CaptureReadOperationForLifecycleParams(arg))
	return custodydb.OperationAudit(row), e
}

func (q captureLifecycleQueries) SaveOriginalOperationPurge(ctx context.Context, arg custodydb.SaveOriginalOperationPurgeParams) (int64, error) {
	return q.Queries.CaptureSaveOriginalOperationPurge(ctx, custodydb.CaptureSaveOriginalOperationPurgeParams(arg))
}

func (q captureLifecycleQueries) SaveOverdueOperationPurge(ctx context.Context, arg custodydb.SaveOverdueOperationPurgeParams) (int64, error) {
	return q.Queries.CaptureSaveOverdueOperationPurge(ctx, custodydb.CaptureSaveOverdueOperationPurgeParams(arg))
}

func (q captureLifecycleQueries) SaveTerminalOperationPurge(ctx context.Context, arg custodydb.SaveTerminalOperationPurgeParams) (int64, error) {
	return q.Queries.CaptureSaveTerminalOperationPurge(ctx, custodydb.CaptureSaveTerminalOperationPurgeParams(arg))
}

func (q captureLifecycleQueries) FinishOperationRetirement(ctx context.Context, arg custodydb.FinishOperationRetirementParams) (bool, error) {
	return q.Queries.CaptureFinishOperationRetirement(ctx, custodydb.CaptureFinishOperationRetirementParams(arg))
}
func (q captureLifecycleQueries) FinishOperationHistory(ctx context.Context, arg custodydb.FinishOperationHistoryParams) (custodydb.FinishOperationHistoryRow, error) {
	row, e := q.Queries.CaptureFinishOperationHistory(ctx, custodydb.CaptureFinishOperationHistoryParams(arg))
	return custodydb.FinishOperationHistoryRow(row), e
}
