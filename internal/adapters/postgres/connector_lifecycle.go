package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This interface selects a fixed query set, not caller-selected relations. The
// common state machine, original recovery checks and final deadlines are shared.
type operationLifecycleQueries interface {
	AckOperationCertificate(ctx context.Context, arg custodydb.AckOperationCertificateParams) (int64, error)
	AckTerminalOperationPurge(ctx context.Context, arg custodydb.AckTerminalOperationPurgeParams) (int64, error)
	ClaimOperationCertificate(ctx context.Context, arg custodydb.ClaimOperationCertificateParams) (int64, error)
	ClaimOperationCertificateVerification(ctx context.Context, arg custodydb.ClaimOperationCertificateVerificationParams) (int64, error)
	CompleteOperationCertificate(ctx context.Context, arg custodydb.CompleteOperationCertificateParams) (int64, error)
	CompleteOperationIntent(ctx context.Context, arg custodydb.CompleteOperationIntentParams) (int64, error)
	CompleteOperationOutcome(ctx context.Context, arg custodydb.CompleteOperationOutcomeParams) (int64, error)
	DueOperationAuditHistory(ctx context.Context, arg custodydb.DueOperationAuditHistoryParams) ([]custodydb.DueOperationAuditHistoryRow, error)
	LeaseOperationPurge(ctx context.Context, arg custodydb.LeaseOperationPurgeParams) (int64, error)
	LeaseOverdueOperationPurge(ctx context.Context, arg custodydb.LeaseOverdueOperationPurgeParams) (int64, error)
	LockOperationAudit(ctx context.Context, arg custodydb.LockOperationAuditParams) (custodydb.OperationAudit, error)
	LockOperationAuditPool(ctx context.Context, arg custodydb.LockOperationAuditPoolParams) (custodydb.OperationAuditPool, error)
	LockOperationLifecycle(ctx context.Context, arg custodydb.LockOperationLifecycleParams) (custodydb.OperationAuditLifecycle, error)
	LockOperationLifecycleAccount(ctx context.Context, arg custodydb.LockOperationLifecycleAccountParams) (custodydb.OperationAuditAccount, error)
	ReadOperationForLifecycle(ctx context.Context, arg custodydb.ReadOperationForLifecycleParams) (custodydb.OperationAudit, error)
	SaveOriginalOperationPurge(ctx context.Context, arg custodydb.SaveOriginalOperationPurgeParams) (int64, error)
	SaveOverdueOperationPurge(ctx context.Context, arg custodydb.SaveOverdueOperationPurgeParams) (int64, error)
	SaveTerminalOperationPurge(ctx context.Context, arg custodydb.SaveTerminalOperationPurgeParams) (int64, error)
	FinishOperationRetirement(ctx context.Context, arg custodydb.FinishOperationRetirementParams) (bool, error)
	FinishOperationHistory(ctx context.Context, arg custodydb.FinishOperationHistoryParams) (custodydb.FinishOperationHistoryRow, error)
}

func (s *OperationLifecycles) queries(q *custodydb.Queries) operationLifecycleQueries {
	if s.capture {
		return captureLifecycleQueries{q}
	}
	if s.connector {
		return connectorLifecycleQueries{q}
	}
	return q
}

type connectorLifecycleQueries struct{ *custodydb.Queries }

// Connector cleanup uses only the private filtered views and the existing fixed
// retirement functions. Source acceptance and role grants are separate duties.
func NewConnectorOperationLifecycles(ctx context.Context, pool *pgxpool.Pool, policy value.OperationLifecyclePolicy, recovery *RecoveryTransactionGuard) (*OperationLifecycles, error) {
	if !connectorAuditPolicy(policy) || recovery == nil || recovery.root != policy.RootID || recovery.installation != policy.InstallationID {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	history := *policy.History
	policy.History = &history
	j := &OperationJournal{ledger: l, root: policy.RootID, lane: "identity", recovery: recovery, lifecycle: &policy}
	return &OperationLifecycles{journal: j, connector: true}, nil
}

func (q connectorLifecycleQueries) AckOperationCertificate(ctx context.Context, arg custodydb.AckOperationCertificateParams) (int64, error) {
	return q.Queries.ConnectorAckOperationCertificate(ctx, custodydb.ConnectorAckOperationCertificateParams(arg))
}

func (q connectorLifecycleQueries) AckTerminalOperationPurge(ctx context.Context, arg custodydb.AckTerminalOperationPurgeParams) (int64, error) {
	return q.Queries.ConnectorAckTerminalOperationPurge(ctx, custodydb.ConnectorAckTerminalOperationPurgeParams(arg))
}

func (q connectorLifecycleQueries) ClaimOperationCertificate(ctx context.Context, arg custodydb.ClaimOperationCertificateParams) (int64, error) {
	return q.Queries.ConnectorClaimOperationCertificate(ctx, custodydb.ConnectorClaimOperationCertificateParams(arg))
}

func (q connectorLifecycleQueries) ClaimOperationCertificateVerification(ctx context.Context, arg custodydb.ClaimOperationCertificateVerificationParams) (int64, error) {
	return q.Queries.ConnectorClaimOperationCertificateVerification(ctx, custodydb.ConnectorClaimOperationCertificateVerificationParams(arg))
}

func (q connectorLifecycleQueries) CompleteOperationCertificate(ctx context.Context, arg custodydb.CompleteOperationCertificateParams) (int64, error) {
	return q.Queries.ConnectorCompleteOperationCertificate(ctx, custodydb.ConnectorCompleteOperationCertificateParams(arg))
}

func (q connectorLifecycleQueries) CompleteOperationIntent(ctx context.Context, arg custodydb.CompleteOperationIntentParams) (int64, error) {
	return q.Queries.ConnectorCompleteOperationIntent(ctx, custodydb.ConnectorCompleteOperationIntentParams(arg))
}

func (q connectorLifecycleQueries) CompleteOperationOutcome(ctx context.Context, arg custodydb.CompleteOperationOutcomeParams) (int64, error) {
	return q.Queries.ConnectorCompleteOperationOutcome(ctx, custodydb.ConnectorCompleteOperationOutcomeParams(arg))
}

func (q connectorLifecycleQueries) DueOperationAuditHistory(ctx context.Context, arg custodydb.DueOperationAuditHistoryParams) ([]custodydb.DueOperationAuditHistoryRow, error) {
	rows, e := q.Queries.ConnectorDueOperationAuditHistory(ctx, custodydb.ConnectorDueOperationAuditHistoryParams(arg))
	if e != nil {
		return nil, e
	}
	out := make([]custodydb.DueOperationAuditHistoryRow, len(rows))
	for i, v := range rows {
		out[i] = custodydb.DueOperationAuditHistoryRow(v)
	}
	return out, nil
}

func (q connectorLifecycleQueries) LeaseOperationPurge(ctx context.Context, arg custodydb.LeaseOperationPurgeParams) (int64, error) {
	return q.Queries.ConnectorLeaseOperationPurge(ctx, custodydb.ConnectorLeaseOperationPurgeParams(arg))
}

func (q connectorLifecycleQueries) LeaseOverdueOperationPurge(ctx context.Context, arg custodydb.LeaseOverdueOperationPurgeParams) (int64, error) {
	return q.Queries.ConnectorLeaseOverdueOperationPurge(ctx, custodydb.ConnectorLeaseOverdueOperationPurgeParams(arg))
}

func (q connectorLifecycleQueries) LockOperationAudit(ctx context.Context, arg custodydb.LockOperationAuditParams) (custodydb.OperationAudit, error) {
	row, e := q.Queries.ConnectorLockOperationAudit(ctx, custodydb.ConnectorLockOperationAuditParams(arg))
	return custodydb.OperationAudit(row), e
}

func (q connectorLifecycleQueries) LockOperationAuditPool(ctx context.Context, arg custodydb.LockOperationAuditPoolParams) (custodydb.OperationAuditPool, error) {
	row, e := q.Queries.ConnectorLockOperationAuditPool(ctx, custodydb.ConnectorLockOperationAuditPoolParams(arg))
	return custodydb.OperationAuditPool(row), e
}

func (q connectorLifecycleQueries) LockOperationLifecycle(ctx context.Context, arg custodydb.LockOperationLifecycleParams) (custodydb.OperationAuditLifecycle, error) {
	row, e := q.Queries.ConnectorLockOperationLifecycle(ctx, custodydb.ConnectorLockOperationLifecycleParams(arg))
	return custodydb.OperationAuditLifecycle(row), e
}

func (q connectorLifecycleQueries) LockOperationLifecycleAccount(ctx context.Context, arg custodydb.LockOperationLifecycleAccountParams) (custodydb.OperationAuditAccount, error) {
	row, e := q.Queries.ConnectorLockOperationLifecycleAccount(ctx, custodydb.ConnectorLockOperationLifecycleAccountParams(arg))
	return custodydb.OperationAuditAccount(row), e
}

func (q connectorLifecycleQueries) ReadOperationForLifecycle(ctx context.Context, arg custodydb.ReadOperationForLifecycleParams) (custodydb.OperationAudit, error) {
	row, e := q.Queries.ConnectorReadOperationForLifecycle(ctx, custodydb.ConnectorReadOperationForLifecycleParams(arg))
	return custodydb.OperationAudit(row), e
}

func (q connectorLifecycleQueries) SaveOriginalOperationPurge(ctx context.Context, arg custodydb.SaveOriginalOperationPurgeParams) (int64, error) {
	return q.Queries.ConnectorSaveOriginalOperationPurge(ctx, custodydb.ConnectorSaveOriginalOperationPurgeParams(arg))
}

func (q connectorLifecycleQueries) SaveOverdueOperationPurge(ctx context.Context, arg custodydb.SaveOverdueOperationPurgeParams) (int64, error) {
	return q.Queries.ConnectorSaveOverdueOperationPurge(ctx, custodydb.ConnectorSaveOverdueOperationPurgeParams(arg))
}

func (q connectorLifecycleQueries) SaveTerminalOperationPurge(ctx context.Context, arg custodydb.SaveTerminalOperationPurgeParams) (int64, error) {
	return q.Queries.ConnectorSaveTerminalOperationPurge(ctx, custodydb.ConnectorSaveTerminalOperationPurgeParams(arg))
}

func (q connectorLifecycleQueries) FinishOperationRetirement(ctx context.Context, arg custodydb.FinishOperationRetirementParams) (bool, error) {
	return q.Queries.ConnectorFinishOperationRetirement(ctx, custodydb.ConnectorFinishOperationRetirementParams(arg))
}
func (q connectorLifecycleQueries) FinishOperationHistory(ctx context.Context, arg custodydb.FinishOperationHistoryParams) (custodydb.FinishOperationHistoryRow, error) {
	row, e := q.Queries.ConnectorFinishOperationHistory(ctx, custodydb.ConnectorFinishOperationHistoryParams(arg))
	return custodydb.FinishOperationHistoryRow(row), e
}
