package postgres

import (
	"bytes"
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
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
	if s.worker {
		return workerLifecycleQueries{captureLifecycleQueries{q}}
	}
	if s.capture {
		return captureLifecycleQueries{q}
	}
	return q
}

func strictJSON(s string, v any) error {
	d := json.NewDecoder(bytes.NewReader([]byte(s)))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
