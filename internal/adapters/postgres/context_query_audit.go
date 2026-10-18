package postgres

import (
	"bytes"
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/audit"
)

// Compare the C-08 typed canonical record, never jsonb::text: PostgreSQL JSONB
// encoding does not reproduce the existing Go record digest. The independent
// acknowledgement and positively joined writer completion must agree exactly.
func queryAuditSnapshot(row custodydb.ReadContextQueryInvocationRow, call value.ContextQueryCall) (audit.OperationSnapshot, error) {
	var in audit.OperationIntent
	a, l := row.OperationAudit, row.OperationAuditLifecycle
	if queryDecode(a.Intent, 8192, &in) != nil || !in.Valid() || in.Lifecycle == nil || !in.Lifecycle.Policy.CertificateVerificationBacked() ||
		in.ID != call.ID || in.RootID != call.RootID || in.Name != call.Tool || in.InputFormat != "context-query-input/v1" || in.InputFormat != call.InputFormat || in.MACVersion != call.MACVersion || in.InputDigest != call.InputDigest || in.PrincipalDigest != call.PrincipalDigest || in.Actor != call.Principal ||
		!in.CreatedAt.Equal(call.StartedAt) || !in.RequestUntil.Equal(call.Until) || !in.WriteUntil.Equal(call.WriteUntil) {
		return audit.OperationSnapshot{}, value.ErrUnavailable
	}
	snapshot, e := auditRow(a, in)
	if e != nil || !snapshot.IntentStarted || snapshot.IntentReceipt == nil || l.OperationID != a.ID || l.RootID != a.RootID || l.Lane != "normal" || !bytes.Equal(l.PrincipalDigest, a.PrincipalDigest) || l.IssuerEpoch != a.IssuerEpoch || uid(l.InstallationID) != in.Lifecycle.Policy.InstallationID || l.Retirement != nil || l.CertificateStarted || l.FinalizationXid.Valid {
		return audit.OperationSnapshot{}, value.ErrUnavailable
	}
	var binding audit.OperationLifecycleBinding
	var completion audit.OperationWriteCompletion
	if queryDecode(l.Binding, 4096, &binding) != nil || !sameAuditJSON(binding, *in.Lifecycle) || queryDecode(l.IntentCompletion, 8192, &completion) != nil ||
		!completion.Valid(in.RootID, in.ID, in.Lifecycle.Policy.StoreID, "intent", in.CreatedAt, in.WriteUntil) || completion.RecordDigest != auditapp.OperationLifecycleDigest(in) || completion.Receipt != *snapshot.IntentReceipt {
		return audit.OperationSnapshot{}, value.ErrUnavailable
	}
	return snapshot, nil
}

func queryIntentFence(ctx context.Context, tx *custodydb.Queries, call value.ContextQueryCall, recovery custodydb.FleetCurrentTrust) error {
	row, e := tx.ReadContextQueryInvocation(ctx, custodydb.ReadContextQueryInvocationParams{ID: id(call.ID), RootID: id(call.RootID)})
	if e != nil {
		return e
	}
	snapshot, e := queryAuditSnapshot(row, call)
	if e != nil {
		return e
	}
	incarnation, e := tx.ReadContextDatabaseIncarnation(ctx, recovery.InstallationID)
	if e != nil {
		return e
	}
	l := row.OperationAuditLifecycle
	if l.InstallationID != recovery.InstallationID || l.IssuerEpoch != recovery.IssuerEpoch || !l.PostmasterAt.Time.Equal(incarnation.PostmasterAt.Time) || l.DatabaseOid != incarnation.DatabaseOid {
		return value.ErrUnavailable
	}
	now, e := tx.CurrentTime(ctx)
	if e != nil || ctx.Err() != nil || !call.Valid(now.Time) || !now.Time.Before(snapshot.Intent.Lifecycle.OriginalPurgeAt) {
		return value.ErrUnavailable
	}
	return nil
}

func queryOutcomeFence(ctx context.Context, tx *custodydb.Queries, call value.ContextQueryCall) error {
	row, e := tx.ReadContextQueryInvocation(ctx, custodydb.ReadContextQueryInvocationParams{ID: id(call.ID), RootID: id(call.RootID)})
	if e != nil {
		return e
	}
	snapshot, e := queryAuditSnapshot(row, call)
	if e != nil || snapshot.Outcome == nil || !snapshot.OutcomeStarted || snapshot.OutcomeReceipt == nil {
		return value.ErrUnavailable
	}
	var completion audit.OperationWriteCompletion
	in := snapshot.Intent
	if queryDecode(row.OperationAuditLifecycle.OutcomeCompletion, 8192, &completion) != nil || !completion.Valid(in.RootID, in.ID, in.Lifecycle.Policy.StoreID, "outcome", in.CreatedAt, in.WriteUntil) || completion.RecordDigest != auditapp.OperationLifecycleDigest(*snapshot.Outcome) || completion.Receipt != *snapshot.OutcomeReceipt {
		return value.ErrUnavailable
	}
	return nil
}
