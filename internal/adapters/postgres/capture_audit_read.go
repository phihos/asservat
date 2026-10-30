package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"bytes"
	"context"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// CaptureOperationIntents has only the purpose-pinned filtered SELECT view.
// Historical acknowledgement grants neither writer closure nor current start.
type CaptureOperationIntents struct {
	ledger *Ledger
	root   string
}

var _ app.CaptureOperationIntentReader = (*CaptureOperationIntents)(nil)

func NewCaptureOperationIntents(ctx context.Context, pool *pgxpool.Pool, root string) (*CaptureOperationIntents, error) {
	if !authorization.UUID(root) {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &CaptureOperationIntents{l, root}, nil
}
func (s *CaptureOperationIntents) ReadCaptureOperationIntent(ctx context.Context, captureID string) (app.CaptureOperationIntentSnapshot, error) {
	var out app.CaptureOperationIntentSnapshot
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(captureID) {
		return out, app.ErrUnavailable
	}
	until := time.Now().Add(5 * time.Second)
	call, close := context.WithDeadline(ctx, until)
	defer close()
	e := s.ledger.transaction(call, func(q *custodydb.Queries) error {
		row, e := q.ReadCaptureOperationIntent(call, custodydb.ReadCaptureOperationIntentParams{RootID: id(s.root), ID: id(captureID)})
		if e != nil {
			return e
		}
		record, projectionErr := captureOperationIntentRecord(row)
		if projectionErr != nil {
			return projectionErr
		}
		out, e = exactCaptureOperationIntent(record)
		return e
	})
	if e != nil || call.Err() != nil || !time.Now().Before(until) {
		return app.CaptureOperationIntentSnapshot{}, app.ErrUnavailable
	}
	return out, nil
}
func exactCaptureOperationIntent(row custodydb.ContextCapture) (app.CaptureOperationIntentSnapshot, error) {
	var out app.CaptureOperationIntentSnapshot
	if !row.IntentOperationID.Valid || row.IntentOperationID != row.ID {
		return out, app.ErrUnavailable
	}
	intent, e := captureIntent(row)
	if e != nil {
		return out, e
	}
	out.Intent = intent
	out.OperationID = uid(row.IntentOperationID)
	if !row.IntentAcknowledgedAt.Valid {
		if row.State != capture.PendingAudit || row.IntentDigest != nil || row.IntentObjectKey.Valid || row.IntentObjectVersion.Valid || row.IntentObjectEtag.Valid || row.IntentObjectBytes.Valid || row.IntentObjectSha256 != nil {
			return app.CaptureOperationIntentSnapshot{}, app.ErrUnavailable
		}
		return out, nil
	}
	receipt := value.Receipt{Key: row.IntentObjectKey.String, Version: row.IntentObjectVersion.String, ETag: row.IntentObjectEtag.String, Bytes: row.IntentObjectBytes.Int64}
	copy(receipt.SHA256[:], row.IntentObjectSha256)
	if row.State != capture.IntentAudited || row.IntentAcknowledgedAt.Time.Before(intent.CreatedAt) || !row.IntentAcknowledgedAt.Time.Before(minCaptureAuditTime(intent.Deadline, intent.CreatedAt.Add(30*time.Second))) || !bytes.Equal(row.IntentDigest, digest(intent)) || !row.IntentObjectKey.Valid || !row.IntentObjectVersion.Valid || !row.IntentObjectEtag.Valid || !row.IntentObjectBytes.Valid || len(row.IntentObjectSha256) != 32 || !receipt.ValidOperation(intent.RootID, intent.CaptureID, "intent") || receipt.Version == "" || receipt.Version == "null" {
		return app.CaptureOperationIntentSnapshot{}, app.ErrUnavailable
	}
	out.Receipt = &receipt
	return out, nil
}

// The protected view exposes immutable intent fields only. Group position is
// derived from that scope, with -1 for a legacy singleton; it is not a later
// mutable completion observation or an additional table privilege.
func captureOperationIntentRecord(row custodydb.ReadCaptureOperationIntentRow) (custodydb.ContextCapture, error) {
	if row.GroupID.Valid && (row.GroupOrdinal < 0 || row.GroupOrdinal > 15) || !row.GroupID.Valid && row.GroupOrdinal != -1 {
		return custodydb.ContextCapture{}, app.ErrUnavailable
	}
	return custodydb.ContextCapture{
		ID:                        row.ID,
		RootID:                    row.RootID,
		RequestKey:                row.RequestKey,
		SubmissionDigest:          row.SubmissionDigest,
		ScopeDigest:               row.ScopeDigest,
		ScopeJson:                 row.ScopeJson,
		ExpectationJson:           row.ExpectationJson,
		PodPinJson:                row.PodPinJson,
		AttemptID:                 row.AttemptID,
		PermissionEpoch:           row.PermissionEpoch,
		PermissionSequence:        row.PermissionSequence,
		IdentityPolicyUid:         row.IdentityPolicyUid,
		IdentityPolicyGeneration:  row.IdentityPolicyGeneration,
		IdentityPolicyDigest:      row.IdentityPolicyDigest,
		CreatedAt:                 row.CreatedAt,
		Deadline:                  row.Deadline,
		State:                     row.State,
		IntentAcknowledgedAt:      row.IntentAcknowledgedAt,
		IntentDigest:              row.IntentDigest,
		IntentObjectKey:           row.IntentObjectKey,
		IntentObjectVersion:       row.IntentObjectVersion,
		IntentObjectEtag:          row.IntentObjectEtag,
		IntentObjectBytes:         row.IntentObjectBytes,
		IntentObjectSha256:        row.IntentObjectSha256,
		ProgressRevision:          row.ProgressRevision,
		DeadlineObservedAt:        row.DeadlineObservedAt,
		PreviewID:                 row.PreviewID,
		IntentOperationID:         row.IntentOperationID,
		ShareInstruction:          row.ShareInstruction,
		HistoryClusterID:          row.HistoryClusterID,
		HistoryNamespaceUid:       row.HistoryNamespaceUid,
		HistoryWorkloadUid:        row.HistoryWorkloadUid,
		HistoryOrigin:             row.HistoryOrigin,
		HistoryParametersRequired: row.HistoryParametersRequired,
		RepeatedFromCaptureID:     row.RepeatedFromCaptureID,
		RepeatedFromExpiresAt:     row.RepeatedFromExpiresAt,
		SnapshotCoverage:          row.SnapshotCoverage,
		SnapshotCoverageDigest:    row.SnapshotCoverageDigest,
		SnapshotExpectationDigest: row.SnapshotExpectationDigest,
		SnapshotCancelKey:         row.SnapshotCancelKey,
		SnapshotCancelActor:       row.SnapshotCancelActor,
		SnapshotCancelRequestedAt: row.SnapshotCancelRequestedAt,
		SnapshotCancelJoinedAt:    row.SnapshotCancelJoinedAt,
		SnapshotCancelProof:       row.SnapshotCancelProof,
		SnapshotCancelProofDigest: row.SnapshotCancelProofDigest,
		GroupID:                   row.GroupID,
		GroupOrdinal:              pgtype.Int2{Int16: row.GroupOrdinal, Valid: row.GroupID.Valid},
	}, nil
}
