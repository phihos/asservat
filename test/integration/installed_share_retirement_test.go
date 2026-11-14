package integration

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// This one concrete reader is shared with the paid-share real SQL fixture so
// installed proof changes cannot defer SQL/nullable scan mistakes to a full run.
// All account totals and original-object state come from one MVCC snapshot.
type shareRetirementSnapshot struct {
	SnapshotAt, ObservedAt                       time.Time
	Share, Operation, Lifecycle, Healthy         bool
	CertificateStarted, CertificateWriter        bool
	CertificateVerifyAttempts                    int64
	CertificateWriteUntil                        *time.Time
	Eligible                                     *time.Time
	OriginalRecords, LiveRecords, HistoryRecords int64
	AccountCharge                                *int64
}

func readShareRetirementSnapshot(ctx context.Context, pool *pgxpool.Pool, root, lane string, principal []byte, share, operation string, release, deleteBy time.Time) (sample shareRetirementSnapshot, err error) {
	err = pool.QueryRow(ctx, `WITH
 account AS (SELECT charged FROM operation_audit_account WHERE root_id=$1 AND lane=$2 AND principal_digest=$3),
 live AS (SELECT count(*) AS records FROM operation_audit WHERE root_id=$1 AND lane=$2 AND principal_digest=$3),
 history AS (SELECT COALESCE(sum(records),0)::bigint AS records FROM operation_audit_history WHERE root_id=$1 AND lane=$2 AND principal_digest=$3),
 original_history AS (SELECT eligible_at,records FROM operation_audit_history WHERE root_id=$1 AND lane=$2 AND principal_digest=$3 AND release_at=$6 AND delete_by=$7),
 lifecycle AS (SELECT certificate_started,certificate_completion,certificate_acknowledged_at,certificate_verify_attempts,retirement FROM operation_audit_lifecycle WHERE root_id=$1 AND operation_id=$5),
 snapshot AS MATERIALIZED (SELECT
 EXISTS(SELECT 1 FROM evidence_share WHERE root_id=$1 AND id=$4) AS share_present,
 EXISTS(SELECT 1 FROM operation_audit WHERE root_id=$1 AND id=$5) AS operation_present,
 EXISTS(SELECT 1 FROM lifecycle) AS lifecycle_present,
 EXISTS(SELECT 1 FROM lifecycle WHERE certificate_acknowledged_at IS NOT NULL) AS healthy,
 COALESCE((SELECT certificate_started FROM lifecycle),false) AS certificate_started,
 EXISTS(SELECT 1 FROM lifecycle WHERE certificate_completion IS NOT NULL) AS certificate_writer,
 COALESCE((SELECT certificate_verify_attempts FROM lifecycle),0) AS certificate_verify_attempts,
 (SELECT (retirement->>'CertificateWriteUntil')::timestamptz FROM lifecycle) AS certificate_write_until,
 (SELECT eligible_at FROM original_history) AS eligible_at,COALESCE((SELECT records FROM original_history),0) AS original_records,
 (SELECT charged FROM account) AS charged,(SELECT records FROM live) AS live_records,(SELECT records FROM history) AS history_records)
 SELECT statement_timestamp(),clock_timestamp(),share_present,operation_present,lifecycle_present,healthy,certificate_started,certificate_writer,certificate_verify_attempts,certificate_write_until,eligible_at,original_records,charged,live_records,history_records FROM snapshot`, root, lane, principal, share, operation, release, deleteBy).Scan(
		&sample.SnapshotAt, &sample.ObservedAt, &sample.Share, &sample.Operation, &sample.Lifecycle, &sample.Healthy,
		&sample.CertificateStarted, &sample.CertificateWriter, &sample.CertificateVerifyAttempts, &sample.CertificateWriteUntil,
		&sample.Eligible, &sample.OriginalRecords, &sample.AccountCharge, &sample.LiveRecords, &sample.HistoryRecords)
	return
}
