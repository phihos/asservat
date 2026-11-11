package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SC-PRV-015: this collector-free focus uses actual public manual/capture sharing, the
// installed worker's three credential facets and its native provider login.
// Short original bounds are selected before installation; SQL timestamps and
// outstanding audit records are never rewritten to manufacture cleanup.
func qualifyInstalledShareRetirement(t *testing.T, parent context.Context, cluster, namespace, workload string, run installedProcessingRun, providers *initialRuntimeNativeProviders) {
	t.Helper()
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	preview := map[string]any{"target_ref": map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"preset_ref": map[string]string{"name": "pod-status", "version": "v1"}, "requested_retention_seconds": installedJourneyRetentionSeconds()}
	installedJourneyShare(t, parent, wire, run.Identity, run.Transport, run.Origin, run.CaseID, run.ArtifactID, run.Native, preview, run.Diagnose)
	type original struct {
		share, operation, lane         string
		principal                      []byte
		purge, live, release, deleteBy time.Time
		eligible                       time.Time
		horizon                        int64
		healthy, cooling, gone         bool
	}
	rows, err := run.SQL.Query(parent, `SELECT s.id::text,s.creating_operation_id::text,a.lane,a.principal_digest,l.original_purge_at,l.live_retire_by,
 (l.binding->>'HistoryReleaseAt')::timestamptz,(l.binding->>'HistoryDeleteBy')::timestamptz,(l.binding#>>'{Policy,BackupHorizonSeconds}')::bigint
 FROM evidence_share s JOIN operation_audit a ON a.id=s.creating_operation_id
 JOIN operation_audit_lifecycle l ON l.operation_id=a.id WHERE s.root_id=$1 ORDER BY s.id`, run.RootID)
	if err != nil {
		t.Fatal("installed share retirement original bindings", err)
	}
	var originals []original
	deadline := time.Now()
	for rows.Next() {
		var o original
		if err = rows.Scan(&o.share, &o.operation, &o.lane, &o.principal, &o.purge, &o.live, &o.release, &o.deleteBy, &o.horizon); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if o.horizon != 2 || o.live.After(time.Now().Add(5*time.Minute)) {
			rows.Close()
			t.Fatal("installed retirement did not consume the original short qualified profile")
		}
		if end := o.deleteBy.Add(20 * time.Second); end.After(deadline) {
			deadline = end
		}
		originals = append(originals, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(originals) != 2 || originals[0].lane == originals[1].lane {
		t.Fatal("installed manual and capture share dependencies", len(originals), err)
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	store := providers.desired.AuditStore
	objects := s3.New(s3.Options{Region: store.Region, BaseEndpoint: aws.String(store.Endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: providers.client, RetryMaxAttempts: 1})
	for _, o := range originals {
		prefix := audit.OperationAuditKey(run.RootID, o.operation, "")
		versions, err := objects.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &store.Bucket, Prefix: &prefix, MaxKeys: aws.Int32(16)})
		if err != nil || len(versions.Versions) < 2 || aws.ToBool(versions.IsTruncated) {
			t.Fatal("installed original share audit objects missing", o.lane, err)
		}
	}
	started := time.Now()
	for {
		complete := true
		for i := range originals {
			o := &originals[i]
			sample, err := readShareRetirementSnapshot(ctx, run.SQL, run.RootID, o.lane, o.principal, o.share, o.operation, o.release, o.deleteBy)
			snapshotAt, observedAt := sample.SnapshotAt, sample.ObservedAt
			share, operation, lifecycle, healthy := sample.Share, sample.Operation, sample.Lifecycle, sample.Healthy
			eligible, originalRecords := sample.Eligible, sample.OriginalRecords
			accountCharge, liveRecords, historyRecords := sample.AccountCharge, sample.LiveRecords, sample.HistoryRecords
			if err != nil {
				run.Diagnose()
				t.Fatal("installed share retirement/account snapshot", err)
			}
			if share != operation || lifecycle != operation {
				t.Fatal("installed retirement did not remove share, operation and lifecycle atomically", o.lane)
			}
			var charged int64
			if accountCharge == nil {
				if liveRecords+historyRecords != 0 {
					t.Fatal("installed audit account disappeared with outstanding charges", o.lane, liveRecords, historyRecords)
				}
			} else {
				charged = *accountCharge
			}
			if charged != liveRecords+historyRecords {
				t.Fatal("installed audit account charge differs from live and residual records", o.lane, charged, liveRecords, historyRecords)
			}
			if operation && !snapshotAt.Before(o.live) {
				t.Logf("installed_share_retirement lane=%s stage=original_live_bound_missed since_purge_ms=%d live_overdue_ms=%d until_history_release_ms=%d until_history_delete_ms=%d snapshot_read_ms=%d share=%t operation=%t lifecycle=%t healthy=%t healthy_previously_observed=%t account_charge=%d live_records=%d history_records=%d original_history_present=%t original_history_records=%d",
					o.lane, snapshotAt.Sub(o.purge).Milliseconds(), snapshotAt.Sub(o.live).Milliseconds(), o.release.Sub(snapshotAt).Milliseconds(), o.deleteBy.Sub(snapshotAt).Milliseconds(), observedAt.Sub(snapshotAt).Milliseconds(),
					share, operation, lifecycle, healthy, o.healthy, charged, liveRecords, historyRecords, eligible != nil, originalRecords)
				t.Fatal("installed identifying share/audit rows outlived original live_retire_by", o.lane)
			}
			if healthy && !o.healthy {
				t.Logf("installed_share_retirement lane=%s stage=healthy_certificate_acknowledged", o.lane)
			}
			o.healthy = o.healthy || healthy
			if !operation {
				if observedAt.Before(o.purge) {
					t.Fatal("installed retirement preceded original purge cutoff", o.lane)
				}
				if !o.gone {
					t.Logf("installed_share_retirement lane=%s stage=atomic_live_deletion", o.lane)
				}
				o.gone = true
			}
			if eligible != nil {
				if originalRecords < 1 || !o.eligible.IsZero() && eligible.Before(o.eligible) {
					t.Fatal("installed original history charge or eligibility regressed", o.lane)
				}
				o.eligible = *eligible
				if o.gone && !o.cooling {
					if !observedAt.Before(*eligible) {
						t.Fatal("installed retirement did not retain a future original cooling bound", o.lane)
					}
					t.Logf("installed_share_retirement lane=%s stage=original_history_charged remaining_ms=%d", o.lane, eligible.Sub(observedAt).Milliseconds())
					o.cooling = true
				}
			} else if originalRecords != 0 || o.cooling && observedAt.Before(o.eligible) {
				t.Fatal("installed original history released before its observed eligibility", o.lane)
			}
			if !o.gone || eligible != nil {
				complete = false
			}
		}
		if complete {
			break
		}
		if installedJourneyPause(ctx, 200*time.Millisecond) != nil {
			run.Diagnose()
			t.Fatal("installed cleanup failed to retire original share/audit/history within its bound", ctx.Err())
		}
	}
	for _, o := range originals {
		if !o.healthy || !o.cooling {
			t.Fatal("installed cleanup did not prove healthy certificate and retained cooling charge", o.lane, o.healthy, o.cooling)
		}
		prefix := audit.OperationAuditKey(run.RootID, o.operation, "")
		versions, err := objects.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &store.Bucket, Prefix: &prefix, MaxKeys: aws.Int32(16)})
		if err != nil || aws.ToBool(versions.IsTruncated) || len(versions.Versions)+len(versions.DeleteMarkers) != 0 {
			t.Fatal("installed share audit versions remain", o.lane, err)
		}
		uploads, err := objects.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &store.Bucket, Prefix: &prefix, MaxUploads: aws.Int32(16)})
		if err != nil || aws.ToBool(uploads.IsTruncated) || len(uploads.Uploads) != 0 {
			t.Fatal("installed share audit uploads remain", o.lane, err)
		}
	}
	t.Logf("installed manual/capture share retirement: healthy certificates, atomic live deletion, independent version/multipart absence and original cooling/release in %s", time.Since(started).Round(time.Millisecond))
}

// This one concrete reader is shared with the paid-share real SQL fixture so
// installed proof changes cannot defer SQL/nullable scan mistakes to a full run.
// All account totals and original-object state come from one MVCC snapshot.
type shareRetirementSnapshot struct {
	SnapshotAt, ObservedAt                       time.Time
	Share, Operation, Lifecycle, Healthy         bool
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
 snapshot AS MATERIALIZED (SELECT
 EXISTS(SELECT 1 FROM evidence_share WHERE root_id=$1 AND id=$4) AS share_present,
 EXISTS(SELECT 1 FROM operation_audit WHERE root_id=$1 AND id=$5) AS operation_present,
 EXISTS(SELECT 1 FROM operation_audit_lifecycle WHERE root_id=$1 AND operation_id=$5) AS lifecycle_present,
 EXISTS(SELECT 1 FROM operation_audit_lifecycle WHERE root_id=$1 AND operation_id=$5 AND certificate_acknowledged_at IS NOT NULL) AS healthy,
 (SELECT eligible_at FROM original_history) AS eligible_at,COALESCE((SELECT records FROM original_history),0) AS original_records,
 (SELECT charged FROM account) AS charged,(SELECT records FROM live) AS live_records,(SELECT records FROM history) AS history_records)
 SELECT statement_timestamp(),clock_timestamp(),share_present,operation_present,lifecycle_present,healthy,eligible_at,original_records,charged,live_records,history_records FROM snapshot`, root, lane, principal, share, operation, release, deleteBy).Scan(
		&sample.SnapshotAt, &sample.ObservedAt, &sample.Share, &sample.Operation, &sample.Lifecycle, &sample.Healthy,
		&sample.Eligible, &sample.OriginalRecords, &sample.AccountCharge, &sample.LiveRecords, &sample.HistoryRecords)
	return
}
