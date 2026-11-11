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
	"github.com/jackc/pgx/v5"
)

// This collector-free focus uses actual public manual/capture sharing, the
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
			var share, operation, lifecycle, healthy bool
			if err = run.SQL.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM evidence_share WHERE id=$1),
 EXISTS(SELECT 1 FROM operation_audit WHERE id=$2),EXISTS(SELECT 1 FROM operation_audit_lifecycle WHERE operation_id=$2),
 EXISTS(SELECT 1 FROM operation_audit_lifecycle WHERE operation_id=$2 AND certificate_acknowledged_at IS NOT NULL)`, o.share, o.operation).Scan(&share, &operation, &lifecycle, &healthy); err != nil {
				run.Diagnose()
				t.Fatal("installed share retirement observation", err)
			}
			if healthy && !o.healthy {
				t.Logf("installed_share_retirement lane=%s stage=healthy_certificate_acknowledged", o.lane)
			}
			o.healthy = o.healthy || healthy
			if !operation {
				if share || lifecycle || time.Now().Before(o.purge) {
					t.Fatal("installed retirement broke atomic dependency or original cutoff", o.lane)
				}
				if !o.gone {
					t.Logf("installed_share_retirement lane=%s stage=atomic_live_deletion", o.lane)
				}
				o.gone = true
			}
			var eligible time.Time
			var charged int64
			err = run.SQL.QueryRow(ctx, `SELECT eligible_at,records FROM operation_audit_history
 WHERE root_id=$1 AND lane=$2 AND principal_digest=$3 AND release_at=$4 AND delete_by=$5`, run.RootID, o.lane, o.principal, o.release, o.deleteBy).Scan(&eligible, &charged)
			if err != nil && err != pgx.ErrNoRows {
				t.Fatal("installed original residual history", err)
			}
			if err == nil && o.gone && charged > 0 {
				if !o.cooling {
					t.Logf("installed_share_retirement lane=%s stage=original_history_charged remaining_ms=%d", o.lane, time.Until(eligible).Milliseconds())
				}
				o.cooling = true
			}
			if !o.gone || err == nil {
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
