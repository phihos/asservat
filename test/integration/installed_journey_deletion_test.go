package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// installedJourneyDeletion observes the installed cleaner with the fixture's
// read-only checks. It never invokes cleanup or changes a cutoff, completion,
// acknowledgement or charge. Snapshot the published attempt before expiry so
// an empty bucket or an unrelated deletion cannot pass the final check.
func installedJourneyDeletion(t *testing.T, ctx context.Context, admin *pgxpool.Pool, p *initialRuntimeNativeProviders, evidenceBucket, root string, diagnose func()) func(string) func() {
	return func(artifactID string) func() {
		t.Helper()
		loc := artifact.Location{ArtifactID: artifactID}
		var allocation string
		var reserved, chargedBytes, chargedObjects, full, replay int64
		var expiresAt, deleteBy time.Time
		before, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		err := admin.QueryRow(before, `
SELECT a.cluster_id::text, a.id::text, a.allocation_id::text,
       a.reserved_bytes, ca.charged_bytes, ca.charged_objects,
       cc.charged_full, cc.charged_replay,
       a.effective_expires_at, a.effective_delete_by
FROM context_catalog c
JOIN custody_attempt a ON a.artifact_id=c.artifact_id
JOIN context_writer_completion w ON w.attempt_id=a.id AND w.root_id=c.root_id AND w.capture_id=c.capture_id
JOIN custody_allocation ca ON ca.id=a.allocation_id
JOIN context_control_account cc ON cc.allocation_id=ca.id
WHERE c.root_id=$1 AND c.artifact_id=$2 AND a.state='stored_unpublished'`, root, artifactID).Scan(
			&loc.ClusterID, &loc.AttemptID, &allocation, &reserved, &chargedBytes, &chargedObjects,
			&full, &replay, &expiresAt, &deleteBy)
		if err != nil || loc.Validate() != nil || reserved <= 0 || chargedBytes != reserved || chargedObjects != 4 || full != 1 || replay != 1 || !time.Now().Before(expiresAt) || !expiresAt.Before(deleteBy) {
			t.Fatal("installed deletion: published attempt lacks its original completed writer and storage charge", err)
		}
		store := s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: aws.String(p.desired.AuditStore.Endpoint), UsePathStyle: true,
			Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: p.client, RetryMaxAttempts: 1})
		inventory := func(read context.Context) (current, versions, markers, uploads int) {
			t.Helper()
			prefix := loc.Prefix()
			objects, err := store.ListObjectsV2(read, &s3.ListObjectsV2Input{Bucket: &evidenceBucket, Prefix: &prefix, MaxKeys: aws.Int32(16)})
			if err != nil || aws.ToBool(objects.IsTruncated) || len(objects.CommonPrefixes) != 0 {
				t.Fatal("installed deletion: incomplete current-object inventory", err)
			}
			v, err := store.ListObjectVersions(read, &s3.ListObjectVersionsInput{Bucket: &evidenceBucket, Prefix: &prefix, MaxKeys: aws.Int32(16)})
			if err != nil || aws.ToBool(v.IsTruncated) || len(v.CommonPrefixes) != 0 {
				t.Fatal("installed deletion: incomplete object-version inventory", err)
			}
			u, err := store.ListMultipartUploads(read, &s3.ListMultipartUploadsInput{Bucket: &evidenceBucket, Prefix: &prefix, MaxUploads: aws.Int32(16)})
			if err != nil || aws.ToBool(u.IsTruncated) || len(u.CommonPrefixes) != 0 {
				t.Fatal("installed deletion: incomplete multipart inventory", err)
			}
			return len(objects.Contents), len(v.Versions), len(v.DeleteMarkers), len(u.Uploads)
		}
		if current, _, markers, uploads := inventory(before); current != 4 || markers != 0 || uploads != 0 {
			t.Fatal("installed deletion: expected four completed evidence objects", current, markers, uploads)
		}
		return func() {
			t.Helper()
			// The test is bounded independently, and can never wait past the
			// artifact's original effective managed-copy deletion deadline.
			until := time.Now().Add(3 * time.Minute)
			if deleteBy.Before(until) {
				until = deleteBy
			}
			wait, stop := context.WithDeadline(ctx, until)
			defer stop()
			var receiptJSON []byte
			var deletedAt, purgedAt, acknowledgedAt time.Time
			for {
				var state string
				var terminal bool
				err := admin.QueryRow(wait, `
SELECT a.state, a.state='deleted' AND d.audit_acknowledged_at IS NOT NULL AND d.finalization_xid IS NOT NULL
FROM custody_attempt a
LEFT JOIN context_deletion_checkpoint d ON d.attempt_id=a.id AND d.root_id=$1
WHERE a.id=$2 AND a.artifact_id=$3`, root, loc.AttemptID, artifactID).Scan(&state, &terminal)
				if err != nil {
					diagnose()
					t.Fatal("installed deletion: failed to observe the original attempt", err)
				}
				if terminal {
					break
				}
				select {
				case <-wait.Done():
					diagnose()
					t.Fatal("installed deletion: evidence did not reach audited finalization", state)
				case <-time.After(5 * time.Second):
				}
			}
			var remainingBytes, remainingObjects, remainingFull, remainingReplay, copies int64
			err := admin.QueryRow(wait, `
SELECT a.deleted_at, d.purged_at, d.audit_acknowledged_at, d.audit_receipt_json,
       ca.charged_bytes, ca.charged_objects, cc.charged_full, cc.charged_replay,
       (SELECT count(*) FROM custody_copy cp WHERE cp.attempt_id=a.id AND cp.ciphertext_bytes IS NOT NULL)
FROM custody_attempt a
JOIN context_deletion_checkpoint d ON d.attempt_id=a.id AND d.root_id=$1
JOIN custody_allocation ca ON ca.id=a.allocation_id
JOIN context_control_account cc ON cc.allocation_id=ca.id
WHERE a.id=$2 AND a.allocation_id=$3 AND a.state='deleted'`, root, loc.AttemptID, allocation).Scan(
				&deletedAt, &purgedAt, &acknowledgedAt, &receiptJSON,
				&remainingBytes, &remainingObjects, &remainingFull, &remainingReplay, &copies)
			if err != nil || purgedAt.Before(expiresAt) || deletedAt.Before(purgedAt) || acknowledgedAt.Before(purgedAt) || !deletedAt.Before(deleteBy) ||
				remainingBytes != chargedBytes-reserved || remainingObjects != chargedObjects-4 || remainingFull != full || remainingReplay != replay || copies != 0 {
				t.Fatal("installed deletion: wrong deadlines, acknowledgement or release scope", err)
			}
			var receipt audit.Receipt
			if json.Unmarshal(receiptJSON, &receipt) != nil || !receipt.ValidContextDeletion(root, loc.AttemptID) || receipt.Version == "" || receipt.Version == "null" {
				t.Fatal("installed deletion: missing immutable audit receipt")
			}
			object, err := store.GetObject(wait, &s3.GetObjectInput{Bucket: aws.String(p.desired.AuditStore.Bucket), Key: &receipt.Key, VersionId: &receipt.Version, IfMatch: &receipt.ETag})
			if err != nil {
				t.Fatal("installed deletion: acknowledged audit version unavailable", err)
			}
			defer object.Body.Close()
			digest := sha256.New()
			count, err := io.Copy(digest, io.LimitReader(object.Body, receipt.Bytes+1))
			if err != nil || count != receipt.Bytes || aws.ToString(object.VersionId) != receipt.Version || aws.ToString(object.ETag) != receipt.ETag || artifact.Digest(digest.Sum(nil)) != receipt.SHA256 {
				t.Fatal("installed deletion: acknowledged audit bytes differ from their receipt", err)
			}
			if current, versions, markers, uploads := inventory(wait); current != 0 || versions != 0 || markers != 0 || uploads != 0 {
				t.Fatal("installed deletion: managed evidence remains", current, versions, markers, uploads)
			}
			t.Log("installed journey: all evidence objects, versions, markers and multipart uploads are absent; acknowledged audit receipt matches its immutable ciphertext version; evidence storage refunded while control charges remain")
		}
	}
}
