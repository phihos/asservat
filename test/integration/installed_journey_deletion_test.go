package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// installedJourneyDeletion temporarily denies the original cleaner's inventory
// of one attempt, then observes failure and recovery. Only the owned fixture's
// bucket policy changes; cleanup, cutoffs, completion, audit and charges remain
// product effects. The existing callback brackets original publication/expiry.
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
		// The browser journey's own capture shares this workload's allocation.
		if err != nil || loc.Validate() != nil || reserved <= 0 || chargedBytes < reserved || chargedObjects < 4 || full < 1 || replay < 1 || !time.Now().Before(expiresAt) || !expiresAt.Before(deleteBy) {
			t.Fatal("installed deletion: published attempt lacks its original completed writer and storage charge", err)
		}
		store := s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: aws.String(p.desired.AuditStore.Endpoint), UsePathStyle: true,
			Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: p.client, RetryMaxAttempts: 1})
		inventory := func(read context.Context) (current, versions, markers, uploads int, identity artifact.Digest) {
			t.Helper()
			prefix := loc.Prefix()
			objects, err := store.ListObjectsV2(read, &s3.ListObjectsV2Input{Bucket: &evidenceBucket, Prefix: &prefix, MaxKeys: aws.Int32(16)})
			if err != nil || objects == nil || objects.IsTruncated == nil || aws.ToBool(objects.IsTruncated) || len(objects.CommonPrefixes) != 0 {
				t.Fatal("installed deletion: incomplete current-object inventory", err)
			}
			v, err := store.ListObjectVersions(read, &s3.ListObjectVersionsInput{Bucket: &evidenceBucket, Prefix: &prefix, MaxKeys: aws.Int32(16)})
			if err != nil || v == nil || v.IsTruncated == nil || aws.ToBool(v.IsTruncated) || len(v.CommonPrefixes) != 0 {
				t.Fatal("installed deletion: incomplete object-version inventory", err)
			}
			u, err := store.ListMultipartUploads(read, &s3.ListMultipartUploadsInput{Bucket: &evidenceBucket, Prefix: &prefix, MaxUploads: aws.Int32(16)})
			if err != nil || u == nil || u.IsTruncated == nil || aws.ToBool(u.IsTruncated) || len(u.CommonPrefixes) != 0 {
				t.Fatal("installed deletion: incomplete multipart inventory", err)
			}
			// Retain bounded original identities, not just counts. A substituted
			// version must not satisfy the failed-deletion observation.
			var entries []string
			for _, o := range objects.Contents {
				entries = append(entries, fmt.Sprintf("object/%q/%q/%d", aws.ToString(o.Key), aws.ToString(o.ETag), aws.ToInt64(o.Size)))
			}
			for _, o := range v.Versions {
				entries = append(entries, fmt.Sprintf("version/%q/%q/%q/%d", aws.ToString(o.Key), aws.ToString(o.VersionId), aws.ToString(o.ETag), aws.ToInt64(o.Size)))
			}
			for _, o := range v.DeleteMarkers {
				entries = append(entries, fmt.Sprintf("marker/%q/%q", aws.ToString(o.Key), aws.ToString(o.VersionId)))
			}
			for _, o := range u.Uploads {
				entries = append(entries, fmt.Sprintf("upload/%q/%q", aws.ToString(o.Key), aws.ToString(o.UploadId)))
			}
			slices.Sort(entries)
			raw, _ := json.Marshal(entries)
			return len(objects.Contents), len(v.Versions), len(v.DeleteMarkers), len(u.Uploads), sha256.Sum256(raw)
		}
		current, versions, markers, uploads, originalInventory := inventory(before)
		if current != 4 || versions != 4 || markers != 0 || uploads != 0 {
			t.Fatal("installed deletion: expected four completed versioned evidence objects", current, versions, markers, uploads)
		}
		original, err := readInstalledDeletionState(before, admin, root, loc)
		if err != nil || original.State != "stored_unpublished" || original.Lease.Valid || original.Deleted || original.Checkpoint ||
			original.Copies != 4 || len(original.Receipts) == 0 || len(original.Writer) != 32 || original.Allocation != allocation ||
			original.Bytes != chargedBytes || original.Objects != chargedObjects || original.Full != full || original.Replay != replay ||
			!original.ExpiresAt.Equal(expiresAt) || !original.DeleteBy.Equal(deleteBy) || !original.Now.Before(expiresAt) {
			t.Fatal("installed deletion: original obligation unavailable before fault", err)
		}
		// These are the existing fixture credentials issued by
		// installerOperatorStorage; this creates no user, key or grant. Positive
		// read-only controls below reject drift from the actual fixture identity.
		cleaner := s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: aws.String(p.desired.AuditStore.Endpoint), UsePathStyle: true,
			Credentials: credentials.NewStaticCredentialsProvider("evidence-delete-continuation", "evidence-delete-continuation-secret", ""), HTTPClient: p.client, RetryMaxAttempts: 1})
		prefix, controlPrefix := loc.Prefix(), "v1/deletion-permission-probe/"+loc.AttemptID+"/"
		if ok, err := installedDeletionInventoryAccess(before, cleaner, evidenceBucket, prefix, false); err != nil || !ok {
			t.Fatal("installed deletion: original cleaner inventory unavailable", err)
		}
		fault := &installedDeletionFault{store: store, bucket: evidenceBucket}
		fault.original, err = fault.read(before)
		if err != nil || !installedDeletionSamePolicy(fault.original, installerEvidenceBucketPolicy(evidenceBucket)) {
			t.Fatal("installed deletion: unexpected original fixture policy", err)
		}
		fault.denied, err = installedDeletionFaultPolicy(fault.original, evidenceBucket, loc)
		if err != nil {
			t.Fatal("installed deletion: invalid fault policy", err)
		}
		// Registered before the mutation: Fatal/unknown replies still restore
		// synchronously before this test completes, under a separate finite bound.
		t.Cleanup(func() {
			cleanup, end := context.WithTimeout(context.Background(), 10*time.Second)
			defer end()
			if err := fault.restore(cleanup); err != nil {
				t.Error("installed deletion: original policy cleanup", err)
			}
		})
		arm, endArm := context.WithDeadline(before, expiresAt)
		defer endArm()
		if err = fault.arm(arm); err != nil {
			t.Fatal("installed deletion: arm exact inventory denial", err)
		}
		if err = installedDeletionWaitAccess(arm, cleaner, evidenceBucket, prefix, true); err != nil {
			t.Fatal("installed deletion: exact cleaner inventory was not denied", err)
		}
		if ok, err := installedDeletionInventoryAccess(arm, cleaner, evidenceBucket, controlPrefix, false); err != nil || !ok {
			t.Fatal("installed deletion: fault affected the independent prefix", err)
		}
		armed, err := readInstalledDeletionState(arm, admin, root, loc)
		if err != nil || !armed.Now.Before(expiresAt) || !time.Now().Before(expiresAt) || armed.State != "stored_unpublished" || armed.Fence != original.Fence {
			t.Fatal("installed deletion: fault was not established before original expiry", err)
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
			failure := installedDeletionFailure{}
			for {
				observed, err := readInstalledDeletionState(wait, admin, root, loc)
				if err != nil {
					diagnose()
					t.Fatal("installed deletion: failed-lease observation unavailable", err)
				}
				done, err := failure.observe(original, observed)
				if err != nil {
					diagnose()
					t.Fatal("installed deletion: failed cleanup did not retain the original obligation", err)
				}
				if done {
					break
				}
				if err := installedJourneyPause(wait, time.Second); err != nil {
					diagnose()
					t.Fatal("installed deletion: no unsuccessful installed lease observed", err)
				}
			}
			// Policy propagation was established before expiry. This checkpoint
			// must reject any unexpected permission result, not retry it away.
			if ok, err := installedDeletionInventoryAccess(wait, cleaner, evidenceBucket, prefix, true); err != nil || !ok {
				t.Fatal("installed deletion: denial disappeared before failed-lease verification", err)
			}
			if ok, err := installedDeletionInventoryAccess(wait, cleaner, evidenceBucket, controlPrefix, false); err != nil || !ok {
				t.Fatal("installed deletion: independent inventory control failed", err)
			}
			if _, _, _, _, identity := inventory(wait); identity != originalInventory {
				t.Fatal("installed deletion: failed cleanup changed original evidence inventory")
			}
			t.Log("installed journey: an installed cleanup lease expired under the exact inventory denial; original evidence, receipts, deadlines and storage/control charges remain, with no purge checkpoint")
			if err := fault.restore(wait); err != nil {
				t.Fatal("installed deletion: original policy restoration", err)
			}
			if err := installedDeletionWaitAccess(wait, cleaner, evidenceBucket, prefix, false); err != nil {
				t.Fatal("installed deletion: original cleaner inventory did not recover", err)
			}
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
			var remainingBytes, remainingObjects, remainingFull, remainingReplay, copies, purgeFence int64
			var finalExpires, finalDeleteBy time.Time
			err := admin.QueryRow(wait, `
SELECT a.deleted_at, d.purged_at, d.audit_acknowledged_at, d.audit_receipt_json,
       ca.charged_bytes, ca.charged_objects, cc.charged_full, cc.charged_replay,
       (SELECT count(*) FROM custody_copy cp WHERE cp.attempt_id=a.id AND cp.ciphertext_bytes IS NOT NULL),
       a.effective_expires_at, a.effective_delete_by, d.purge_fence
FROM custody_attempt a
JOIN context_deletion_checkpoint d ON d.attempt_id=a.id AND d.root_id=$1
JOIN custody_allocation ca ON ca.id=a.allocation_id
JOIN context_control_account cc ON cc.allocation_id=ca.id
WHERE a.id=$2 AND a.allocation_id=$3 AND a.state='deleted'`, root, loc.AttemptID, allocation).Scan(
				&deletedAt, &purgedAt, &acknowledgedAt, &receiptJSON,
				&remainingBytes, &remainingObjects, &remainingFull, &remainingReplay, &copies, &finalExpires, &finalDeleteBy, &purgeFence)
			if err != nil || purgedAt.Before(expiresAt) || deletedAt.Before(purgedAt) || acknowledgedAt.Before(purgedAt) || !deletedAt.Before(deleteBy) ||
				!finalExpires.Equal(expiresAt) || !finalDeleteBy.Equal(deleteBy) || purgeFence <= failure.Fence ||
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
			if current, versions, markers, uploads, _ := inventory(wait); current != 0 || versions != 0 || markers != 0 || uploads != 0 {
				t.Fatal("installed deletion: managed evidence remains", current, versions, markers, uploads)
			}
			t.Log("installed journey: all evidence objects, versions, markers and multipart uploads are absent; acknowledged audit receipt matches its immutable ciphertext version; evidence storage refunded while control charges remain")
		}
	}
}
