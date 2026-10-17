package integration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ADR-166 against real PostgreSQL and the owned S3 backend. Synthetic random
// ciphertext stands in for encoder output; no artifact format is asserted.
func qualifyStreamingCustody(t *testing.T, ctx context.Context, admin *pgxpool.Pool, ledger *postgres.Ledger, store *objectstore.Store, s3Admin *s3.Client, bucket string, charge func(*testing.T, string) (int64, int64)) {
	t.Helper()
	objects := objectstore.StreamingObjects{Store: store}
	plan := func(allocation, pool string, native int64) artifact.StreamingPlan {
		now := time.Now().UTC().Truncate(time.Microsecond)
		return artifact.StreamingPlan{Registration: artifact.Registration{Location: artifact.Location{ClusterID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: pool, AllocationID: allocation, PoolRevision: 1, AllocationRevision: 1, NativeLimit: native, AnchorAt: now.Add(-time.Second), WriteUntil: now.Add(2 * time.Minute), ExpiresAt: now.Add(3 * time.Minute), DeleteBy: now.Add(4 * time.Minute)}, WriterEpoch: custodyID()}
	}
	// One pool/allocation sized for exactly three streaming attempts.
	root, allocation, storeID := custodyID(), custodyID(), custodyID()
	sample := plan(allocation, storeID, 20<<20)
	bytesPer := sample.Registration.ReservedBytes() + sample.TemporaryBytes()
	objectsPer := int64(4 + 1 + sample.PartLimit())
	valid := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
	if _, err := admin.Exec(ctx, "INSERT INTO custody_pool(id,store_id,revision,valid_until,byte_limit,object_limit) VALUES($1,$2,1,$3,$4,$5)", root, storeID, valid, 3*bytesPer, 3*objectsPer); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: allocation, PoolID: root, ScopeID: custodyID(), ServiceClass: "context", PoolRevision: 1, Revision: 1, Bytes: 3 * bytesPer, Objects: 3 * objectsPer, ValidUntil: valid}); err != nil {
		t.Fatal(err)
	}
	first := plan(allocation, storeID, 20<<20)
	if _, err := ledger.Register(ctx, first.Registration); !errors.Is(err, artifact.ErrInvalid) {
		t.Fatal("small path accepted a streaming-size attempt", err)
	}
	if _, err := ledger.RegisterStreaming(ctx, first); err != nil {
		t.Fatal("streaming registration", err)
	}
	if b, o := charge(t, allocation); b != bytesPer || o != objectsPer {
		t.Fatal("final and temporary obligations not charged together", b, o, bytesPer, objectsPer)
	}
	// SQL rejects a large attempt without its journal, even for a privileged writer.
	r := first.Registration
	_, err := admin.Exec(ctx, "INSERT INTO custody_attempt(id,cluster_id,artifact_id,allocation_id,request_digest,pool_revision,allocation_revision,native_limit,reserved_bytes,anchor_at,write_until,expires_at,delete_by) VALUES($1,$2,$3,$4,$5,1,1,$6,$7,$8,$9,$10,$11)", custodyID(), r.Location.ClusterID, custodyID(), allocation, make([]byte, 32), r.NativeLimit, r.ReservedBytes(), r.AnchorAt, r.WriteUntil, r.ExpiresAt, r.DeleteBy)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("journal-less large attempt accepted", err)
	}
	w, err := privacy.NewStreamingWriter(ctx, first, ledger, objects)
	if err != nil {
		t.Fatal("writer", err)
	}
	native := make([]byte, 20<<20)
	if _, err = rand.Read(native); err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(native); off += 3 << 20 { // chunk sizes unrelated to parts
		if err = w.Write(ctx, native[off:min(off+3<<20, len(native))]); err != nil {
			t.Fatal("write", off, err)
		}
	}
	receipt, err := w.Finish(ctx)
	if err != nil || receipt.Bytes != int64(len(native)) || receipt.SHA256 != artifact.Digest(sha256.Sum256(native)) || receipt.VersionID == "" {
		t.Fatal("verified streaming receipt", receipt, err)
	}
	if _, err = privacy.NewStreamingWriter(ctx, first, ledger, objects); err == nil {
		t.Fatal("spent create claim repeated")
	}
	// Create-only completion: a second upload cannot replace the committed object.
	key := first.Registration.Location.Prefix() + artifact.Role(0)
	upload, err := store.CreateUpload(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	part := artifact.StreamingPart{Number: 1, Bytes: 1 << 20, SHA256: sha256.Sum256(native[:1<<20])}
	if part.ETag, err = store.UploadPart(ctx, key, upload, part, native[:1<<20]); err != nil {
		t.Fatal(err)
	}
	if _, err = store.CompleteUpload(ctx, key, upload, []artifact.StreamingPart{part}, part.Bytes, part.SHA256); !errors.Is(err, objectstore.ErrExists) {
		t.Fatal("backend did not enforce create-only completion", err)
	}
	if err = store.AbortUpload(ctx, key, upload); err != nil {
		t.Fatal(err)
	}
	head, err := s3Admin.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err != nil || aws.ToInt64(head.ContentLength) != int64(len(native)) || aws.ToString(head.VersionId) != receipt.VersionID {
		t.Fatal("committed object replaced", err)
	}
	state, err := ledger.ReadStreaming(ctx, first)
	if err != nil || state.Receipt == nil || *state.Receipt != receipt || len(state.Parts) != 3 {
		t.Fatal("journal", err)
	}
	if err = privacy.ReleaseStreaming(ctx, first, state, ledger, objects); err != nil {
		_, partsErr := s3Admin.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: &key, UploadId: &state.UploadID})
		listed, listErr := s3Admin.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket, Prefix: &key})
		uploads := -1
		if listErr == nil {
			uploads = len(listed.Uploads)
		}
		code, status := "", 0
		var api smithy.APIError
		if errors.As(partsErr, &api) {
			code = api.ErrorCode()
		}
		var response interface{ HTTPStatusCode() int }
		if errors.As(partsErr, &response) {
			status = response.HTTPStatusCode()
		}
		t.Logf("inventory: list-parts-code=%q status=%d list-uploads=%d list-error=%t", code, status, uploads, listErr != nil)
		t.Fatal("release after verified object", err)
	}
	if b, o := charge(t, allocation); b != first.Registration.ReservedBytes() || o != 4 {
		t.Fatal("temporary obligation not released exactly once", b, o)
	}
	// Abort path: an unfinished upload releases only after inventory absence.
	second := plan(allocation, storeID, 20<<20)
	if _, err = ledger.RegisterStreaming(ctx, second); err != nil {
		t.Fatal(err)
	}
	w2, err := privacy.NewStreamingWriter(ctx, second, ledger, objects)
	if err != nil {
		t.Fatal(err)
	}
	if err = w2.Write(ctx, native[:9<<20]); err != nil { // one full part uploaded
		t.Fatal(err)
	}
	state, err = ledger.ReadStreaming(ctx, second)
	if err != nil || state.UploadID == "" || len(state.Parts) != 1 || state.CompleteSpent {
		t.Fatal("unfinished journal", err)
	}
	if err = privacy.ReleaseStreaming(ctx, second, state, ledger, objects); err != nil {
		t.Fatal("abort release", err)
	}
	if b, o := charge(t, allocation); b != first.Registration.ReservedBytes()+second.Registration.ReservedBytes() || o != 8 {
		t.Fatal("abort release accounting", b, o)
	}
	if err = privacy.ReleaseStreaming(ctx, second, state, ledger, objects); err == nil {
		t.Fatal("released twice")
	}
	// An uncertain completion keeps its temporary charge until the attempt's own
	// purge proves the prefix empty; deletion then releases both charges once.
	third := plan(allocation, storeID, 20<<20)
	expiry := time.Now().UTC().Truncate(time.Microsecond).Add(4 * time.Second)
	third.Registration.WriteUntil, third.Registration.ExpiresAt, third.Registration.DeleteBy = expiry, expiry, expiry.Add(time.Second)
	before, beforeObjects := charge(t, allocation)
	if _, err = ledger.RegisterStreaming(ctx, third); err != nil {
		t.Fatal(err)
	}
	w3, err := privacy.NewStreamingWriter(ctx, third, ledger, objects)
	if err != nil {
		t.Fatal(err)
	}
	if err = w3.Write(ctx, native[:8<<20]); err != nil { // exactly one acknowledged part
		t.Fatal(err)
	}
	// The completion request was sent but its reply was lost: spent, no receipt.
	if _, _, err = ledger.AdvanceStreaming(ctx, third, artifact.StreamingStep{Kind: artifact.StreamClaimComplete, Bytes: 8 << 20, SHA256: sha256.Sum256(native[:8<<20])}); err != nil {
		t.Fatal(err)
	}
	if state, err = ledger.ReadStreaming(ctx, third); err != nil || !state.CompleteSpent || state.Receipt != nil {
		t.Fatal("uncertain completion journal", err)
	}
	if err = privacy.ReleaseStreaming(ctx, third, state, ledger, objects); err == nil {
		t.Fatal("uncertain completion released before the attempt purge")
	}
	if b, _ := charge(t, allocation); b != before+third.Registration.ReservedBytes()+third.TemporaryBytes() {
		t.Fatal("uncertain completion lost its temporary charge", b)
	}
	time.Sleep(time.Until(expiry.Add(20 * time.Millisecond)))
	bound, err := store.ForCustody(storeID)
	if err != nil {
		t.Fatal(err)
	}
	if err = (privacy.Cleaner{Ledger: ledger, Barrier: &fixtureBarrier{}, Purger: bound}).Clean(ctx, third.Registration.Location); err != nil {
		t.Fatal("streaming attempt cleanup", err)
	}
	if b, o := charge(t, allocation); b != before || o != beforeObjects {
		t.Fatal("streaming attempt deletion did not return to the prior charge", b, o, before, beforeObjects)
	}
	t.Log("ADR-166 streaming: 20 MiB in three parts, create-only completion, full ciphertext verification, exact charge release and abort inventory on real PostgreSQL/S3")
}
