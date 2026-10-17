package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Actual version/marker/upload inventory with a LIST-only credential. Fixture
// administration and arbitrary synthetic physical bytes are not valid audit
// receipts, an installed reserve, writer closure or retirement authority.
func TestOwnerAuditInventoryWithRealServices(t *testing.T) {
	if os.Getenv("ASSERVAT_OWNER_AUDIT_INVENTORY") != "1" {
		t.Skip("run scripts/test-custody.py --owner-audit-inventory")
	}
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CUSTODY_FIXTURES"))
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	var f fixture
	if json.Unmarshal(raw, &f) != nil || f.S3 == "" {
		clear(raw)
		t.Fatal("invalid fixture")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	bridge := tlsBridge(t, f.S3)
	const id = "a9a9b231-0d4c-4d72-89aa-1a4516be9e9c"
	const bucket = "synthetic-owner-inventory"
	const foreignBucket = "synthetic-owner-inventory-foreign"
	prefix := "hub-owner-configuration/v1/" + id + "/" + id + "/" + id + "/"
	credential := func(role string) aws.CredentialsProvider {
		if role == "administrator" {
			return credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
		}
		return credentials.NewStaticCredentialsProvider(role+"-synthetic", role+"-synthetic-secret", "")
	}
	client := func(role string) *s3.Client {
		return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &bridge.URL, UsePathStyle: true, Credentials: credential(role), HTTPClient: bridge.Client(), RetryMaxAttempts: 1})
	}
	admin, writer, inspector := client("administrator"), client("configuration"), client("inventory")
	if _, err = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(foreignBucket)}); err != nil {
		t.Fatal(err)
	}
	original := fleet.OwnerConfiguration{Pool: fleet.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{bridge.Certificate().Raw}}
	historical := fleet.OwnerConfigurationObservation{Configuration: original, ObservedAt: time.Now().Add(-time.Hour), FreshUntil: time.Now().Add(-time.Hour + 5*time.Second)}
	if historical.Valid(time.Now()) {
		t.Fatal("fixture accidentally supplied current source authority")
	}
	key := audit.OwnerConfigurationAuditKey(original)
	// Keep an actual unversioned zero-byte copy before enabling the bucket. Its
	// address is accepted only when the independent actual LIST reports null.
	if _, err = admin.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: &key, Body: bytes.NewReader(nil)}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	expectedBodies := map[string][]byte{}
	put := func(k string, body []byte) string {
		v, e := writer.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: &k, Body: bytes.NewReader(body)})
		if e != nil || aws.ToString(v.VersionId) == "" || aws.ToString(v.VersionId) == "null" {
			t.Fatal("fixture versioned write", e)
		}
		expectedBodies[k+"\x00"+*v.VersionId] = bytes.Clone(body)
		return *v.VersionId
	}
	first := put(key, []byte("synthetic first physical bytes"))
	put(key, []byte("synthetic second physical bytes"))
	marker, err := admin.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: &key})
	if err != nil || !aws.ToBool(marker.DeleteMarker) || aws.ToString(marker.VersionId) == "" {
		t.Fatal("fixture marker missing", err)
	}
	latest := put(key, []byte("synthetic latest physical bytes"))
	put(key+"0", []byte("synthetic generation ten"))
	put(key+"1", []byte("synthetic generation eleven"))
	upload, err := writer.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(bucket), Key: &key})
	if err != nil || aws.ToString(upload.UploadId) == "" {
		t.Fatal("fixture pending upload", err)
	}
	part := []byte("synthetic unfinished part with unknown diagnostic byte count")
	if _, err = writer.UploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String(bucket), Key: &key, UploadId: upload.UploadId, PartNumber: aws.Int32(1), Body: bytes.NewReader(part)}); err != nil {
		t.Fatal("fixture part", err)
	}
	// The inspection role has LIST alone, scoped to this owned bucket. Verify it
	// cannot read ciphertext, PUT, delete versions, abort, or alter versioning.
	denied := func(t *testing.T, e error) {
		t.Helper()
		var api smithy.APIError
		if !errors.As(e, &api) || api.ErrorCode() != "AccessDenied" {
			t.Fatal("expected actual inspector AccessDenied", e)
		}
	}
	before := readNativeOwnerAuditInventory(t, ctx, admin, bucket, prefix, key, *upload.UploadId)
	if len(before.versions) != 7 || len(before.uploads) != 1 || len(before.parts) != 1 || before.parts[1] != int64(len(part)) {
		t.Fatal("fixture physical graph incomplete", len(before.versions), len(before.uploads), before.parts)
	}
	null, ok := before.versions[key+"\x00null"]
	if !ok || null.marker || null.size != 0 {
		t.Fatal("actual historical zero-byte null version not listed")
	}
	expectedBodies[key+"\x00null"] = nil
	if len(expectedBodies) != 6 {
		t.Fatal("fixture expected body graph changed")
	}
	for object, body := range expectedBodies {
		v, ok := before.versions[object]
		if !ok || v.marker || v.size != int64(len(body)) || v.digest != sha256.Sum256(body) {
			t.Fatal("independent exact version bytes differ")
		}
	}
	productBridge, trace := nativeOwnerAuditBridge(t, f.S3)
	store, err := objectstore.New(productBridge.URL, "us-east-1", bucket, credential("inventory"), productBridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reader, err := objectstore.NewOwnerConfigurationAuditInventory(store, id, historical.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	historical = fleet.OwnerConfigurationObservation{} // No current source reread is available.
	t.Run("list-only-retains-versions-before-multipart-denial", func(t *testing.T) {
		page, e := reader.Read(ctx)
		calls := trace.observations()
		want := []nativeOwnerAuditCall{{Operation: "ListObjectVersions", Status: 200}, {Operation: "ListMultipartUploads", Status: 403}}
		if !errors.Is(e, objectstore.ErrStorage) || !reflect.DeepEqual(calls, want) || !page.VersionsComplete || page.UploadsComplete || page.CurrentComplete || page.Current != nil || len(page.Versions) != 5 || len(page.Uploads) != 0 {
			t.Fatalf("original LIST-only failure differs: %v; fixed calls=%+v versionsComplete=%t uploadsComplete=%t currentComplete=%t retainedVersions=%d retainedUploads=%d", e, calls, page.VersionsComplete, page.UploadsComplete, page.CurrentComplete, len(page.Versions), len(page.Uploads))
		}
		for _, version := range page.Versions {
			known, ok := before.versions[key+"\x00"+version.VersionID]
			if !ok || version.CiphertextBytes != known.size || version.Latest != known.latest || (version.Kind == objectstore.OwnerAuditDeleteMarker) != known.marker {
				t.Fatal("failed LIST discarded or changed known original version facts")
			}
		}
	})
	if t.Failed() {
		t.FailNow()
	}
	// A separate fixture administrator grants exactly the missing bucket-level
	// API action, scoped to this principal and the original requested prefix.
	// The inspector's coarse actions remain List-only; no object Read is added.
	policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Sid": "AllowOnlyOriginalMultipartListing", "Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::000000000000:user/inventory"}, "Action": "s3:ListBucketMultipartUploads", "Resource": "arn:aws:s3:::" + bucket, "Condition": map[string]any{"StringEquals": map[string]any{"s3:prefix": key}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: aws.String(string(policy))}); err != nil {
		t.Fatal("fixture narrow multipart-list policy", err)
	}
	t.Run("multipart-policy-rejects-other-prefixes", func(t *testing.T) {
		for _, prefix := range []*string{nil, aws.String(key + "0"), aws.String(key + "1")} {
			_, e := inspector.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(bucket), Prefix: prefix, MaxUploads: aws.Int32(1)})
			denied(t, e)
		}
		_, e := inspector.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(foreignBucket), Prefix: &key, MaxUploads: aws.Int32(1)})
		denied(t, e)
	})
	if t.Failed() {
		t.FailNow()
	}
	t.Run("inspection-credential-cannot-mutate-or-read-bodies", func(t *testing.T) {
		_, e := inspector.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(foreignBucket), Prefix: &key, MaxKeys: aws.Int32(1)})
		denied(t, e)
		_, e = inspector.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String(bucket), Key: &key, UploadId: upload.UploadId, MaxParts: aws.Int32(1)})
		denied(t, e)
		got, e := inspector.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: &key})
		if got != nil && got.Body != nil {
			got.Body.Close()
		}
		denied(t, e)
		got, e = inspector.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: &key, VersionId: &first})
		if got != nil && got.Body != nil {
			got.Body.Close()
		}
		denied(t, e)
		_, e = inspector.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: &key, Body: bytes.NewReader([]byte("forbidden"))})
		denied(t, e)
		_, e = inspector.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: &key, VersionId: &first})
		denied(t, e)
		_, e = inspector.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(bucket), Key: &key, UploadId: upload.UploadId})
		denied(t, e)
		_, e = inspector.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusSuspended}})
		denied(t, e)
	})
	if t.Failed() {
		t.FailNow()
	}
	t.Run("expired-original-source-exact-physical-inventory", func(t *testing.T) {
		page, e := reader.Read(ctx)
		if e != nil || page.Key != key || page.StoreID != id || !page.Configuration.Equal(original) || page.ReadUntil.Sub(page.ReadStartedAt) > 5*time.Second || !page.VersionsComplete || !page.UploadsComplete || !page.CurrentComplete || page.CurrentUnmatched {
			t.Logf("original inventory transport: %+v; versionsComplete=%t uploadsComplete=%t currentComplete=%t retainedVersions=%d retainedUploads=%d", trace.observations(), page.VersionsComplete, page.UploadsComplete, page.CurrentComplete, len(page.Versions), len(page.Uploads))
			t.Fatal("actual bounded historical inventory unavailable", e)
		}
		if len(page.Versions) != 5 || len(page.Uploads) != 1 || page.Uploads[0].UploadID != *upload.UploadId || page.Current == nil {
			t.Fatal("version/marker/upload/neighbor distinction lost")
		}
		wantCalls := []nativeOwnerAuditCall{{Operation: "ListObjectVersions", Status: 200}, {Operation: "ListMultipartUploads", Status: 403}, {Operation: "ListObjectVersions", Status: 200}, {Operation: "ListMultipartUploads", Status: 200}, {Operation: "ListObjectsV2", Status: 200}}
		if !reflect.DeepEqual(trace.observations(), wantCalls) {
			t.Fatal("narrow policy did not produce the fixed successful three-LIST operation", trace.observations())
		}
		seen := map[string]bool{}
		for _, v := range page.Versions {
			known, ok := before.versions[key+"\x00"+v.VersionID]
			if !ok || seen[v.VersionID] || v.CiphertextBytes != known.size || v.Latest != known.latest || (v.Kind == objectstore.OwnerAuditDeleteMarker) != known.marker {
				t.Fatal("diagnostic differs from independent version/body inventory")
			}
			seen[v.VersionID] = true
		}
		if !seen["null"] || !seen[*marker.VersionId] || !seen[latest] || page.Current.Bytes != before.versions[key+"\x00"+latest].size {
			t.Fatal("actual original physical IDs/bytes missing")
		}
	})
	if t.Failed() {
		t.FailNow()
	}
	t.Run("inventory-preserves-all-physical-obligations", func(t *testing.T) {
		after := readNativeOwnerAuditInventory(t, ctx, admin, bucket, prefix, key, *upload.UploadId)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("read-only inventory changed physical copies, marker, upload or part")
		}
		t.Log("independent exact version bodies and all seven version/marker entries unchanged; one unfinished upload and part retained; no ledger, release or retirement effect")
	})
	if t.Failed() {
		t.FailNow()
	}
	// Fixture cleanup belongs to its independent administrator after all product
	// reads joined. It is not a product retirement/refund assertion.
	if _, err = admin.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(bucket), Key: &key, UploadId: upload.UploadId}); err != nil {
		t.Fatal(err)
	}
	for ref := range before.versions {
		parts := strings.SplitN(ref, "\x00", 2)
		if _, err = admin.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: &parts[0], VersionId: &parts[1]}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = admin.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(foreignBucket)}); err != nil {
		t.Fatal(err)
	}
}

type nativeOwnerAuditVersion struct {
	size           int64
	marker, latest bool
	digest         [32]byte
}
type nativeOwnerAuditInventory struct {
	versions map[string]nativeOwnerAuditVersion
	uploads  map[string]string
	parts    map[int32]int64
}

func readNativeOwnerAuditInventory(t *testing.T, ctx context.Context, admin *s3.Client, bucket, prefix, key, upload string) nativeOwnerAuditInventory {
	t.Helper()
	out := nativeOwnerAuditInventory{map[string]nativeOwnerAuditVersion{}, map[string]string{}, map[int32]int64{}}
	versions, err := admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &prefix, MaxKeys: aws.Int32(32)})
	if err != nil || versions.IsTruncated == nil || *versions.IsTruncated {
		t.Fatal("independent version inventory", err)
	}
	for _, v := range versions.Versions {
		if v.Key == nil || !strings.HasPrefix(*v.Key, prefix) || v.VersionId == nil || *v.VersionId == "" || v.Size == nil || *v.Size < 0 || *v.Size > 4096 || v.IsLatest == nil {
			t.Fatal("invalid fixture data metadata")
		}
		response, e := admin.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: v.Key, VersionId: v.VersionId})
		if e != nil {
			t.Fatal("exact physical read", e)
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 4097))
		response.Body.Close()
		if e != nil || int64(len(body)) != *v.Size || aws.ToString(response.VersionId) != *v.VersionId {
			t.Fatal("exact physical body mismatch", e)
		}
		ref := *v.Key + "\x00" + *v.VersionId
		if _, exists := out.versions[ref]; exists {
			t.Fatal("duplicate actual version")
		}
		out.versions[ref] = nativeOwnerAuditVersion{size: *v.Size, latest: *v.IsLatest, digest: sha256.Sum256(body)}
	}
	for _, v := range versions.DeleteMarkers {
		if v.Key == nil || !strings.HasPrefix(*v.Key, prefix) || v.VersionId == nil || *v.VersionId == "" || v.IsLatest == nil {
			t.Fatal("invalid fixture marker")
		}
		ref := *v.Key + "\x00" + *v.VersionId
		if _, exists := out.versions[ref]; exists {
			t.Fatal("duplicate actual marker")
		}
		out.versions[ref] = nativeOwnerAuditVersion{marker: true, latest: *v.IsLatest}
	}
	uploads, err := admin.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket, Prefix: &prefix, MaxUploads: aws.Int32(32)})
	if err != nil || uploads.IsTruncated == nil || *uploads.IsTruncated {
		t.Fatal("independent upload inventory", err)
	}
	for _, v := range uploads.Uploads {
		if v.Key == nil || !strings.HasPrefix(*v.Key, prefix) || v.UploadId == nil || *v.UploadId == "" {
			t.Fatal("invalid actual upload")
		}
		ref := *v.Key + "\x00" + *v.UploadId
		if _, exists := out.uploads[ref]; exists {
			t.Fatal("duplicate actual upload")
		}
		out.uploads[ref] = *v.UploadId
	}
	parts, err := admin.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: &key, UploadId: &upload, MaxParts: aws.Int32(32)})
	if err != nil || parts.IsTruncated == nil || *parts.IsTruncated {
		t.Fatal("independent multipart body inventory", err)
	}
	for _, v := range parts.Parts {
		if v.PartNumber == nil || *v.PartNumber < 1 || v.Size == nil || *v.Size < 0 {
			t.Fatal("invalid actual part")
		}
		if _, exists := out.parts[*v.PartNumber]; exists {
			t.Fatal("duplicate actual part")
		}
		out.parts[*v.PartNumber] = *v.Size
	}
	return out
}
