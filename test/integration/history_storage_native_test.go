package integration

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Actual IAM and storage SDK/TLS behavior, synthetic ciphertexts and registration.
// No test fact supplies production history, recovery, writer or deletion authority.
func TestHistoryCiphertextStorageCapabilityWithRealS3(t *testing.T) {
	path := os.Getenv("ASSERVAT_HISTORY_STORAGE_FIXTURE")
	if path == "" {
		t.Skip("run make history-storage-integration")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var f struct {
		S3, Bucket, Root, Cluster, Identity string
		Actions                             []string
	}
	if json.Unmarshal(raw, &f) != nil || f.S3 == "" {
		t.Fatal("invalid owned history fixture")
	}
	cap, err := objectstore.SeaweedHistoryCapability(f.Bucket, f.Root, f.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	if f.Identity != cap.Identity || !reflect.DeepEqual(f.Actions, cap.SeaweedIdentityActions) {
		t.Fatal("fixture identity differs from production proposal")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bridge := tlsBridge(t, f.S3)
	client := func(key, secret string) *s3.Client {
		return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &bridge.URL, UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: bridge.Client(), RetryMaxAttempts: 1})
	}
	admin := client("synthetic-only", "synthetic-only-secret")
	history := client("synthetic-history", "synthetic-history-secret")
	writer := client("synthetic-evidence", "synthetic-evidence-secret")
	if _, err = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &f.Bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &f.Bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	// Merge the additional purpose, retaining the existing writer deletion denial.
	var original, addition map[string]json.RawMessage
	if json.Unmarshal([]byte(installerEvidenceBucketPolicy(f.Bucket)), &original) != nil || json.Unmarshal(cap.S3BucketPolicy, &addition) != nil {
		t.Fatal("policy proposal invalid")
	}
	var statements, extra []json.RawMessage
	if json.Unmarshal(original["Statement"], &statements) != nil || json.Unmarshal(addition["Statement"], &extra) != nil {
		t.Fatal("policy statements invalid")
	}
	statements = append(statements, extra...)
	original["Statement"], _ = json.Marshal(statements)
	policyRaw, _ := json.Marshal(original)
	policy := string(policyRaw)
	if _, err = admin.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &f.Bucket, Policy: &policy}); err != nil {
		t.Fatal("history policy", err)
	}
	// Only fixture setup convergence of a bounded read-only LIST may retry.
	setup, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	for {
		_, err = history.ListObjectsV2(setup, &s3.ListObjectsV2Input{Bucket: &f.Bucket, Prefix: &cap.Prefix, MaxKeys: aws.Int32(1)})
		if err == nil {
			break
		}
		var failure smithy.APIError
		if !errors.As(err, &failure) || (failure.ErrorCode() != "AccessDenied" && failure.ErrorCode() != "InvalidAccessKeyId") {
			t.Fatal(err)
		}
		select {
		case <-setup.Done():
			t.Fatal("history policy unavailable", setup.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	denied := func(label string, err error) {
		t.Helper()
		var failure smithy.APIError
		if !errors.As(err, &failure) || failure.ErrorCode() != "AccessDenied" {
			t.Fatal(label+" must receive AccessDenied", err)
		}
	}
	evidenceKey := "v1/" + f.Cluster + "/synthetic-history-permission-probe/data"
	evidence, err := writer.PutObject(ctx, &s3.PutObjectInput{Bucket: &f.Bucket, Key: &evidenceKey, Body: strings.NewReader("synthetic evidence permission probe")})
	if err != nil {
		t.Fatal("original writer no longer works", err)
	}
	readDenied := func(key string, version *string) {
		t.Helper()
		got, e := history.GetObject(ctx, &s3.GetObjectInput{Bucket: &f.Bucket, Key: &key, VersionId: version})
		if got != nil && got.Body != nil {
			_ = got.Body.Close()
		}
		denied("outside-prefix read", e)
	}
	readDenied(evidenceKey, nil)
	readDenied(evidenceKey, evidence.VersionId)
	_, err = history.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &f.Bucket, Key: &evidenceKey, VersionId: evidence.VersionId})
	denied("evidence version deletion", err)
	_, err = writer.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &f.Bucket, Key: &evidenceKey, VersionId: evidence.VersionId})
	denied("original writer deletion", err)
	_, err = history.PutObject(ctx, &s3.PutObjectInput{Bucket: &f.Bucket, Key: &evidenceKey, Body: strings.NewReader("forbidden")})
	denied("evidence write", err)
	foreign := "history/v1/" + f.Root + "/30000000-0000-4000-8000-000000000003/foreign"
	foreignObject, err := admin.PutObject(ctx, &s3.PutObjectInput{Bucket: &f.Bucket, Key: &foreign, Body: strings.NewReader("synthetic foreign metadata")})
	if err != nil {
		t.Fatal(err)
	}
	readDenied(foreign, foreignObject.VersionId)
	_, err = history.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &f.Bucket, Key: &foreign, VersionId: foreignObject.VersionId})
	denied("foreign metadata deletion", err)
	for _, prefix := range []*string{nil, aws.String("v1/"), aws.String("history/v1/" + f.Root + "/30000000-0000-4000-8000-000000000003/")} {
		_, err = history.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &f.Bucket, Prefix: prefix, MaxKeys: aws.Int32(1)})
		denied("evidence/foreign object inventory", err)
		_, err = history.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &f.Bucket, Prefix: prefix, MaxKeys: aws.Int32(1)})
		denied("evidence/foreign version inventory", err)
		_, err = history.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &f.Bucket, Prefix: prefix, MaxUploads: aws.Int32(1)})
		denied("evidence/foreign multipart inventory", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := capture.HistoryExpectation{RootID: f.Root, CaptureID: "40000000-0000-4000-8000-000000000004", Registration: artifact.Registration{Location: artifact.Location{ClusterID: f.Cluster, ArtifactID: "50000000-0000-4000-8000-000000000005", AttemptID: "60000000-0000-4000-8000-000000000006"}, StoreID: "70000000-0000-4000-8000-000000000007", AllocationID: "80000000-0000-4000-8000-000000000008", PoolRevision: 1, AllocationRevision: 1, NativeLimit: capture.MaxHistoryParameters, AnchorAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}, SelectorKey: artifact.Digest{1}, SettingsKey: artifact.Digest{2}, MACVersion: "synthetic", OriginalExecutionDigest: artifact.Digest{3}}
	store, err := objectstore.New(bridge.URL, "us-east-1", f.Bucket, credentials.NewStaticCredentialsProvider("synthetic-history", "synthetic-history-secret", ""), bridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	objects := objectstore.HistoryObjects{Store: store, StoreID: e.Registration.StoreID}
	sealed, _ := json.Marshal(artifact.SealedKey{Reference: "transit/metadata", Ciphertext: "synthetic-wrapped-manifest-key"})
	bundle := capture.HistoryCiphertexts{[]byte("synthetic encrypted data"), []byte("synthetic encrypted index"), []byte("synthetic encrypted manifest"), sealed}
	copies, err := objects.Write(ctx, e, bundle)
	if err != nil {
		t.Fatal("history write with actual acknowledged commit", err)
	}
	got, err := objects.Read(ctx, e, copies)
	if err != nil {
		t.Fatal("history version-pinned read", err)
	}
	defer got.Clear()
	for i := range 3 {
		if !bytes.Equal(got[i], bundle[i]) {
			t.Fatal("history ciphertext changed")
		}
	}
	prefix := cap.Prefix + e.Registration.Location.ArtifactID + "/" + e.Registration.Location.AttemptID + "/"
	dataKey := prefix + "data"
	if _, err = admin.PutObject(ctx, &s3.PutObjectInput{Bucket: &f.Bucket, Key: &dataKey, Body: strings.NewReader("synthetic newer history version")}); err != nil {
		t.Fatal(err)
	}
	old, err := objects.Read(ctx, e, copies)
	if err != nil || !bytes.Equal(old[0], bundle[0]) {
		t.Fatal("retained metadata version replaced", err)
	}
	old.Clear()
	uploadKey := prefix + "incomplete"
	upload, err := admin.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &f.Bucket, Key: &uploadKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.UploadPart(ctx, &s3.UploadPartInput{Bucket: &f.Bucket, Key: &uploadKey, UploadId: upload.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("synthetic unfinished part")}); err != nil {
		t.Fatal(err)
	}
	if _, err = history.ListParts(ctx, &s3.ListPartsInput{Bucket: &f.Bucket, Key: &uploadKey, UploadId: upload.UploadId, MaxParts: aws.Int32(1)}); err != nil {
		t.Fatal("history multipart part inventory", err)
	}
	if err = objects.Purge(ctx, e); err != nil {
		t.Fatal("complete history versions and multipart cleanup", err)
	}
	versions, err := admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &f.Bucket, Prefix: &prefix, MaxKeys: aws.Int32(16)})
	if err != nil || aws.ToBool(versions.IsTruncated) || len(versions.Versions)+len(versions.DeleteMarkers) > 0 {
		t.Fatal("history versions remain", err)
	}
	uploads, err := admin.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &f.Bucket, Prefix: &prefix, MaxUploads: aws.Int32(16)})
	if err != nil || aws.ToBool(uploads.IsTruncated) || len(uploads.Uploads) > 0 {
		t.Fatal("history multipart remains", err)
	}
	unchanged, err := admin.GetObject(ctx, &s3.GetObjectInput{Bucket: &f.Bucket, Key: &evidenceKey, VersionId: evidence.VersionId})
	if err != nil {
		t.Fatal("evidence changed during metadata purge", err)
	}
	body, err := io.ReadAll(unchanged.Body)
	_ = unchanged.Body.Close()
	if err != nil || string(body) != "synthetic evidence permission probe" {
		t.Fatal("evidence bytes changed", err)
	}
	t.Log("history-only actual write/read, retained version, ListParts, full version/marker/multipart cleanup; evidence and foreign get/delete/list denied; original writer deletion denial preserved")
}
