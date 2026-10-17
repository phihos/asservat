package integration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Concrete SDK/store/audit composition with real S3 and adapter-facing TLS.
// The fixture's administrator credentials and in-process wrapping key are
// synthetic; this is not runtime IAM, installed key service or SQL authority.
func TestVersionedAuditStorageWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run the owned custody fixture with this exact test")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	var f fixture
	if json.Unmarshal(raw, &f) != nil || f.S3 == "" {
		clear(raw)
		t.Fatal("invalid fixture")
	}
	clear(raw)
	ctx, end := context.WithTimeout(context.Background(), 45*time.Second)
	defer end()
	bridge := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &bridge.URL, UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client(), RetryMaxAttempts: 1})
	bucket := "versioned-audit-" + custodyID()
	if _, err = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	store, err := objectstore.NewVersionedAudit(bridge.URL, "us-east-1", bucket, creds, bridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	unversioned := "unversioned"
	if receipt, err := store.PutSmall(ctx, unversioned, []byte("synthetic unacknowledged bytes")); !errors.Is(err, objectstore.ErrStorage) || receipt != (objectstore.Object{}) {
		t.Fatal("unversioned write acknowledged", err)
	}
	// Rejection does not claim rollback: the uncertain physical copy still exists.
	if _, err = admin.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &unversioned}); err != nil {
		t.Fatal("fixture did not retain refused write", err)
	}
	if _, err = admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	keyBytes := make([]byte, 32)
	if _, err = rand.Read(keyBytes); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(keyBytes)
	clear(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	keys := authorityTestKeys{a: aead}
	writer := &objectstore.OwnerConfigurationAuditObjects{Store: store, Seal: keys, Open: keys}
	id := custodyID()
	configuration := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{bridge.Certificate().Raw}}
	type result struct {
		receipt audit.Receipt
		err     error
	}
	results := make(chan result, 8)
	var joined sync.WaitGroup
	for range 8 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			r, e := writer.WriteOwnerConfiguration(ctx, configuration)
			results <- result{r, e}
		}()
	}
	joined.Wait()
	close(results)
	var original audit.Receipt
	for got := range results {
		if got.err != nil {
			t.Fatal("concurrent original audit", got.err)
		}
		if got.receipt.Version == "" || got.receipt.Version == "null" {
			t.Fatal("missing immutable version")
		}
		if original.Key == "" {
			original = got.receipt
		} else if original != got.receipt {
			t.Fatal("same audit accepted different original receipts")
		}
	}
	list, err := admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &original.Key, MaxKeys: aws.Int32(16)})
	if err != nil || aws.ToBool(list.IsTruncated) || len(list.Versions) != 1 || len(list.DeleteMarkers) != 0 || aws.ToString(list.Versions[0].VersionId) != original.Version {
		t.Fatal("concurrent audit did not retain exactly one version", err)
	}
	pinned := objectstore.Object{Key: original.Key, VersionID: original.Version, ETag: original.ETag, Bytes: original.Bytes, SHA256: original.SHA256}
	if err = store.Verify(ctx, pinned); err != nil {
		t.Fatal("original version verification", err)
	}
	if _, err = admin.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &original.Key, Body: bytes.NewReader([]byte("synthetic malformed latest version"))}); err != nil {
		t.Fatal(err)
	}
	if err = store.Verify(ctx, pinned); err != nil {
		t.Fatal("latest-key replacement changed pinned bytes", err)
	}
	if r, e := writer.WriteOwnerConfiguration(ctx, configuration); e == nil || r != (audit.Receipt{}) {
		t.Fatal("malformed latest record reconciled as original audit")
	}
	if _, err = admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusSuspended}}); err != nil {
		t.Fatal(err)
	}
	if r, e := store.PutSmall(ctx, "suspended", []byte("synthetic suspended version")); !errors.Is(e, objectstore.ErrStorage) || r != (objectstore.Object{}) {
		t.Fatal("suspended-versioning write acknowledged", e)
	}
	// Only the independent synthetic administrator deletes. Exact null versions
	// are included; never turn logical deletion into another marker.
	all, err := admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, MaxKeys: aws.Int32(16)})
	if err != nil || aws.ToBool(all.IsTruncated) || len(all.Versions) != 4 || len(all.DeleteMarkers) != 0 {
		t.Fatal("complete exact inventory unavailable", err)
	}
	for _, v := range all.Versions {
		if _, err = admin.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: v.Key, VersionId: v.VersionId}); err != nil {
			t.Fatal(err)
		}
	}
	remaining, err := admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, MaxKeys: aws.Int32(16)})
	if err != nil || aws.ToBool(remaining.IsTruncated) || len(remaining.Versions) != 0 || len(remaining.DeleteMarkers) != 0 {
		t.Fatal("version inventory remained after deletion", err)
	}
	if err = store.Verify(ctx, pinned); !errors.Is(err, objectstore.ErrStorage) {
		t.Fatal("erased original still verified", err)
	}
	if _, err = admin.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
}
