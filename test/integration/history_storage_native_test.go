package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type regionalStorageFixture struct {
	S3, Bucket, Root, Cluster, OtherCluster           string
	Admin, Writer, History, OtherWriter, OtherHistory contracts.SeaweedCredential
	BucketPolicy                                      string
}

// The fixture script mounts the production compiler's s3.json before the
// pinned server starts. All credentials and object contents are synthetic.
func TestPrepareRegionalStorageFixture(t *testing.T) {
	dir := os.Getenv("ASSERVAT_REGIONAL_STORAGE_FIXTURE_DIR")
	if dir == "" {
		t.Skip("prepared by make history-storage-integration")
	}
	f := regionalStorageFixture{Bucket: "synthetic-history-capability", Root: custodyID(), Cluster: custodyID(), OtherCluster: custodyID()}
	installation := custodyID()
	credential := func(role, scope string) contracts.SeaweedCredential {
		c, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: role, ScopeID: scope})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	f.Admin = credential("admin", installation)
	f.Writer, f.History = credential("regional-write", f.Cluster), credential("regional-history", f.Cluster)
	f.OtherWriter, f.OtherHistory = credential("regional-write", f.OtherCluster), credential("regional-history", f.OtherCluster)
	var grants []contracts.SeaweedGrant
	for _, c := range []contracts.SeaweedCredential{f.Writer, f.History, f.OtherWriter, f.OtherHistory, credential("download-read", installation), credential("evidence-delete", installation)} {
		grants = append(grants, contracts.SeaweedGrant{Credential: c, Bucket: f.Bucket, InstallationID: installation, ClusterID: c.Principal.ScopeID, RootID: f.Root})
	}
	writeConfig := func(file string, grants []contracts.SeaweedGrant) string {
		t.Helper()
		config, err := providerconfig.CompileSeaweedStorage(f.Admin, grants)
		if err != nil {
			t.Fatal(err)
		}
		// The fixture container runs as UID 1000. The parent directory is private.
		if err = os.WriteFile(filepath.Join(dir, file), config.Config, 0444); err != nil {
			t.Fatal(err)
		}
		return string(config.Policies[f.Bucket])
	}
	f.BucketPolicy = writeConfig("s3.json", grants)
	active := slices.DeleteFunc(grants, func(g contracts.SeaweedGrant) bool {
		return g.Credential.Principal.ScopeID == f.OtherCluster
	})
	if writeConfig("s3-revoked.json", active) != f.BucketPolicy {
		t.Fatal("withdrawal changed the shared bucket policy")
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "fixture.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func readRegionalStorageFixture(t *testing.T) regionalStorageFixture {
	t.Helper()
	path := os.Getenv("ASSERVAT_HISTORY_STORAGE_FIXTURE")
	if path == "" {
		t.Skip("run make history-storage-integration")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var f regionalStorageFixture
	if json.Unmarshal(raw, &f) != nil || f.S3 == "" || f.BucketPolicy == "" {
		t.Fatal("invalid owned regional storage fixture")
	}
	return f
}

func regionalStorageClients(bridge *httptest.Server) func(contracts.SeaweedCredential) *s3.Client {
	return func(c contracts.SeaweedCredential) *s3.Client {
		return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &bridge.URL, UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, ""), HTTPClient: bridge.Client(), RetryMaxAttempts: 1})
	}
}

// Actual IAM and storage SDK/TLS behavior, synthetic ciphertexts and registration.
// No test fact supplies production history, recovery, writer or deletion authority.
func TestHistoryCiphertextStorageCapabilityWithRealS3(t *testing.T) {
	f := readRegionalStorageFixture(t)
	historyPrefix := "history/v1/" + f.Root + "/" + f.Cluster + "/"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bridge := tlsBridge(t, f.S3)
	client := regionalStorageClients(bridge)
	admin := client(f.Admin)
	history := client(f.History)
	writer := client(f.Writer)
	if _, err := admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &f.Bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &f.Bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &f.Bucket, Policy: &f.BucketPolicy}); err != nil {
		t.Fatal("shared bucket policy", err)
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
	foreign := "history/v1/" + f.Root + "/" + f.OtherCluster + "/foreign"
	foreignObject, err := client(f.OtherHistory).PutObject(ctx, &s3.PutObjectInput{Bucket: &f.Bucket, Key: &foreign, Body: strings.NewReader("synthetic foreign metadata")})
	if err != nil {
		t.Fatal(err)
	}
	readDenied(foreign, foreignObject.VersionId)
	_, err = history.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &f.Bucket, Key: &foreign, VersionId: foreignObject.VersionId})
	denied("foreign metadata deletion", err)
	for _, prefix := range []*string{nil, aws.String("v1/"), aws.String("history/v1/" + f.Root + "/" + f.OtherCluster + "/")} {
		_, err = history.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &f.Bucket, Prefix: prefix, MaxKeys: aws.Int32(1)})
		denied("evidence/foreign object inventory", err)
		_, err = history.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &f.Bucket, Prefix: prefix, MaxKeys: aws.Int32(1)})
		denied("evidence/foreign version inventory", err)
		_, err = history.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &f.Bucket, Prefix: prefix, MaxUploads: aws.Int32(1)})
		denied("evidence/foreign multipart inventory", err)
	}
	foreignEvidence := "v1/" + f.OtherCluster + "/foreign"
	_, err = client(f.OtherWriter).PutObject(ctx, &s3.PutObjectInput{Bucket: &f.Bucket, Key: &foreignEvidence, Body: strings.NewReader("other region")})
	if err != nil {
		t.Fatal("other region writer", err)
	}
	_, err = writer.PutObject(ctx, &s3.PutObjectInput{Bucket: &f.Bucket, Key: &foreignEvidence, Body: strings.NewReader("forbidden")})
	denied("foreign evidence write", err)
	_, err = writer.GetObject(ctx, &s3.GetObjectInput{Bucket: &f.Bucket, Key: &evidenceKey})
	denied("evidence writer read", err)
	_, err = writer.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &f.Bucket, Prefix: &evidenceKey})
	denied("evidence writer list", err)
	for _, c := range []*s3.Client{writer, history} {
		_, err = c.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &f.Bucket, Policy: &f.BucketPolicy})
		denied("regional bucket administration", err)
	}
	for _, abort := range []bool{false, true} {
		mpKey := evidenceKey + "-multipart"
		start, err := writer.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &f.Bucket, Key: &mpKey})
		if err != nil {
			t.Fatal("writer start multipart", err)
		}
		part, err := writer.UploadPart(ctx, &s3.UploadPartInput{Bucket: &f.Bucket, Key: &mpKey, UploadId: start.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("synthetic part")})
		if err != nil {
			t.Fatal("writer upload part", err)
		}
		if abort {
			_, err = writer.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &f.Bucket, Key: &mpKey, UploadId: start.UploadId})
		} else {
			_, err = writer.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &f.Bucket, Key: &mpKey, UploadId: start.UploadId, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{{PartNumber: aws.Int32(1), ETag: part.ETag}}}})
		}
		if err != nil {
			t.Fatal("writer finish multipart", err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := capture.HistoryExpectation{RootID: f.Root, CaptureID: "40000000-0000-4000-8000-000000000004", Registration: artifact.Registration{Location: artifact.Location{ClusterID: f.Cluster, ArtifactID: "50000000-0000-4000-8000-000000000005", AttemptID: "60000000-0000-4000-8000-000000000006"}, StoreID: "70000000-0000-4000-8000-000000000007", AllocationID: "80000000-0000-4000-8000-000000000008", PoolRevision: 1, AllocationRevision: 1, NativeLimit: capture.MaxHistoryParameters, AnchorAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}, SelectorKey: artifact.Digest{1}, SettingsKey: artifact.Digest{2}, MACVersion: "synthetic", OriginalExecutionDigest: artifact.Digest{3}}
	store, err := objectstore.New(bridge.URL, "us-east-1", f.Bucket, credentials.NewStaticCredentialsProvider(f.History.AccessKeyID, f.History.SecretAccessKey, ""), bridge.Client())
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
	prefix := historyPrefix + e.Registration.Location.ArtifactID + "/" + e.Registration.Location.AttemptID + "/"
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

// This phase runs after the same store restarts with one registration removed.
// Use both originally issued credentials and objects from before withdrawal.
func TestRevokedRegionalStorageKeysWithRealS3(t *testing.T) {
	f := readRegionalStorageFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := regionalStorageClients(tlsBridge(t, f.S3))
	otherHistory := "history/v1/" + f.Root + "/" + f.OtherCluster + "/foreign"
	read := &s3.GetObjectInput{Bucket: &f.Bucket, Key: &otherHistory}
	object, err := client(f.Admin).GetObject(ctx, read)
	if err != nil {
		t.Fatal("revoked cluster's retained history is missing", err)
	}
	object.Body.Close()
	denied := func(label string, err error) {
		t.Helper()
		var failure smithy.APIError
		if !errors.As(err, &failure) || failure.ErrorCode() != "InvalidAccessKeyId" {
			t.Fatalf("%s: expected InvalidAccessKeyId for withdrawn credential, got %v", label, err)
		}
	}
	_, err = client(f.OtherHistory).GetObject(ctx, read)
	denied("revoked history read", err)
	write := &s3.PutObjectInput{Bucket: &f.Bucket, Key: aws.String("v1/" + f.OtherCluster + "/foreign"), Body: strings.NewReader("refused")}
	_, err = client(f.OtherWriter).PutObject(ctx, write)
	denied("revoked evidence write", err)
	for _, item := range []struct {
		credential contracts.SeaweedCredential
		key        string
	}{{f.Writer, "v1/" + f.Cluster + "/retained"}, {f.History, "history/v1/" + f.Root + "/" + f.Cluster + "/retained"}} {
		if _, err := client(item.credential).PutObject(ctx, &s3.PutObjectInput{Bucket: &f.Bucket, Key: &item.key, Body: strings.NewReader("retained")}); err != nil {
			t.Fatal("remaining cluster credential refused", item.credential.Principal.Purpose, err)
		}
	}
}
