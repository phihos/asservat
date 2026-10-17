package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Real S3 and cryptography, with local key backends inside the test process.
// This does not qualify the pending authenticated local key-service boundary.
func TestLocalKeysWithRealStorage(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration for owned real-service fixtures")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture file unavailable")
	}
	var f fixture
	if json.Unmarshal(b, &f) != nil || f.S3 == "" {
		t.Fatal("invalid fixture")
	}
	clear(b)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s3TLS := tlsBridge(t, f.S3)
	credential := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &s3TLS.URL, UsePathStyle: true, Credentials: credential, HTTPClient: s3TLS.Client(), RetryMaxAttempts: 1})
	if _, err := admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("local-keys")}); err != nil {
		t.Fatal("fixture bucket creation")
	}
	store, err := objectstore.New(s3TLS.URL, "us-east-1", "local-keys", credential, s3TLS.Client())
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	defer clear(material)
	scope := kms.LocalKeyScope{InstallationID: "00000000-0000-4000-8000-000000000001", Purpose: "artifact", KeyID: "synthetic-storage"}
	secret, err := json.Marshal(map[string]any{
		"format": "asservat-local-keys/v1", "installationID": scope.InstallationID, "purpose": scope.Purpose,
		"keyID": scope.KeyID, "activeVersion": 1,
		"keys": []any{map[string]any{"version": 1, "material": material}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	loadKeys := func() *kms.LocalKeyBackend {
		t.Helper()
		backend, err := kms.NewLocalKeyBackend(scope, bytes.NewReader(secret))
		if err != nil {
			t.Fatal(err)
		}
		return backend
	}
	writer := loadKeys()
	binding := artifact.Binding{
		ClusterID: "00000000-0000-4000-8000-000000000051", ArtifactID: "00000000-0000-4000-8000-000000000052",
		AttemptID: "00000000-0000-4000-8000-000000000053", MediaType: "application/octet-stream",
	}
	native := make([]byte, (8<<20)+733)
	if _, err := rand.Read(native); err != nil {
		t.Fatal(err)
	}
	defer clear(native)
	encoder, err := framed.Prepare(ctx, binding, writer)
	if err != nil {
		t.Fatal(err)
	}
	var data, index bytes.Buffer
	layout, err := encoder.Encode(ctx, bytes.NewReader(native), &data, &index, int64(len(native)))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := framed.MarshalLayout(layout)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := framed.PrepareManifest(ctx, binding, writer)
	if err != nil {
		t.Fatal(err)
	}
	cipher, sealed, err := manifest.Seal(ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "v1/" + binding.ClusterID + "/" + binding.ArtifactID + "/" + binding.AttemptID + "/"
	objects := make([]objectstore.Object, 0, 3)
	for _, item := range []struct {
		name string
		body []byte
	}{{"data", data.Bytes()}, {"index", index.Bytes()}, {"manifest", cipher}} {
		object, err := store.PutSmall(ctx, prefix+item.name, item.body)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Verify(ctx, object); err != nil {
			t.Fatal(err)
		}
		objects = append(objects, object)
	}
	// Reconstruct from serialized root material and stored encrypted metadata;
	// retain no writer keysets or native-layout values in the read path.
	readerKeys := loadKeys()
	manifestSource, err := store.Pin(objects[2])
	if err != nil {
		t.Fatal(err)
	}
	stored, err := manifestSource.ReadRange(ctx, 0, objects[2].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := framed.OpenManifest(ctx, binding, readerKeys, sealed, stored, objects[2].SHA256)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := framed.ParseLayout(opened, binding)
	if err != nil {
		t.Fatal(err)
	}
	dataSource, err := store.Pin(objects[0])
	if err != nil {
		t.Fatal(err)
	}
	indexSource, err := store.Pin(objects[1])
	if err != nil {
		t.Fatal(err)
	}
	reader, err := framed.Open(ctx, restored, readerKeys, dataSource, indexSource)
	if err != nil {
		t.Fatal(err)
	}
	out := &output{}
	if err := reader.Read(ctx, 0, restored.NativeBytes, out); err != nil || !bytes.Equal(out.Bytes(), native) || artifact.Digest(sha256.Sum256(out.Bytes())) != restored.NativeSHA256 {
		t.Fatal("native readback mismatch", err)
	}
	out.Reset()
	offset := int64((8 << 20) - 97)
	if err := reader.Read(ctx, offset, 141, out); err != nil || !bytes.Equal(out.Bytes(), native[offset:offset+141]) {
		t.Fatal("cross-frame range mismatch", err)
	}
	t.Logf("local wrapping, encrypted manifest reload and TLS S3: exact %d-byte native file/hash and cross-frame range", len(native))
}
