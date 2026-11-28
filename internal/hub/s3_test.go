package hub_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"asservat.local/asservat/internal/hub"
)

// The S3 store streams an object of unknown size, reads it back and deletes
// it. Set ASSERVAT_TEST_S3 to "host:port,accessKey,secretKey" of an
// S3-compatible server reachable over HTTP.
func TestS3Blobs(t *testing.T) {
	parts := strings.Split(os.Getenv("ASSERVAT_TEST_S3"), ",")
	if len(parts) != 3 {
		t.Skip("ASSERVAT_TEST_S3 is not set")
	}
	const bucket = "asservat-test"
	client, err := minio.New(parts[0], &minio.Options{Creds: credentials.NewStaticV4(parts[1], parts[2], "")})
	if err != nil {
		t.Fatal(err)
	}
	if exists, err := client.BucketExists(t.Context(), bucket); err != nil {
		t.Fatal(err)
	} else if !exists {
		if err := client.MakeBucket(t.Context(), bucket, minio.MakeBucketOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	blobs, err := hub.NewS3Blobs(parts[0], bucket, parts[1], parts[2], false)
	if err != nil {
		t.Fatal(err)
	}
	// A hub that starts is told whether its bucket is there.
	if err := blobs.Check(t.Context()); err != nil {
		t.Fatal("a bucket that is there:", err)
	}
	if missing, err := hub.NewS3Blobs(parts[0], "asservat-no-such-bucket", parts[1], parts[2], false); err != nil || missing.Check(t.Context()) == nil {
		t.Fatal("a bucket that is not there is taken for one that is", err)
	}
	data := make([]byte, 20<<20) // more than one multipart part
	rand.Read(data)
	// io.MultiReader hides the length, like an upload that is still recording.
	if err := blobs.Put(t.Context(), "object", io.MultiReader(bytes.NewReader(data))); err != nil {
		t.Fatal(err)
	}
	r, err := blobs.Get(t.Context(), "object")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("read back", len(got), err)
	}
	if err := blobs.Delete(t.Context(), "object"); err != nil {
		t.Fatal(err)
	}
	if r, err := blobs.Get(context.Background(), "object"); err == nil {
		if _, err := io.ReadAll(r); err == nil {
			t.Fatal("a deleted object is still served")
		}
	}
	if err := blobs.Delete(t.Context(), "object"); err != nil {
		t.Fatal("deleting an absent object", err)
	}
}
