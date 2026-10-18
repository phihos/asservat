package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// This owned provider qualification runs the same operations as the installer.
// It supplies no installed deletion lease, cleanup authority or capacity proof.
func TestInstalledEvidenceDeleteCredentialWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run scripts/test-custody.py --run '^TestInstalledEvidenceDeleteCredentialWithRealServices$'")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	var f struct {
		S3                      string `json:"s3"`
		InstalledEvidenceDelete bool   `json:"installedEvidenceDelete"`
	}
	if json.Unmarshal(raw, &f) != nil || f.S3 == "" {
		clear(raw)
		t.Fatal("invalid fixture")
	}
	clear(raw)
	if !f.InstalledEvidenceDelete {
		t.Skip("the exact custody selection must provision the List-only evidence-delete identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bridge := tlsBridge(t, f.S3)
	client := func(key, secret string) *s3.Client {
		return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &bridge.URL, UsePathStyle: true,
			Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: bridge.Client(), RetryMaxAttempts: 1})
	}
	admin := client("synthetic-only", "synthetic-only-secret")
	cleaner := client("evidence-delete-continuation", "evidence-delete-continuation-secret")
	const bucket = "synthetic-installed-evidence-delete"
	if _, err = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("create owned evidence-deletion fixture bucket", err)
	}
	qualifyInstalledEvidenceDeleteCredential(t, ctx, admin, cleaner, bucket)
}
