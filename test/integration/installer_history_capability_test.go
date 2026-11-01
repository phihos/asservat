package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// The owned installer fixture provisions the operator's separate history
// capability using the production proposal, never the evidence writer key.
func installerRegionalHistoryCredential(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, bucket, root, cluster string) []byte {
	t.Helper()
	capability, err := objectstore.SeaweedHistoryCapability(bucket, root, cluster)
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		Container string `json:"runtimeProviderPairS3Container"`
	}
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil || json.Unmarshal(raw, &native) != nil || !strings.HasPrefix(native.Container, "asservat-context-") || !strings.HasSuffix(native.Container, "-s3") {
		clear(raw)
		t.Fatal("owned history S3 container missing", err)
	}
	clear(raw)
	runID := strings.TrimSuffix(strings.TrimPrefix(native.Container, "asservat-"), "-s3")
	label, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{ index .Config.Labels \"asservat.test\" }}", native.Container).Output()
	if err != nil || strings.TrimSpace(string(label)) != runID {
		t.Fatal("refuse non-owned history storage administration", err)
	}
	key, secret := "history-"+cluster, "synthetic-history-secret-"+cluster
	shell := "s3.configure -user=" + capability.Identity + " -access_key=" + key + " -secret_key=" + secret + " -actions=" + strings.Join(capability.SeaweedIdentityActions, ",") + " -apply\n"
	command := exec.CommandContext(ctx, "docker", "exec", "-i", native.Container, "/usr/bin/weed", "shell", "-master=localhost:9333", "-filer=localhost:8888")
	command.Stdin = strings.NewReader(shell)
	if output, e := command.CombinedOutput(); e != nil {
		clear(output)
		t.Fatal("owned history IAM provisioning failed", e)
	}
	var historyPolicy struct {
		Version   string
		Statement []map[string]any
	}
	if json.Unmarshal(capability.S3BucketPolicy, &historyPolicy) != nil {
		t.Fatal("history policy proposal invalid")
	}
	for _, statement := range historyPolicy.Statement {
		if sid, ok := statement["Sid"].(string); ok {
			statement["Sid"] = sid + strings.ReplaceAll(cluster, "-", "")
		}
	}
	addition, _ := json.Marshal(historyPolicy)
	installerMergeBucketPolicy(t, ctx, p, bucket, addition)
	out, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: key, SecretAccessKey: secret})
	return out
}

// Preserve other region capabilities and existing writer deletion denials.
// Reinstalling a region is idempotent and never replaces the bucket's policy.
func installerMergeBucketPolicy(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, bucket string, addition []byte) {
	t.Helper()
	store := s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: aws.String(p.desired.AuditStore.Endpoint), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: p.client, RetryMaxAttempts: 1})
	current, err := store.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
	var statements []json.RawMessage
	if err == nil && current.Policy != nil {
		var policy struct{ Statement []json.RawMessage }
		if json.Unmarshal([]byte(*current.Policy), &policy) != nil {
			t.Fatal("invalid existing bucket policy")
		}
		statements = policy.Statement
	} else if err != nil {
		var failure smithy.APIError
		if !errors.As(err, &failure) || failure.ErrorCode() != "NoSuchBucketPolicy" {
			t.Fatal("read existing bucket policy", err)
		}
	}
	var policy struct{ Statement []json.RawMessage }
	if json.Unmarshal(addition, &policy) != nil || len(policy.Statement) == 0 {
		t.Fatal("invalid proposed bucket policy")
	}
	seen := map[string]bool{}
	var combined []any
	for _, raw := range append(statements, policy.Statement...) {
		var statement map[string]any
		if json.Unmarshal(raw, &statement) != nil {
			t.Fatal("invalid bucket policy statement")
		}
		canonical, _ := json.Marshal(statement)
		if !seen[string(canonical)] {
			combined = append(combined, statement)
			seen[string(canonical)] = true
		}
	}
	encoded, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": combined})
	text := string(encoded)
	if _, err = store.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &text}); err != nil {
		t.Fatal("merge regional capability policy", err)
	}
}
