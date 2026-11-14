package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

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
