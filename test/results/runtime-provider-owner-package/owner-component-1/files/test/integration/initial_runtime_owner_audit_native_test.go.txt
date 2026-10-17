package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// This is external administration of the same owned native backend, not an
// installer IAM API. Runtime receives only the two fixed owner audit prefixes;
// the existing configuration denial is retained in the one fixture policy.
func (o *initialRuntimeNativeOwner) provisionOwnerAudit(t *testing.T, ctx context.Context, api kubernetes.Interface) {
	t.Helper()
	p := o.providers
	in := o.bootstrap.Input
	if in.ProviderAuthentication == nil || in.ProviderAuthentication.AuditCredentials != p.owner.AuditCredentials || in.InstallationID != p.installation || in.ClusterID != p.cluster {
		t.Fatal("owner audit material does not match original selection")
	}
	var native struct {
		Container string `json:"runtimeProviderPairS3Container"`
	}
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil || json.Unmarshal(raw, &native) != nil || !strings.HasPrefix(native.Container, "asservat-context-") || !strings.HasSuffix(native.Container, "-s3") {
		clear(raw)
		t.Fatal("owned native S3 container unavailable", err)
	}
	clear(raw)
	runID := strings.TrimSuffix(strings.TrimPrefix(native.Container, "asservat-"), "-s3")
	inspect := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{ index .Config.Labels \"asservat.test\" }}", native.Container)
	label, err := inspect.Output()
	if err != nil || strings.TrimSpace(string(label)) != runID {
		t.Fatal("refuse non-owned owner audit provider administration", err)
	}
	bucket := in.AuditStore.Bucket
	prefixes := [2]string{"hub-owner-enrollment/v1/" + in.InstallationID + "/", "hub-owner-certificate/v1/" + in.InstallationID + "/"}
	client := func(key, secret string) *s3.Client {
		return s3.New(s3.Options{Region: in.AuditStore.Region, BaseEndpoint: &in.AuditStore.Endpoint, UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: p.client, RetryMaxAttempts: 1})
	}
	admin := client("synthetic-only", "synthetic-only-secret")
	runtime := client("owner-synthetic", "owner-synthetic-secret")
	versioning, err := admin.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &bucket})
	if err != nil || versioning.Status != s3types.BucketVersioningStatusEnabled {
		t.Fatal("original audit bucket must already require versions", err)
	}
	// Refuse an unknown fixture policy instead of overwriting it. The worker
	// predecessor creates exactly this one denial; the sole transition adds the
	// independent owner principal without changing any action/resource/effect.
	policyReply, err := admin.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
	if err != nil {
		t.Fatal("original worker deletion policy unavailable", err)
	}
	var policy map[string]any
	if json.Unmarshal([]byte(aws.ToString(policyReply.Policy)), &policy) != nil || len(policy) != 2 || policy["Version"] != "2012-10-17" {
		t.Fatal("unexpected original worker bucket policy")
	}
	statements, ok := policy["Statement"].([]any)
	if !ok || len(statements) != 1 {
		t.Fatal("unexpected original worker policy statement set")
	}
	statement, ok := statements[0].(map[string]any)
	if !ok || len(statement) != 5 || statement["Sid"] != "DenyRuntimeDeletion" || statement["Effect"] != "Deny" || statement["Resource"] != "arn:aws:s3:::"+bucket+"/*" {
		t.Fatal("unexpected original worker deletion statement")
	}
	actions, ok := statement["Action"].([]any)
	if !ok || len(actions) != 2 || actions[0] != "s3:DeleteObject" || actions[1] != "s3:DeleteObjectVersion" {
		t.Fatal("original worker deletion actions changed")
	}
	principal, ok := statement["Principal"].(map[string]any)
	if !ok || len(principal) != 1 || principal["AWS"] != "arn:aws:iam::000000000000:user/configuration" {
		t.Fatal("original worker deletion principal changed")
	}
	principal["AWS"] = []string{"arn:aws:iam::000000000000:user/configuration", "arn:aws:iam::000000000000:user/owner"}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: aws.String(string(policyRaw))}); err != nil {
		t.Fatal("extend owned exact runtime deletion denial", err)
	}
	command := exec.CommandContext(ctx, "docker", "exec", "-i", native.Container, "/usr/bin/weed", "shell", "-master=localhost:9333", "-filer=localhost:8888")
	command.Stdin = strings.NewReader("s3.configure -user=owner -access_key=owner-synthetic -secret_key=owner-synthetic-secret -actions=Read:" + bucket + "/" + prefixes[0] + "*,Write:" + bucket + "/" + prefixes[0] + "*,Read:" + bucket + "/" + prefixes[1] + "*,Write:" + bucket + "/" + prefixes[1] + "* -apply\n")
	output, err := command.CombinedOutput()
	clear(output)
	if err != nil {
		t.Fatal("owned exact owner IAM setup unavailable", err)
	}
	denied := func(err error) {
		t.Helper()
		var failure smithy.APIError
		if !errors.As(err, &failure) || failure.ErrorCode() != "AccessDenied" {
			t.Fatal("scoped owner audit denial unavailable", err)
		}
	}
	for _, prefix := range prefixes {
		key := prefix + "qualification/" + custodyID()
		// Register exact-key complete version cleanup before even the first
		// request. An uncertain PUT is never repeated or assumed absent.
		t.Cleanup(func() { retireNativeOwnerProbe(t, admin, bucket, key) })
		body := []byte("synthetic owner audit storage capability probe, not evidence")
		seed, err := admin.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(body)})
		if err != nil || aws.ToString(seed.VersionId) == "" || aws.ToString(seed.VersionId) == "null" {
			t.Fatal("immutable original owner capability probe unavailable", err)
		}
		// External provider subscription may converge only by bounded named
		// reads, before any product credential publication/launch begins.
		setup, stop := context.WithTimeout(ctx, 10*time.Second)
		for {
			got, readErr := runtime.GetObject(setup, &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: seed.VersionId})
			if readErr == nil {
				data, readErr := io.ReadAll(io.LimitReader(got.Body, 1024))
				_ = got.Body.Close()
				if readErr != nil || aws.ToString(got.VersionId) != aws.ToString(seed.VersionId) || !bytes.Equal(data, body) {
					stop()
					t.Fatal("scoped original owner version mismatch", readErr)
				}
				break
			}
			var failure smithy.APIError
			if !errors.As(readErr, &failure) || failure.ErrorCode() != "InvalidAccessKeyId" && failure.ErrorCode() != "AccessDenied" {
				stop()
				t.Fatal("scoped owner provider read unavailable", readErr)
			}
			select {
			case <-setup.Done():
				stop()
				t.Fatal("bounded owner provider subscription did not become ready", setup.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
		stop()
		later, err := runtime.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader([]byte("distinct synthetic later version"))})
		if err != nil || aws.ToString(later.VersionId) == "" || aws.ToString(later.VersionId) == "null" || aws.ToString(later.VersionId) == aws.ToString(seed.VersionId) {
			t.Fatal("scoped owner write did not produce a distinct immutable version", err)
		}
		original, err := runtime.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: seed.VersionId})
		if err != nil {
			t.Fatal("original owner version unavailable after later write", err)
		}
		data, err := io.ReadAll(io.LimitReader(original.Body, 1024))
		_ = original.Body.Close()
		if err != nil || aws.ToString(original.VersionId) != aws.ToString(seed.VersionId) || !bytes.Equal(data, body) {
			t.Fatal("later version replaced original owner receipt", err)
		}
		_, err = runtime.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: seed.VersionId})
		denied(err)
		_, err = runtime.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
		denied(err)
	}
	foreign := "outside-owner-scope/" + custodyID()
	t.Cleanup(func() { retireNativeOwnerProbe(t, admin, bucket, foreign) })
	_, err = runtime.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &foreign, Body: bytes.NewReader([]byte("must be denied"))})
	denied(err)
	_, err = runtime.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusSuspended}})
	denied(err)
	_, err = runtime.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: aws.String(string(policyRaw))})
	denied(err)
	_, err = runtime.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
	denied(err)
	selected := in.ProviderAuthentication.AuditCredentials
	secret, err := api.CoreV1().Secrets(in.Namespace.Name).Get(ctx, selected.Name, meta.GetOptions{})
	if err != nil || string(secret.UID) != selected.UID || len(secret.Data) != 0 {
		t.Fatal("original empty owner audit selection changed", err)
	}
	payload, err := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "owner-synthetic", SecretAccessKey: "owner-synthetic-secret", SessionToken: ""})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	secret.Data = map[string][]byte{contracts.OwnerProviderAuditCredentialFile: payload}
	if _, err = api.CoreV1().Secrets(in.Namespace.Name).Update(ctx, secret, meta.UpdateOptions{}); err != nil {
		t.Fatal("fill original scoped owner audit material", err)
	}
}

// This independent fixture administrator retires every version and marker of
// one exact synthetic probe key, including an unacknowledged/null version. It
// never infers absence from a latest-object GET or deletes a foreign key.
func retireNativeOwnerProbe(t *testing.T, admin *s3.Client, bucket, key string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	page, err := admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &key, MaxKeys: aws.Int32(16)})
	if err != nil || aws.ToBool(page.IsTruncated) {
		t.Error("complete exact owner probe version inventory unavailable", err)
		return
	}
	objects := make([]s3types.ObjectIdentifier, 0, len(page.Versions)+len(page.DeleteMarkers))
	for _, version := range page.Versions {
		objects = append(objects, s3types.ObjectIdentifier{Key: version.Key, VersionId: version.VersionId})
	}
	for _, marker := range page.DeleteMarkers {
		objects = append(objects, s3types.ObjectIdentifier{Key: marker.Key, VersionId: marker.VersionId})
	}
	for _, object := range objects {
		if aws.ToString(object.Key) != key || aws.ToString(object.VersionId) == "" {
			t.Error("refuse foreign or unaddressable owner probe copy")
			return
		}
		if _, err = admin.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: object.Key, VersionId: object.VersionId}); err != nil {
			t.Error("exact owner probe version cleanup failed", err)
			return
		}
	}
	remaining, err := admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &key, MaxKeys: aws.Int32(1)})
	if err != nil || aws.ToBool(remaining.IsTruncated) || len(remaining.Versions) != 0 || len(remaining.DeleteMarkers) != 0 {
		t.Error("owner probe copies remain after exact version cleanup", err)
	}
}
