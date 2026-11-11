package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

func TestInstalledOperationCleanupStorageWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run scripts/test-custody.py --run '^TestInstalledOperationCleanupStorageWithRealServices$'")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("owned fixture unavailable", err)
	}
	var f struct {
		S3        string `json:"s3"`
		Container string `json:"s3Container"`
	}
	if json.Unmarshal(raw, &f) != nil || f.S3 == "" || !strings.HasPrefix(f.Container, "asservat-custody-") || !strings.HasSuffix(f.Container, "-s3") {
		clear(raw)
		t.Fatal("invalid owned cleanup fixture")
	}
	clear(raw)
	ctx, end := context.WithTimeout(t.Context(), 60*time.Second)
	defer end()
	bridge := tlsBridge(t, f.S3)
	const bucket = "synthetic-installed-operation-cleanup"
	const root = "10000000-0000-4000-8000-000000001491"
	p := &initialRuntimeNativeProviders{client: bridge.Client(), desired: contracts.InitialBootstrap{AuditStore: contracts.OwnerAuditStore{Endpoint: bridge.URL, Region: "us-east-1", Bucket: bucket}}}
	admin := installerCleanupClient(p, "synthetic-only", "synthetic-only-secret")
	if _, err = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("owned cleanup bucket", err)
	}
	if _, err = admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal("owned cleanup versioning", err)
	}
	installerOperationCleanupCredentials(t, ctx, p, *providerconfig.OperationCleanupStorageRequirementsFor(p.desired.AuditStore, root), []string{"operation-cleanup", "operation-verify"}, f.Container)
}

// Preserve every existing audit principal and cleanup statement when later
// operator phases add users. Only the specifically selected cleaner can delete;
// verification and ordinary writers retain their original blanket denial.
func installerAuditRuntimeDeletionPolicy(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, bucket string, users []string) {
	t.Helper()
	store := installerCleanupClient(p, "synthetic-only", "synthetic-only-secret")
	var statements []json.RawMessage
	var principals []string
	observed, err := store.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
	if err == nil && observed.Policy != nil {
		var current struct{ Statement []json.RawMessage }
		if json.Unmarshal([]byte(*observed.Policy), &current) != nil {
			t.Fatal("invalid existing audit bucket policy")
		}
		for _, raw := range current.Statement {
			var s struct {
				Sid       string
				Principal struct{ AWS json.RawMessage }
			}
			if json.Unmarshal(raw, &s) != nil {
				t.Fatal("invalid audit bucket statement")
			}
			if s.Sid != "DenyRuntimeDeletion" {
				statements = append(statements, raw)
			} else {
				var old []string
				if json.Unmarshal(s.Principal.AWS, &old) != nil {
					var one string
					if json.Unmarshal(s.Principal.AWS, &one) != nil {
						t.Fatal("invalid existing deletion principals")
					}
					old = []string{one}
				}
				for _, principal := range old {
					if principal != "arn:aws:iam::000000000000:user/operation-cleanup" {
						principals = append(principals, principal)
					}
				}
			}
		}
	} else if err != nil {
		var failure smithy.APIError
		if !errors.As(err, &failure) || failure.ErrorCode() != "NoSuchBucketPolicy" {
			t.Fatal("read audit bucket policy", err)
		}
	}
	for _, u := range users {
		if u != "operation-cleanup" {
			principals = append(principals, "arn:aws:iam::000000000000:user/"+u)
		}
	}
	if len(principals) > 0 {
		b, _ := json.Marshal(map[string]any{"Sid": "DenyRuntimeDeletion", "Effect": "Deny", "Principal": map[string]any{"AWS": principals}, "Action": []string{"s3:DeleteObject", "s3:DeleteObjectVersion"}, "Resource": "arn:aws:s3:::" + bucket + "/*"})
		statements = append(statements, b)
	}
	b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if _, err := store.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: aws.String(string(b))}); err != nil {
		t.Fatal("audit runtime deletion policy", err)
	}
}

func installerOwnedOperatorStorage(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, container, user string, actions, users []string) []byte {
	t.Helper()
	if (!strings.HasPrefix(container, "asservat-context-") && !strings.HasPrefix(container, "asservat-custody-")) || !strings.HasSuffix(container, "-s3") {
		t.Fatal("unsupported owned S3 fixture")
	}
	runID := strings.TrimSuffix(strings.TrimPrefix(container, "asservat-"), "-s3")
	label, err := installedOutput(ctx, installedDockerTimeout, "docker", "inspect", "--format", "{{ index .Config.Labels \"asservat.test\" }}", container)
	if err != nil || strings.TrimSpace(string(label)) != runID || len(actions) == 0 {
		t.Fatal("refuse non-owned S3 administration", err)
	}
	bucket := p.desired.AuditStore.Bucket
	key, secret := user+"-continuation", user+"-continuation-secret"
	shell := "s3.configure -user=administrator -access_key=synthetic-only -secret_key=synthetic-only-secret -actions=Admin,Read,Write,List -apply\n" +
		"s3.configure -user=" + user + " -access_key=" + key + " -secret_key=" + secret + " -actions=" + strings.Join(actions, ",") + " -apply\n"
	command, commandDone := installedBoundedCommand(ctx, installedDockerTimeout, "docker", "exec", "-i", container, "/usr/bin/weed", "shell", "-master=localhost:9333", "-filer=localhost:8888")
	defer commandDone()
	command.Stdin = strings.NewReader(shell)
	if output, e := command.CombinedOutput(); e != nil {
		clear(output)
		t.Fatal("owned exact IAM provisioning command unavailable", e)
	}
	installerAuditRuntimeDeletionPolicy(t, ctx, p, bucket, users)
	out, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: key, SecretAccessKey: secret})
	return out
}

func installerCleanupClient(p *initialRuntimeNativeProviders, key, secret string) *s3.Client {
	return s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: &p.desired.AuditStore.Endpoint, UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: p.client, RetryMaxAttempts: 1})
}

func installerOperationCleanupPolicy(bucket, prefix string) []byte {
	resource := "arn:aws:s3:::" + bucket
	list := []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"}
	principal := func(user string) map[string]any {
		return map[string]any{"AWS": "arn:aws:iam::000000000000:user/" + user}
	}
	var statements []any
	for _, user := range []string{"operation-cleanup", "operation-verify"} {
		statements = append(statements,
			map[string]any{"Sid": "AllowOperationInventory" + user, "Effect": "Allow", "Principal": principal(user), "Action": list, "Resource": resource, "Condition": map[string]any{"StringLike": map[string]any{"s3:prefix": prefix + "*"}}},
			map[string]any{"Sid": "DenyForeignOperationInventory" + user, "Effect": "Deny", "Principal": principal(user), "Action": list, "Resource": resource, "Condition": map[string]any{"StringNotLike": map[string]any{"s3:prefix": prefix + "*"}}},
			map[string]any{"Sid": "DenyOperationAdministration" + user, "Effect": "Deny", "Principal": principal(user), "Action": []string{"s3:PutBucketVersioning", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutLifecycleConfiguration", "s3:PutBucketAcl", "s3:DeleteBucket"}, "Resource": resource})
	}
	statements = append(statements,
		map[string]any{"Sid": "AllowOperationCleanupDeletion", "Effect": "Allow", "Principal": principal("operation-cleanup"), "Action": []string{"s3:DeleteObjectVersion", "s3:AbortMultipartUpload"}, "Resource": resource + "/" + prefix + "*"},
		map[string]any{"Sid": "AllowOperationCertificateWrite", "Effect": "Allow", "Principal": principal("operation-cleanup"), "Action": "s3:PutObject", "Resource": resource + "/" + prefix + "*/deletion-certificate"},
		map[string]any{"Sid": "DenyOperationVerificationWrite", "Effect": "Deny", "Principal": principal("operation-verify"), "Action": []string{"s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload"}, "Resource": resource + "/*"})
	b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
	return b
}

func installerOperationCleanupCredentials(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, requirements providerconfig.OperationCleanupStorageRequirements, users []string, container ...string) map[string][]byte {
	t.Helper()
	bucket := p.desired.AuditStore.Bucket
	if requirements.Store.Bucket != bucket || len(requirements.Prefixes) != 1 || !strings.HasPrefix(requirements.Prefixes[0], "operation-audit/v1/") || requirements.Versioning != "Enabled" {
		t.Fatal("unexpected cleanup storage requirements")
	}
	prefix := requirements.Prefixes[0]
	parts := strings.Split(prefix, "/")
	if len(parts) != 4 || parts[0] != "operation-audit" || parts[1] != "v1" || !authorization.UUID(parts[2]) || parts[3] != "" || !reflect.DeepEqual(requirements, *providerconfig.OperationCleanupStorageRequirementsFor(requirements.Store, parts[2])) {
		t.Fatal("noncanonical cleanup storage requirements")
	}
	out := map[string][]byte{}
	for user, key := range map[string]string{"operation-cleanup": contracts.InstallerInboxCleanupAuditCredential, "operation-verify": contracts.InstallerInboxCleanupVerifyCredential} {
		if len(container) == 0 {
			out[key] = installerOperatorStorage(t, ctx, p, user, []string{"Read:" + bucket + "/" + prefix + "*", "List:" + bucket}, users)
		} else if len(container) == 1 {
			out[key] = installerOwnedOperatorStorage(t, ctx, p, container[0], user, []string{"Read:" + bucket + "/" + prefix + "*", "List:" + bucket}, users)
		} else {
			t.Fatal("multiple S3 fixtures")
		}
	}
	installerMergeBucketPolicy(t, ctx, p, bucket, installerOperationCleanupPolicy(bucket, prefix))
	qualifyInstalledOperationCleanupStorage(t, ctx, installerCleanupClient(p, "synthetic-only", "synthetic-only-secret"), installerCleanupClient(p, "operation-cleanup-continuation", "operation-cleanup-continuation-secret"), installerCleanupClient(p, "operation-verify-continuation", "operation-verify-continuation-secret"), bucket, prefix)
	return out
}

// This is the exact real-S3 probe shared by the bounded fixture and installed
// operator step. It supplies no SQL lifecycle, native proof or runtime grant.
func qualifyInstalledOperationCleanupStorage(t *testing.T, ctx context.Context, admin, cleanup, verify *s3.Client, bucket, prefix string) {
	t.Helper()
	probe := prefix + custodyID() + "/"
	key, foreign := probe+"intent", "unrelated/"+custodyID()
	var versions []s3.DeleteObjectInput
	var uploads []s3.AbortMultipartUploadInput
	defer func() {
		call, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		for _, u := range uploads {
			_, err := admin.AbortMultipartUpload(call, &u)
			var failure smithy.APIError
			if err != nil && (!errors.As(err, &failure) || failure.ErrorCode() != "NoSuchUpload") {
				t.Error("cleanup storage probe multipart cleanup", err)
			}
		}
		for _, v := range versions {
			if _, err := admin.DeleteObject(call, &v); err != nil {
				t.Error("cleanup storage probe version cleanup", err)
			}
		}
	}()
	seed := func(name string) *string {
		r, err := admin.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &name, Body: strings.NewReader("synthetic permission probe; not evidence")})
		if err != nil || aws.ToString(r.VersionId) == "" || aws.ToString(r.VersionId) == "null" {
			t.Fatal("versioned cleanup probe", err)
		}
		versions = append(versions, s3.DeleteObjectInput{Bucket: &bucket, Key: &name, VersionId: r.VersionId})
		return r.VersionId
	}
	version, foreignVersion := seed(key), seed(foreign)
	denied := func(name string, err error) {
		t.Helper()
		var failure smithy.APIError
		if !errors.As(err, &failure) || failure.ErrorCode() != "AccessDenied" {
			t.Fatal("expected actual AccessDenied: "+name, err)
		}
	}
	for _, reader := range []*s3.Client{cleanup, verify} {
		setup, stop := context.WithTimeout(ctx, 10*time.Second)
		for {
			_, readyErr := reader.ListObjectsV2(setup, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &probe, MaxKeys: aws.Int32(1)})
			if readyErr == nil {
				break
			}
			var failure smithy.APIError
			if !errors.As(readyErr, &failure) || (failure.ErrorCode() != "InvalidAccessKeyId" && failure.ErrorCode() != "AccessDenied") {
				stop()
				t.Fatal("cleanup IAM readiness", readyErr)
			}
			select {
			case <-setup.Done():
				stop()
				t.Fatal("cleanup IAM subscription unavailable", setup.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
		stop()
		list, err := reader.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &probe, MaxKeys: aws.Int32(4)})
		if err != nil || aws.ToBool(list.IsTruncated) || len(list.Versions) != 1 {
			t.Fatal("exact cleanup inventory", err)
		}
		obj, err := reader.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: version})
		if err != nil {
			t.Fatal("pinned cleanup read", err)
		}
		_, copyErr := io.Copy(io.Discard, obj.Body)
		closeErr := obj.Body.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal("cleanup body ownership", copyErr, closeErr)
		}
		_, err = reader.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &foreign, MaxKeys: aws.Int32(4)})
		denied("foreign inventory", err)
		foreignObject, readErr := reader.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &foreign, VersionId: foreignVersion})
		if foreignObject != nil && foreignObject.Body != nil {
			_ = foreignObject.Body.Close()
		}
		err = readErr
		denied("foreign object", err)
		_, err = reader.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusSuspended}})
		denied("administration", err)
	}
	_, err := verify.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader([]byte("denied"))})
	denied("verification write", err)
	_, err = verify.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: version})
	denied("verification delete", err)
	_, err = cleanup.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader([]byte("denied"))})
	denied("original audit overwrite", err)
	certificate := probe + "deletion-certificate"
	got, err := cleanup.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &certificate, Body: strings.NewReader("synthetic certificate permission probe"), IfNoneMatch: aws.String("*")})
	if err != nil || aws.ToString(got.VersionId) == "" || aws.ToString(got.VersionId) == "null" {
		t.Fatal("certificate conditional write", err)
	}
	versions = append(versions, s3.DeleteObjectInput{Bucket: &bucket, Key: &certificate, VersionId: got.VersionId})
	duplicate, duplicateErr := cleanup.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &certificate, Body: strings.NewReader("denied duplicate certificate"), IfNoneMatch: aws.String("*")})
	if duplicateErr == nil {
		if duplicate != nil {
			versions = append(versions, s3.DeleteObjectInput{Bucket: &bucket, Key: &certificate, VersionId: duplicate.VersionId})
		}
		t.Fatal("duplicate conditional certificate write accepted")
	}
	var precondition smithy.APIError
	if !errors.As(duplicateErr, &precondition) || precondition.ErrorCode() != "PreconditionFailed" {
		t.Fatal("certificate conditional create refusal", duplicateErr)
	}

	upload, err := admin.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal("synthetic cleanup multipart", err)
	}
	u := s3.AbortMultipartUploadInput{Bucket: &bucket, Key: &key, UploadId: upload.UploadId}
	uploads = append(uploads, u)
	_, err = cleanup.AbortMultipartUpload(ctx, &u)
	if err != nil {
		t.Fatal("exact cleanup abort", err)
	}
	_, err = cleanup.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: version})
	if err != nil {
		t.Fatal("exact cleanup version delete", err)
	}
	_, err = cleanup.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &foreign, VersionId: foreignVersion})
	denied("foreign deletion", err)
}
