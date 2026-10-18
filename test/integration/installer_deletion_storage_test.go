package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Keep the regional writer's deletion denial when adding the cleaner. Coarse
// SeaweedFS List also needs an explicit prefix denial; its Write action would
// admit PutObject and is never assigned to this identity. Multipart inventory
// needs its own bucket-policy Allow, as qualified by the audit inventory suite.
func installerEvidenceBucketPolicy(bucket string) string {
	object := "arn:aws:s3:::" + bucket + "/*"
	resource := "arn:aws:s3:::" + bucket
	deletion := map[string]any{"AWS": "arn:aws:iam::000000000000:user/evidence-delete"}
	list := []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"}
	policy, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Sid": "DenyRegionalDeletion", "Effect": "Deny", "Principal": map[string]any{"AWS": []string{"arn:aws:iam::000000000000:user/regional-evidence"}}, "Action": []string{"s3:DeleteObject", "s3:DeleteObjectVersion"}, "Resource": object},
		map[string]any{"Sid": "AllowEvidenceDeletion", "Effect": "Allow", "Principal": deletion, "Action": []string{"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload"}, "Resource": resource + "/v1/*"},
		map[string]any{"Sid": "AllowEvidenceInventory", "Effect": "Allow", "Principal": deletion, "Action": list, "Resource": resource, "Condition": map[string]any{"StringLike": map[string]any{"s3:prefix": "v1/*"}}},
		map[string]any{"Sid": "DenyForeignInventory", "Effect": "Deny", "Principal": deletion, "Action": list, "Resource": resource, "Condition": map[string]any{"StringNotLike": map[string]any{"s3:prefix": "v1/*"}}},
		map[string]any{"Sid": "DenyEvidenceRead", "Effect": "Deny", "Principal": deletion, "Action": []string{"s3:GetObject", "s3:GetObjectVersion"}, "Resource": object},
		// Pinned SeaweedFS 4.48 expands PutObject statements to multipart
		// actions even for Deny, including AbortMultipartUpload. Its own
		// request-method condition distinguishes cleanup DELETE from PUT/POST.
		// This fixture-specific condition grants no coarse Write permission.
		map[string]any{"Sid": "DenyEvidenceWrite", "Effect": "Deny", "Principal": deletion, "Action": []string{"s3:PutObject"}, "Resource": object, "Condition": map[string]any{"StringNotEquals": map[string]any{"s3:RequestMethod": "DELETE"}}},
		map[string]any{"Sid": "DenyEvidenceAdministration", "Effect": "Deny", "Principal": deletion, "Action": []string{"s3:PutBucketVersioning", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutLifecycleConfiguration", "s3:PutBucketAcl", "s3:DeleteBucket"}, "Resource": resource},
	}})
	return string(policy)
}

func installerEvidenceDeleteCredential(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, bucket string, users []string) []byte {
	t.Helper()
	raw := installerOperatorStorage(t, ctx, p, "evidence-delete", []string{"List:" + bucket}, users)
	credential, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(raw))
	if err != nil {
		t.Fatal("deletion credential", err)
	}
	client := func(key, secret string) *s3.Client {
		return s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: &p.desired.AuditStore.Endpoint, UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: p.client, RetryMaxAttempts: 1})
	}
	admin, cleaner := client("synthetic-only", "synthetic-only-secret"), client(credential.AccessKeyID, credential.SecretAccessKey)
	qualifyInstalledEvidenceDeleteCredential(t, ctx, admin, cleaner, bucket)
	return raw
}

// Both the full installer and the small owned-S3 fixture run these exact
// backend operations after independently provisioning the List-only identity.
func qualifyInstalledEvidenceDeleteCredential(t *testing.T, ctx context.Context, admin, cleaner *s3.Client, bucket string) {
	t.Helper()
	var err error
	policy := installerEvidenceBucketPolicy(bucket)
	if _, err = admin.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &policy}); err != nil {
		t.Fatal("evidence deletion policy", err)
	}
	// Versioning is fixture setup before the installed writer starts. It lets
	// the permission probes and the later journey exercise version/marker purge.
	if _, err = admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal("versioned evidence fixture", err)
	}
	prefix := "v1/deletion-permission-probe/" + custodyID() + "/"
	key, foreign := prefix+"object", "outside-v1/deletion-permission-probe/"+custodyID()
	var versions []s3.DeleteObjectInput
	var uploads []s3.AbortMultipartUploadInput
	defer func() {
		cleanup, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		for _, upload := range uploads {
			_, e := admin.AbortMultipartUpload(cleanup, &upload)
			var failure smithy.APIError
			if e != nil && (!errors.As(e, &failure) || failure.ErrorCode() != "NoSuchUpload") {
				t.Error("deletion multipart probe cleanup", e)
			}
		}
		for _, v := range versions {
			if _, e := admin.DeleteObject(cleanup, &v); e != nil {
				t.Error("deletion permission probe cleanup", e)
			}
		}
	}()
	seed := func(k string) *string {
		got, e := admin.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &k, Body: strings.NewReader("synthetic permission probe; not evidence")})
		if e != nil || aws.ToString(got.VersionId) == "" || aws.ToString(got.VersionId) == "null" {
			t.Fatal("versioned deletion permission probe", e)
		}
		versions = append(versions, s3.DeleteObjectInput{Bucket: &bucket, Key: &k, VersionId: got.VersionId})
		return got.VersionId
	}
	version, foreignVersion := seed(key), seed(foreign)
	// Only this bounded read retries provider subscription convergence; no
	// uncertain mutation or product operation is replayed.
	setup, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	for {
		_, err = cleaner.ListObjectsV2(setup, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix, MaxKeys: aws.Int32(1)})
		if err == nil {
			break
		}
		var failure smithy.APIError
		if !errors.As(err, &failure) || failure.ErrorCode() != "InvalidAccessKeyId" && failure.ErrorCode() != "AccessDenied" {
			t.Fatal("deletion inventory credential", err)
		}
		select {
		case <-setup.Done():
			t.Fatal("deletion credential subscription unavailable", setup.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	denied := func(operation string, err error) {
		t.Helper()
		var failure smithy.APIError
		if !errors.As(err, &failure) || failure.ErrorCode() != "AccessDenied" {
			t.Fatal("deletion credential must receive AccessDenied for "+operation, err)
		}
	}
	for _, v := range []*string{nil, version} {
		got, e := cleaner.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: v})
		if got != nil && got.Body != nil {
			_ = got.Body.Close()
		}
		denied("evidence read", e)
	}
	put, err := cleaner.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader("synthetic forbidden write")})
	if put != nil && put.VersionId != nil {
		versions = append(versions, s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: put.VersionId})
	}
	denied("evidence write", err)
	created, err := cleaner.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	if created != nil && aws.ToString(created.UploadId) != "" {
		uploads = append(uploads, s3.AbortMultipartUploadInput{Bucket: &bucket, Key: &key, UploadId: created.UploadId})
	}
	denied("multipart creation", err)
	_, err = cleaner.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}})
	denied("bucket versioning", err)
	_, err = cleaner.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &policy})
	denied("bucket policy", err)
	_, err = cleaner.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &foreign, VersionId: foreignVersion})
	denied("foreign-prefix deletion", err)
	for _, other := range []*string{nil, aws.String("outside-v1/")} {
		_, err = cleaner.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: other, MaxKeys: aws.Int32(1)})
		denied("foreign-prefix object inventory", err)
		_, err = cleaner.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: other, MaxKeys: aws.Int32(1)})
		denied("foreign-prefix version inventory", err)
		_, err = cleaner.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket, Prefix: other, MaxUploads: aws.Int32(1)})
		denied("foreign-prefix multipart inventory", err)
	}
	if _, err = cleaner.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &prefix, MaxKeys: aws.Int32(1)}); err != nil {
		t.Fatal("deletion version inventory", err)
	}
	if _, err = cleaner.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket, Prefix: &prefix, MaxUploads: aws.Int32(1)}); err != nil {
		t.Fatal("deletion multipart inventory", err)
	}
	upload, err := admin.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key})
	if err != nil || upload == nil || aws.ToString(upload.UploadId) == "" {
		t.Fatal("synthetic deletion multipart probe", err)
	}
	uploads = append(uploads, s3.AbortMultipartUploadInput{Bucket: &bucket, Key: &key, UploadId: upload.UploadId})
	part, err := admin.UploadPart(ctx, &s3.UploadPartInput{Bucket: &bucket, Key: &key, UploadId: upload.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("synthetic complete final part")})
	if err != nil || part == nil || aws.ToString(part.ETag) == "" {
		t.Fatal("synthetic deletion multipart part", err)
	}
	_, err = cleaner.UploadPart(ctx, &s3.UploadPartInput{Bucket: &bucket, Key: &key, UploadId: upload.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("synthetic forbidden replacement part")})
	denied("multipart part write", err)
	_, err = cleaner.UploadPartCopy(ctx, &s3.UploadPartCopyInput{Bucket: &bucket, Key: &key, UploadId: upload.UploadId, PartNumber: aws.Int32(1), CopySource: aws.String(bucket + "/" + key)})
	denied("multipart part copy", err)
	completed, err := cleaner.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &bucket, Key: &key, UploadId: upload.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{{PartNumber: aws.Int32(1), ETag: part.ETag}}}})
	if completed != nil && aws.ToString(completed.VersionId) != "" {
		versions = append(versions, s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: completed.VersionId})
	}
	denied("multipart completion", err)
	if _, err = cleaner.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &bucket, Key: &key, UploadId: upload.UploadId}); err != nil {
		t.Fatal("deletion abort permission", err)
	}
	remaining, err := admin.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket, Prefix: &prefix, MaxUploads: aws.Int32(4)})
	if err != nil || remaining == nil || remaining.IsTruncated == nil || *remaining.IsTruncated || len(remaining.Uploads) != 0 || len(remaining.CommonPrefixes) != 0 {
		t.Fatal("cleaner did not remove the administrator's synthetic upload", err)
	}
	marker, err := cleaner.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
	if err != nil || !aws.ToBool(marker.DeleteMarker) || aws.ToString(marker.VersionId) == "" {
		t.Fatal("deletion marker permission", err)
	}
	versions = append(versions, s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: marker.VersionId})
	for _, v := range []*string{version, marker.VersionId} {
		if _, err = cleaner.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: v}); err != nil {
			t.Fatal("deletion version permission", err)
		}
	}
	remainingVersions, err := admin.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &prefix, MaxKeys: aws.Int32(4)})
	if err != nil || remainingVersions == nil || remainingVersions.IsTruncated == nil || *remainingVersions.IsTruncated || len(remainingVersions.Versions) != 0 || len(remainingVersions.DeleteMarkers) != 0 || len(remainingVersions.CommonPrefixes) != 0 {
		t.Fatal("cleaner did not remove the synthetic version and marker", err)
	}
}
