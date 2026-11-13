package objectstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// SeaweedSetup is bucket administration of the bundled store by the setup
// Job. It is never an ordinary evidence or audit writer.
type SeaweedSetup struct {
	store    *Store
	endpoint string
}

func NewSeaweedSetup(endpoint, region string, admin contracts.SeaweedCredential, h *http.Client) (*SeaweedSetup, error) {
	if providerconfig.ValidateSeaweedCredential(admin) != nil || admin.Principal.Purpose != "admin" {
		return nil, ErrStorage
	}
	store, e := New(endpoint, region, "setup", credentials.NewStaticCredentialsProvider(admin.AccessKeyID, admin.SecretAccessKey, ""), h)
	if e != nil {
		return nil, e
	}
	return &SeaweedSetup{store: store, endpoint: endpoint}, nil
}
func (s *SeaweedSetup) Close() {
	if s != nil && s.store != nil {
		s.store.Close()
	}
}
func seaweedNamedError(e error, name string) bool {
	var n interface{ ErrorCode() string }
	return errors.As(e, &n) && n.ErrorCode() == name
}

var seaweedSetupBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func (s *SeaweedSetup) validClaim(c contracts.SeaweedBucketInitialization) bool {
	return s != nil && s.store != nil && seaweedSetupBucket.MatchString(c.Bucket) && !strings.Contains(c.Bucket, "..") && authorization.UUID(c.InstallationID)
}

// seaweedOwnership are the deterministic ownership tags of one bucket.
func seaweedOwnership(c contracts.SeaweedBucketInitialization) []types.Tag {
	return []types.Tag{
		{Key: aws.String("asservat:installation"), Value: aws.String(c.InstallationID)},
		{Key: aws.String("asservat:bucket"), Value: aws.String(c.Bucket)},
	}
}
func sameSeaweedTags(a, b []types.Tag) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, t := range a {
		if seen[aws.ToString(t.Key)] {
			return false
		}
		seen[aws.ToString(t.Key)] = true
		found := false
		for _, u := range b {
			if aws.ToString(t.Key) == aws.ToString(u.Key) && aws.ToString(t.Value) == aws.ToString(u.Value) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ConfigureBucket creates the bucket if missing (an unknown create reply is
// resolved by reading the bucket back, never by a second create), tags an
// empty untagged bucket with its ownership, enables versioning and, when
// policy is non-empty, applies the bucket policy. A retained policy may only
// be extended: existing statements keep their SIDs and contents. A bucket
// tagged for another installation, or untagged with content, is refused.
func (s *SeaweedSetup) ConfigureBucket(ctx context.Context, c contracts.SeaweedBucketInitialization, policy json.RawMessage) error {
	if !s.validClaim(c) || ctx == nil || ctx.Err() != nil || len(policy) > providerconfig.SeaweedConfigLimit {
		return storageAnswer{"setup-input"}
	}
	if len(policy) != 0 {
		if _, e := seaweedPolicyStatements(policy); e != nil {
			return storageAnswer{"setup-policy"}
		}
	}
	client := s.store.client
	tags, e := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &c.Bucket})
	if e != nil && seaweedNamedError(e, "NoSuchBucket") {
		_, _ = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &c.Bucket})
		tags, e = client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &c.Bucket})
		if e != nil && !seaweedNamedError(e, "NoSuchTagSet") {
			return storageAnswer{"setup-create"}
		}
	}
	untagged := seaweedNamedError(e, "NoSuchTagSet") || e == nil && tags != nil && len(tags.TagSet) == 0
	if untagged {
		if e = s.empty(ctx, c.Bucket); e != nil {
			return e
		}
		if _, e = client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: &c.Bucket, Tagging: &types.Tagging{TagSet: seaweedOwnership(c)}}); e != nil {
			return storageAnswer{"setup-tag"}
		}
		tags, e = client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &c.Bucket})
	}
	if e != nil || tags == nil || !sameSeaweedTags(tags.TagSet, seaweedOwnership(c)) {
		return storageAnswer{"setup-ownership"}
	}
	version, e := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &c.Bucket})
	if e != nil {
		return storageAnswer{"setup-version-read"}
	}
	if version.Status != types.BucketVersioningStatusEnabled {
		if _, e = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &c.Bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); e != nil {
			return storageAnswer{"setup-version-write"}
		}
		if version, e = client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &c.Bucket}); e != nil || version.Status != types.BucketVersioningStatusEnabled {
			return storageAnswer{"setup-version-final"}
		}
	}
	if len(policy) == 0 {
		return ctx.Err()
	}
	old, e := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &c.Bucket})
	if e != nil && !seaweedNamedError(e, "NoSuchBucketPolicy") {
		return storageAnswer{"setup-policy-read"}
	}
	if e == nil && old.Policy != nil {
		if !seaweedPolicyExtends([]byte(*old.Policy), policy) {
			return storageAnswer{"setup-policy-replacement"}
		}
	}
	if e != nil || old.Policy == nil || !sameSeaweedJSON([]byte(*old.Policy), policy) {
		text := string(policy)
		if _, e = client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &c.Bucket, Policy: &text}); e != nil {
			return storageAnswer{"setup-policy-write"}
		}
		actual, e := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &c.Bucket})
		if e != nil || actual.Policy == nil || !sameSeaweedJSON([]byte(*actual.Policy), policy) {
			return storageAnswer{"setup-policy-final"}
		}
	}
	return ctx.Err()
}
func (s *SeaweedSetup) empty(ctx context.Context, bucket string) error {
	c := s.store.client
	objects, e := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket, MaxKeys: aws.Int32(1)})
	if e != nil || objects.IsTruncated == nil || *objects.IsTruncated || len(objects.Contents) != 0 {
		return storageAnswer{"setup-nonempty-objects"}
	}
	versions, e := c.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, MaxKeys: aws.Int32(1)})
	if e != nil || versions.IsTruncated == nil || *versions.IsTruncated || len(versions.Versions) != 0 || len(versions.DeleteMarkers) != 0 {
		return storageAnswer{"setup-nonempty-versions"}
	}
	uploads, e := c.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket, MaxUploads: aws.Int32(1)})
	if e != nil || uploads.IsTruncated == nil || *uploads.IsTruncated || len(uploads.Uploads) != 0 {
		return storageAnswer{"setup-nonempty-multipart"}
	}
	return nil
}
func sameSeaweedJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ax, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return bytes.Equal(ax, by)
}
func seaweedPolicyStatements(raw []byte) (map[string]json.RawMessage, error) {
	var d struct {
		Version   string            `json:"Version"`
		Statement []json.RawMessage `json:"Statement"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF || d.Version != "2012-10-17" || len(d.Statement) == 0 || len(d.Statement) > 4096*5 {
		return nil, ErrStorage
	}
	out := map[string]json.RawMessage{}
	for _, s := range d.Statement {
		var v struct {
			Sid string `json:"Sid"`
		}
		if json.Unmarshal(s, &v) != nil || !strings.HasPrefix(v.Sid, "Asservat") || len(v.Sid) > 96 || out[v.Sid] != nil {
			return nil, ErrStorage
		}
		out[v.Sid] = s
	}
	return out, nil
}
func seaweedPolicyExtends(old, next []byte) bool {
	a, e := seaweedPolicyStatements(old)
	if e != nil {
		return false
	}
	b, e := seaweedPolicyStatements(next)
	if e != nil {
		return false
	}
	for sid, s := range a {
		if !sameSeaweedJSON(s, b[sid]) {
			return false
		}
	}
	return true
}

// EnsureSetupBuckets idempotently creates and configures the bundled store's
// buckets with the bucket administrator credential, in name order. policies
// optionally maps a bucket to its compiled bucket policy
// (providerconfig.CompiledSeaweedStorage.Policies). rootsPEM are the store's
// TLS roots. Each configured bucket is reported on out.
func EnsureSetupBuckets(ctx context.Context, endpoint, region string, rootsPEM []byte, admin contracts.SeaweedCredential, installationID string, buckets []string, policies map[string]json.RawMessage, out io.Writer) error {
	if ctx == nil || out == nil || len(buckets) == 0 || !authorization.UUID(installationID) {
		return storageAnswer{"setup-input"}
	}
	for bucket := range policies {
		if !slices.Contains(buckets, bucket) {
			return storageAnswer{"setup-input"}
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootsPEM) {
		return storageAnswer{"setup-roots"}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	setup, err := NewSeaweedSetup(endpoint, region, admin, &http.Client{Transport: transport})
	if err != nil {
		return storageAnswer{"setup-input"}
	}
	defer setup.Close()
	ordered := slices.Clone(buckets)
	slices.Sort(ordered)
	for i, bucket := range ordered {
		if i > 0 && ordered[i-1] == bucket {
			return storageAnswer{"setup-input"}
		}
		if err = setup.ConfigureBucket(ctx, contracts.SeaweedBucketInitialization{InstallationID: installationID, Bucket: bucket}, policies[bucket]); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "bucket ready: %s\n", bucket)
	}
	return nil
}
