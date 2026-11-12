package objectstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// SeaweedSetup is finite trusted installer administration of a dedicated
// backend. It is never an ordinary evidence or audit writer.
type SeaweedSetup struct {
	store             *Store
	endpoint, backend string
}

func NewSeaweedSetup(endpoint, region string, admin contracts.SeaweedCredential, h *http.Client) (*SeaweedSetup, error) {
	if providerconfig.ValidateSeaweedCredential(admin) != nil || admin.Principal.Purpose != "admin" {
		return nil, ErrStorage
	}
	store, e := New(endpoint, region, "setup", credentials.NewStaticCredentialsProvider(admin.AccessKeyID, admin.SecretAccessKey, ""), h)
	if e != nil {
		return nil, e
	}
	return &SeaweedSetup{store: store, endpoint: endpoint, backend: admin.Principal.ScopeID}, nil
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
	if s == nil || s.store == nil || c.BackendID != s.backend || c.Endpoint != s.endpoint || !seaweedSetupBucket.MatchString(c.Bucket) || strings.Contains(c.Bucket, "..") {
		return false
	}
	for _, id := range []string{c.BackendID, c.InstallationID, c.InitializationID, c.StateSecretUID, c.PVCUID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return len(c.Image) > len("@sha256:")+64 && strings.HasSuffix(c.Image, "@sha256:"+c.Image[len(c.Image)-64:]) && hexDigest(c.Image[len(c.Image)-64:])
}
func hexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func seaweedOwnership(c contracts.SeaweedBucketInitialization) []types.Tag {
	return []types.Tag{
		{Key: aws.String("asservat:backend"), Value: aws.String(c.BackendID)},
		{Key: aws.String("asservat:installation"), Value: aws.String(c.InstallationID)},
		{Key: aws.String("asservat:initialization"), Value: aws.String(c.InitializationID)},
		{Key: aws.String("asservat:state"), Value: aws.String(c.StateSecretUID)},
		{Key: aws.String("asservat:pvc"), Value: aws.String(c.PVCUID)},
		{Key: aws.String("asservat:image"), Value: aws.String(c.Image)},
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

// ConfigureBucket resolves only the original dedicated backend's pending empty
// bucket, including an unknown first Create reply. The common seed must still
// prohibit ALL runtime grants/activation while Pending. Established tagged
// replay may contain managed ciphertext and does not read its contents.
func (s *SeaweedSetup) ConfigureBucket(ctx context.Context, c contracts.SeaweedBucketInitialization, policy json.RawMessage) error {
	if !s.validClaim(c) || ctx == nil || ctx.Err() != nil || len(policy) == 0 || len(policy) > providerconfig.SeaweedConfigLimit {
		return storageAnswer{"setup-input"}
	}
	if _, e := seaweedPolicyStatements(policy); e != nil {
		return storageAnswer{"setup-policy"}
	}
	client := s.store.client
	tags, e := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &c.Bucket})
	if e != nil && seaweedNamedError(e, "NoSuchBucket") && c.Pending {
		_, createErr := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &c.Bucket})
		// Never retry create or mint another identity after an unknown response.
		tags, e = client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &c.Bucket})
		if e != nil && !seaweedNamedError(e, "NoSuchTagSet") {
			_ = createErr
			return storageAnswer{"setup-create"}
		}
	}
	untagged := seaweedNamedError(e, "NoSuchTagSet") || e == nil && tags != nil && len(tags.TagSet) == 0
	if untagged {
		if !c.Pending {
			return storageAnswer{"setup-unowned"}
		}
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
		if !c.Pending {
			return storageAnswer{"setup-version-changed"}
		}
		if _, e = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &c.Bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); e != nil {
			return storageAnswer{"setup-version-write"}
		}
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
	}
	version, e = client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &c.Bucket})
	if e != nil || version.Status != types.BucketVersioningStatusEnabled {
		return storageAnswer{"setup-version-final"}
	}
	actual, e := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &c.Bucket})
	if e != nil || actual.Policy == nil || !sameSeaweedJSON([]byte(*actual.Policy), policy) || ctx.Err() != nil {
		return storageAnswer{"setup-policy-final"}
	}
	return nil
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

// SeaweedBuckets gives callers deterministic setup order without exposing keys.
func SeaweedBuckets(policies map[string]json.RawMessage) []string {
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
