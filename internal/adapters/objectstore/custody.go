package objectstore

import (
	"context"
	"errors"
	"strings"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// CustodyStore pins the configured store identity as well as its credentials.
// A worker must never certify absence on a different backend and release charge.
type CustodyStore struct {
	store   *Store
	storeID string
}

var _ evidence.CopyVerifier = (*CustodyStore)(nil)
var _ privacy.AttemptPurger = (*CustodyStore)(nil)

func (s *Store) ForCustody(storeID string) (*CustodyStore, error) {
	if (artifact.Location{ClusterID: storeID, ArtifactID: storeID, AttemptID: storeID}).Validate() != nil {
		return nil, artifact.ErrInvalid
	}
	return &CustodyStore{s, storeID}, nil
}

func (s *CustodyStore) PurgeAttempt(ctx context.Context, r artifact.Registration) error {
	if r.Validate() != nil || r.StoreID != s.storeID {
		return artifact.ErrInvalid
	}
	return s.store.PurgeAttempt(ctx, r.Location)
}

func (s *CustodyStore) VerifyCopies(ctx context.Context, r artifact.Registration, c artifact.Copies) error {
	if r.Validate() != nil || c.Validate(r) != nil || r.StoreID != s.storeID {
		return artifact.ErrInvalid
	}
	for i, v := range c {
		if err := s.store.Verify(ctx, Object{Key: r.Location.Prefix() + artifact.Role(i), VersionID: v.VersionID, ETag: v.ETag, Bytes: v.Bytes, SHA256: v.SHA256}); err != nil {
			return err
		}
	}
	return nil
}

const inventoryBatch = 128

type version struct{ key, id string }
type upload struct{ key, id string }
type inventory struct {
	versions  []version
	uploads   []upload
	keys      []string
	truncated bool
}

// inventory is deliberately one bounded page per API. A truncated batch may be
// deleted, but cannot certify absence. Unknown/malformed backend data fails closed.
func (s *Store) inventory(ctx context.Context, prefix string) (inventory, error) {
	var result inventory
	v, err := s.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &s.bucket, Prefix: &prefix, MaxKeys: aws.Int32(inventoryBatch)})
	if err != nil {
		return result, ErrStorage
	}
	if v == nil || v.IsTruncated == nil {
		return result, artifact.ErrIntegrity
	}
	if len(v.Versions)+len(v.DeleteMarkers) > inventoryBatch {
		return result, artifact.ErrLimit
	}
	add := func(key, ver string) error {
		if !strings.HasPrefix(key, prefix) || len(key) > 512 || len(ver) < 1 || len(ver) > 1024 {
			return artifact.ErrIntegrity
		}
		result.versions = append(result.versions, version{key, ver})
		return nil
	}
	for _, x := range v.Versions {
		if err = add(aws.ToString(x.Key), aws.ToString(x.VersionId)); err != nil {
			return result, err
		}
	}
	for _, x := range v.DeleteMarkers {
		if err = add(aws.ToString(x.Key), aws.ToString(x.VersionId)); err != nil {
			return result, err
		}
	}
	result.truncated = *v.IsTruncated
	u, err := s.client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &s.bucket, Prefix: &prefix, MaxUploads: aws.Int32(inventoryBatch)})
	if err != nil {
		return result, ErrStorage
	}
	if u == nil || u.IsTruncated == nil {
		return result, artifact.ErrIntegrity
	}
	if len(u.Uploads) > inventoryBatch {
		return result, artifact.ErrLimit
	}
	for _, x := range u.Uploads {
		key, ref := aws.ToString(x.Key), aws.ToString(x.UploadId)
		if !strings.HasPrefix(key, prefix) || len(key) > 512 || len(ref) < 1 || len(ref) > 1024 {
			return result, artifact.ErrIntegrity
		}
		result.uploads = append(result.uploads, upload{key, ref})
	}
	result.truncated = result.truncated || *u.IsTruncated
	o, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix, MaxKeys: aws.Int32(inventoryBatch)})
	if err != nil {
		return result, ErrStorage
	}
	if o == nil || o.IsTruncated == nil {
		return result, artifact.ErrIntegrity
	}
	if len(o.Contents) > inventoryBatch {
		return result, artifact.ErrLimit
	}
	for _, x := range o.Contents {
		key := aws.ToString(x.Key)
		if !strings.HasPrefix(key, prefix) || len(key) > 512 {
			return result, artifact.ErrIntegrity
		}
		result.keys = append(result.keys, key)
	}
	result.truncated = result.truncated || *o.IsTruncated
	return result, nil
}

// PurgeAttempt requires the caller's completed writer barrier and a qualified
// complete inventory backend. It removes versions, delete markers and incomplete
// uploads, then independently inventories again. A delete marker is not erasure.
// More than one page returns ErrLimit after progress; the same obligation retries.
func (s *Store) PurgeAttempt(ctx context.Context, l artifact.Location) error {
	if l.Validate() != nil {
		return artifact.ErrInvalid
	}
	in, err := s.inventory(ctx, l.Prefix())
	if err != nil {
		return err
	}
	for _, u := range in.uploads {
		_, err = s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &s.bucket, Key: &u.key, UploadId: &u.id})
		if err != nil {
			var api interface{ ErrorCode() string }
			if !errors.As(err, &api) || api.ErrorCode() != "NoSuchUpload" {
				return ErrStorage
			}
		}
	}
	// Delete exact version IDs, including null versions and markers. Never
	// unversioned DELETE on versioned keys: that would create another marker.
	covered := map[string]bool{}
	for _, v := range in.versions {
		covered[v.key] = true
		_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &v.key, VersionId: &v.id})
		if err != nil {
			return ErrStorage
		}
	}
	for _, key := range in.keys {
		if covered[key] {
			continue
		}
		// Backends without version records still need physical null-version
		// removal; never create a delete marker by omitting VersionId.
		_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key, VersionId: aws.String("null")})
		if err != nil {
			return ErrStorage
		}
	}
	after, err := s.inventory(ctx, l.Prefix())
	if err != nil {
		return err
	}
	if after.truncated || len(after.versions)+len(after.uploads)+len(after.keys) > 0 {
		return artifact.ErrLimit
	}
	return nil
}
