package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// ADR-166 multipart writes. Every call is a single SDK attempt; the caller
// spends its one-use journal claim first and never repeats an uncertain
// create or complete. Parts are sequential and bounded by the journal.

func (s *Store) CreateUpload(ctx context.Context, key string) (string, error) {
	if !safeKey.MatchString(key) {
		return "", artifact.ErrInvalid
	}
	o, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &s.bucket, Key: &key, ContentType: aws.String("application/octet-stream"), ChecksumAlgorithm: types.ChecksumAlgorithmSha256})
	if err != nil || o.UploadId == nil || *o.UploadId == "" || len(*o.UploadId) > 1024 {
		return "", ErrStorage // outcome may be uncertain: keep the charge
	}
	return *o.UploadId, nil
}

func (s *Store) UploadPart(ctx context.Context, key, upload string, part artifact.StreamingPart, ciphertext []byte) (string, error) {
	if !safeKey.MatchString(key) || upload == "" || part.Number < 1 || part.Number > artifact.StreamingMaxParts || int64(len(ciphertext)) != part.Bytes || part.Bytes > artifact.StreamingPartBytes || artifact.Digest(sha256.Sum256(ciphertext)) != part.SHA256 {
		return "", artifact.ErrInvalid
	}
	o, err := s.client.UploadPart(ctx, &s3.UploadPartInput{Bucket: &s.bucket, Key: &key, UploadId: &upload, PartNumber: aws.Int32(int32(part.Number)), Body: bytes.NewReader(ciphertext), ContentLength: aws.Int64(part.Bytes), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(part.SHA256[:]))})
	if err != nil || o.ETag == nil || *o.ETag == "" || len(*o.ETag) > 1024 {
		return "", ErrStorage
	}
	return *o.ETag, nil
}

// CompleteUpload completes exactly the retained parts with create-only
// semantics. The receipt pins version/ETag; the full-object ciphertext hash is
// established only by VerifyStreaming, never by the multipart ETag.
func (s *Store) CompleteUpload(ctx context.Context, key, upload string, parts []artifact.StreamingPart, size int64, sum artifact.Digest) (Object, error) {
	if !safeKey.MatchString(key) || upload == "" || len(parts) < 1 || len(parts) > artifact.StreamingMaxParts || size < 1 {
		return Object{}, artifact.ErrInvalid
	}
	completed := make([]types.CompletedPart, len(parts))
	var total int64
	for i, p := range parts {
		if p.Number != i+1 || p.ETag == "" {
			return Object{}, artifact.ErrInvalid
		}
		total += p.Bytes
		completed[i] = types.CompletedPart{PartNumber: aws.Int32(int32(p.Number)), ETag: aws.String(p.ETag), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(p.SHA256[:]))}
	}
	if total != size {
		return Object{}, artifact.ErrInvalid
	}
	o, err := s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &s.bucket, Key: &key, UploadId: &upload, MultipartUpload: &types.CompletedMultipartUpload{Parts: completed}, IfNoneMatch: aws.String("*")})
	if err != nil {
		var response interface{ HTTPStatusCode() int }
		if errors.As(err, &response) && response.HTTPStatusCode() == http.StatusPreconditionFailed {
			return Object{}, ErrExists
		}
		return Object{}, ErrStorage // HTTP 200 with an embedded error is an SDK error too
	}
	if o.ETag == nil || *o.ETag == "" || !s.acceptsVersion(aws.ToString(o.VersionId)) {
		return Object{}, ErrStorage
	}
	return Object{key, aws.ToString(o.VersionId), *o.ETag, size, sum}, nil
}

func (s *Store) AbortUpload(ctx context.Context, key, upload string) error {
	if !safeKey.MatchString(key) || upload == "" {
		return artifact.ErrInvalid
	}
	if _, err := s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &s.bucket, Key: &key, UploadId: &upload}); err != nil {
		if noSuchUpload(err) {
			return nil
		}
		return ErrStorage
	}
	return nil
}

// The SDK models NoSuchUpload as a typed error only for some operations
// (not ListParts); the S3 error code is the stable signal.
func noSuchUpload(err error) bool {
	var api smithy.APIError
	return errors.As(err, &api) && api.ErrorCode() == "NoSuchUpload"
}

// UploadAbsent positively establishes that no open upload for key remains:
// the exact upload's parts are gone and no upload for the key is listed.
// In-flight parts can still land after an abort, so callers abort first and
// accept absence only from this later inventory.
func (s *Store) UploadAbsent(ctx context.Context, key, upload string) (bool, error) {
	if !safeKey.MatchString(key) || upload == "" {
		return false, artifact.ErrInvalid
	}
	_, err := s.client.ListParts(ctx, &s3.ListPartsInput{Bucket: &s.bucket, Key: &key, UploadId: &upload, MaxParts: aws.Int32(1)})
	if err == nil || !noSuchUpload(err) {
		if err != nil {
			return false, ErrStorage
		}
		return false, nil
	}
	o, err := s.client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &s.bucket, Prefix: &key, MaxUploads: aws.Int32(1000)})
	if err != nil || aws.ToBool(o.IsTruncated) {
		return false, ErrStorage
	}
	for _, u := range o.Uploads {
		if aws.ToString(u.Key) == key {
			return false, nil
		}
	}
	return true, nil
}

// VerifyStreaming rereads the complete ciphertext in bounded ranges and checks
// its SHA-256 and length against the journal's expectation, up to limit.
func (s *Store) VerifyStreaming(ctx context.Context, o Object, limit int64) error {
	if o.Bytes < 1 || o.Bytes > limit || limit > artifact.StreamingNativeLimit+int64(artifact.MaxFrames)*artifact.CipherOverhead {
		return artifact.ErrLimit
	}
	p, err := s.Pin(o)
	if err != nil {
		return err
	}
	h := sha256.New()
	for off := int64(0); off < o.Bytes; {
		n := min(artifact.FrameBytes, o.Bytes-off)
		b, err := p.ReadRange(ctx, off, n)
		if err != nil {
			return err
		}
		h.Write(b)
		clear(b)
		off += n
	}
	if !bytes.Equal(h.Sum(nil), o.SHA256[:]) {
		return artifact.ErrIntegrity
	}
	return nil
}

// StreamingObjects is the location-keyed facet for the application writer.
// The data role keeps the small path's key, so readers and purge are shared.
type StreamingObjects struct{ Store *Store }

func streamingKey(loc artifact.Location) string { return loc.Prefix() + artifact.Role(0) }

func (s StreamingObjects) CreateUpload(ctx context.Context, loc artifact.Location) (string, error) {
	return s.Store.CreateUpload(ctx, streamingKey(loc))
}
func (s StreamingObjects) UploadPart(ctx context.Context, loc artifact.Location, upload string, part artifact.StreamingPart, ciphertext []byte) (string, error) {
	return s.Store.UploadPart(ctx, streamingKey(loc), upload, part, ciphertext)
}
func (s StreamingObjects) CompleteUpload(ctx context.Context, loc artifact.Location, upload string, parts []artifact.StreamingPart, size int64, sum artifact.Digest) (artifact.CopyReceipt, error) {
	o, err := s.Store.CompleteUpload(ctx, streamingKey(loc), upload, parts, size, sum)
	return artifact.CopyReceipt{VersionID: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}, err
}
func (s StreamingObjects) AbortUpload(ctx context.Context, loc artifact.Location, upload string) error {
	return s.Store.AbortUpload(ctx, streamingKey(loc), upload)
}
func (s StreamingObjects) UploadAbsent(ctx context.Context, loc artifact.Location, upload string) (bool, error) {
	return s.Store.UploadAbsent(ctx, streamingKey(loc), upload)
}
func (s StreamingObjects) VerifyStreaming(ctx context.Context, loc artifact.Location, r artifact.CopyReceipt, limit int64) error {
	return s.Store.VerifyStreaming(ctx, object(loc, 0, r), limit)
}
