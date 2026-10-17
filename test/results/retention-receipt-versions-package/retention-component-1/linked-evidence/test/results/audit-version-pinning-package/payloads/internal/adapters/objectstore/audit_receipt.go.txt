package objectstore

import (
	"context"
	"crypto/sha256"
	"io"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// An acknowledged PUT or retained receipt already selects a version. Never
// replace that selection with the latest-key pointer, even if the replacement
// decrypts to the same record. This read supplies neither writer completion nor
// reconciliation authority; its consumer still verifies the encrypted record
// and current original operation deadlines.
func (s *Store) readAcknowledgedControlAudit(ctx context.Context, expected Object, maximum int64) (Object, []byte, error) {
	var zero Object
	if s == nil || ctx == nil || ctx.Err() != nil || maximum < 1 || maximum > MaxSmallObject || expected.Bytes < 1 || expected.Bytes > maximum || expected.SHA256 == (artifact.Digest{}) {
		return zero, nil, artifact.ErrInvalid
	}
	if _, err := s.Pin(expected); err != nil {
		return zero, nil, err
	}
	q := &s3.GetObjectInput{Bucket: &s.bucket, Key: &expected.Key, IfMatch: &expected.ETag}
	if expected.VersionID != "" {
		q.VersionId = &expected.VersionID
	}
	v, err := s.client.GetObject(ctx, q)
	if err != nil {
		return zero, nil, ErrStorage
	}
	defer v.Body.Close()
	if aws.ToInt64(v.ContentLength) != expected.Bytes || aws.ToString(v.ETag) != expected.ETag || aws.ToString(v.VersionId) != expected.VersionID {
		return zero, nil, artifact.ErrIntegrity
	}
	body, err := io.ReadAll(io.LimitReader(v.Body, expected.Bytes+1))
	if err != nil || int64(len(body)) != expected.Bytes || artifact.Digest(sha256.Sum256(body)) != expected.SHA256 || ctx.Err() != nil {
		clear(body)
		return zero, nil, artifact.ErrIntegrity
	}
	return expected, body, nil
}
