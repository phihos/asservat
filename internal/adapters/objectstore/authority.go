package objectstore

import (
	"context"
	"crypto/sha256"
	"io"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func (s *Store) readControlAudit(ctx context.Context, key string, maximum int64) (Object, []byte, error) {
	var out Object
	if !safeKey.MatchString(key) {
		return out, nil, artifact.ErrInvalid
	}
	// One bounded GET returns a consistent immutable version, including the body.
	v, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return out, nil, storageRefusal(err)
	}
	defer v.Body.Close()
	size := aws.ToInt64(v.ContentLength)
	if size < 1 || size > maximum || aws.ToString(v.ETag) == "" || !s.acceptsVersion(aws.ToString(v.VersionId)) {
		return out, nil, artifact.ErrIntegrity
	}
	body, err := io.ReadAll(io.LimitReader(v.Body, size+1))
	if err != nil || int64(len(body)) != size {
		return out, nil, artifact.ErrIntegrity
	}
	return Object{Key: key, VersionID: aws.ToString(v.VersionId), ETag: aws.ToString(v.ETag), Bytes: size, SHA256: artifact.Digest(sha256.Sum256(body))}, body, nil
}
