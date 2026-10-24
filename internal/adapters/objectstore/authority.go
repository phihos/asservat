package objectstore

import (
	"context"
	"crypto/sha256"
	"io"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// AuthorityObjects is a dedicated encrypted control-audit namespace. Bootstrap
// must supply audit-only object/KMS credentials, never artifact unwrap rights.
// Storage policy must preserve acknowledged versions and deny their deletion
// to this writer.
type AuthorityObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ auditapp.AuthorityWriter = (*AuthorityObjects)(nil)

func (a *AuthorityObjects) WriteAuthorityAudit(ctx context.Context, r audit.AuthorityRecord) (audit.Receipt, error) {
	var out audit.Receipt
	if a.Store == nil || a.Seal == nil || a.Open == nil || !r.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key := audit.AuthorityKey(r.RootID, r.ID)
	cipher, err := framed.SealAuthority(ctx, a.Seal, r)
	if err != nil {
		return out, err
	}
	object, body, err := a.Store.putControlAudit(ctx, key, cipher, MaxSmallObject)
	if err != nil {
		return out, err
	}
	if err = framed.VerifyAuthority(ctx, a.Open, r, body); err != nil {
		return out, err
	}
	out = audit.Receipt{Key: key, Version: object.VersionID, ETag: object.ETag, Bytes: object.Bytes, SHA256: object.SHA256}
	if !out.Valid(r.RootID, r.ID) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
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
