package objectstore

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type ClosedDownloadStopObjects struct {
	store   *Store
	storeID string
	seal    app.KeySealer
	open    app.KeyOpener
}

func NewClosedDownloadStopObjects(store *Store, storeID string, seal app.KeySealer, open app.KeyOpener) (*ClosedDownloadStopObjects, error) {
	if store == nil || !authorization.UUID(storeID) || seal == nil || open == nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return &ClosedDownloadStopObjects{store, storeID, seal, open}, nil
}

var _ app.ClosedDownloadStopObjects = (*ClosedDownloadStopObjects)(nil)

func (s *ClosedDownloadStopObjects) CreateClosedDownloadStop(ctx context.Context, b value.DownloadStopLifecycleBinding, d artifact.DownloadStopDecision) (value.DownloadStopWriteCompletion, error) {
	if s == nil || !b.Valid() || !d.Valid() || b.DownloadID != d.DownloadID || b.RootID != d.RootID || b.Policy.StoreID != s.storeID || d.StoreID != s.storeID || !d.RetainUntil.Equal(b.HardDeleteBy) || !d.WriteUntil.Before(b.OriginalPurgeAt) || d.RequestedAt.Before(b.ReservedAt) {
		return value.DownloadStopWriteCompletion{}, artifact.ErrDownloadUnavailable
	}
	return s.write(ctx, b, "decision", d.RequestedAt, d.WriteUntil, d, func(c context.Context) ([]byte, error) { return framed.SealDownloadStop(c, s.seal, d) }, func(c context.Context, p []byte) error { return framed.VerifyDownloadStop(c, s.open, d, p) })
}
func (s *ClosedDownloadStopObjects) write(ctx context.Context, b value.DownloadStopLifecycleBinding, phase string, since, until time.Time, record any, seal func(context.Context) ([]byte, error), verify func(context.Context, []byte) error) (value.DownloadStopWriteCompletion, error) {
	var zero value.DownloadStopWriteCompletion
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(until) {
		return zero, artifact.ErrDownloadUnavailable
	}
	live, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	p, e := seal(live)
	if e != nil || len(p) == 0 || int64(len(p)) > artifact.DownloadStopCipherLimit {
		return zero, artifact.ErrDownloadUnavailable
	}
	defer clear(p)
	key := artifact.DownloadStopKey(b.RootID, b.DownloadID)
	if phase == "certificate" {
		key = value.DownloadStopCertificateKey(b.RootID, b.DownloadID)
	}
	put, e := s.store.PutSmall(live, key, p)
	// Existing or unknown is deliberately not positive completion.
	if e != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	stored := time.Now().UTC().Truncate(time.Microsecond)
	object, got, e := s.store.readAcknowledgedControlAudit(live, put, artifact.DownloadStopCipherLimit)
	if e != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	defer clear(got)
	if object != put || verify(live, got) != nil || live.Err() != nil || ctx.Err() != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	closed := time.Now().UTC().Truncate(time.Microsecond)
	cancel() // all owned I/O is synchronous and joined before completion
	c := value.DownloadStopWriteCompletion{Protocol: value.DownloadStopWriterProtocol, RootID: b.RootID, DownloadID: b.DownloadID, StoreID: s.storeID, Phase: phase, BindingDigest: auditapp.OperationLifecycleDigest(b), RecordDigest: auditapp.OperationLifecycleDigest(record), Receipt: value.Receipt{Key: key, Version: object.VersionID, ETag: object.ETag, Bytes: object.Bytes, SHA256: object.SHA256}, StoredAt: stored, ClosedAt: closed}
	if ctx.Err() != nil || !time.Now().Before(until) || !c.Valid(b, phase, since, until) {
		return zero, artifact.ErrDownloadUnavailable
	}
	return c, nil
}

type DownloadStopCleanupObjects struct {
	producer *ClosedDownloadStopObjects
	signer   app.DownloadStopRetirementSigner
	verifier app.DownloadStopRetirementVerifier
}
type DownloadStopCleanupVerifier struct {
	store    *Store
	storeID  string
	open     app.KeyOpener
	verifier app.DownloadStopRetirementVerifier
}

func NewDownloadStopCleanupObjects(store *Store, storeID string, seal app.KeySealer, open app.KeyOpener, signer app.DownloadStopRetirementSigner, verifier app.DownloadStopRetirementVerifier) (*DownloadStopCleanupObjects, error) {
	p, e := NewClosedDownloadStopObjects(store, storeID, seal, open)
	if e != nil || signer == nil || verifier == nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return &DownloadStopCleanupObjects{p, signer, verifier}, nil
}
func NewDownloadStopCleanupVerifier(store *Store, storeID string, open app.KeyOpener, verifier app.DownloadStopRetirementVerifier) (*DownloadStopCleanupVerifier, error) {
	if store == nil || !authorization.UUID(storeID) || open == nil || verifier == nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return &DownloadStopCleanupVerifier{store, storeID, open, verifier}, nil
}

var _ app.DownloadStopCleanupObjects = (*DownloadStopCleanupObjects)(nil)
var _ app.DownloadStopCleanupVerifier = (*DownloadStopCleanupVerifier)(nil)

func (s *DownloadStopCleanupObjects) CreateDownloadStopCertificate(ctx context.Context, b value.DownloadStopLifecycleBinding, r value.DownloadStopRetirement) (value.DownloadStopWriteCompletion, error) {
	if s == nil || !b.Valid() || !r.Valid() || b.RootID != r.RootID || b.DownloadID != r.DownloadID || b.Policy.StoreID != r.StoreID || s.producer.storeID != r.StoreID || r.BindingDigest != auditapp.OperationLifecycleDigest(b) || !r.CertificatePurgeAt.Equal(b.CertificatePurgeAt) || !r.LiveRetireBy.Equal(b.LiveRetireBy) {
		return value.DownloadStopWriteCompletion{}, artifact.ErrDownloadUnavailable
	}
	return s.producer.write(ctx, b, "certificate", r.PurgedAt, r.CertificateWriteUntil, r, func(c context.Context) ([]byte, error) {
		return framed.SealDownloadStopRetirement(c, s.producer.seal, s.signer, r)
	}, func(c context.Context, p []byte) error {
		return framed.VerifyDownloadStopRetirement(c, s.producer.open, s.verifier, r, p)
	})
}
func (s *DownloadStopCleanupVerifier) VerifyDownloadStopCertificate(ctx context.Context, r value.DownloadStopRetirement, receipt value.Receipt) error {
	if s == nil || ctx == nil || !r.Valid() || s.storeID != r.StoreID || !value.ValidDownloadStopReceipt(receipt, r.RootID, r.DownloadID, "certificate") || !time.Now().Before(r.CertificateWriteUntil) {
		return artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, r.CertificateWriteUntil)
	defer cancel()
	o, p, e := s.store.readAcknowledgedControlAudit(ctx, Object{Key: receipt.Key, VersionID: receipt.Version, ETag: receipt.ETag, Bytes: receipt.Bytes, SHA256: receipt.SHA256}, artifact.DownloadStopCipherLimit)
	if e != nil {
		return artifact.ErrDownloadUnavailable
	}
	defer clear(p)
	got := value.Receipt{Key: o.Key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	if got != receipt || framed.VerifyDownloadStopRetirement(ctx, s.open, s.verifier, r, p) != nil || ctx.Err() != nil || !time.Now().Before(r.CertificateWriteUntil) {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func downloadStopInventory(ctx context.Context, store *Store, storeID string, l value.DownloadStopPurgeLease) (inventory, error) {
	if store == nil || ctx == nil || !l.Valid() || l.StoreID != storeID || !time.Now().Before(l.Until) {
		return inventory{}, artifact.ErrDownloadUnavailable
	}
	key := artifact.DownloadStopKey(l.RootID, l.DownloadID)
	in, e := store.inventory(ctx, key)
	if e != nil {
		return in, e
	}
	if in.truncated {
		return in, artifact.ErrLimit
	}
	allowed := func(k string) bool {
		return k == key || l.Phase == "terminal" && k == value.DownloadStopCertificateKey(l.RootID, l.DownloadID)
	}
	for _, v := range in.versions {
		if !allowed(v.key) {
			return inventory{}, artifact.ErrIntegrity
		}
	}
	for _, v := range in.uploads {
		if !allowed(v.key) {
			return inventory{}, artifact.ErrIntegrity
		}
	}
	for _, k := range in.keys {
		if !allowed(k) {
			return inventory{}, artifact.ErrIntegrity
		}
	}
	return in, nil
}
func (s *DownloadStopCleanupObjects) PurgeDownloadStopObjects(ctx context.Context, l value.DownloadStopPurgeLease) error {
	if s == nil || ctx == nil || !l.Valid() {
		return artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, l.Until)
	defer cancel()
	in, e := downloadStopInventory(ctx, s.producer.store, s.producer.storeID, l)
	if e != nil {
		return e
	}
	store := s.producer.store
	for _, u := range in.uploads {
		if _, e = store.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &store.bucket, Key: &u.key, UploadId: &u.id}); e != nil {
			var api interface{ ErrorCode() string }
			if !errors.As(e, &api) || api.ErrorCode() != "NoSuchUpload" {
				return ErrStorage
			}
		}
	}
	covered := map[string]bool{}
	for _, v := range in.versions {
		covered[v.key] = true
		if _, e = store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &store.bucket, Key: &v.key, VersionId: &v.id}); e != nil {
			return ErrStorage
		}
	}
	for _, k := range in.keys {
		if !covered[k] {
			if _, e = store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &store.bucket, Key: &k, VersionId: aws.String("null")}); e != nil {
				return ErrStorage
			}
		}
	}
	return downloadStopAbsence(ctx, store, s.producer.storeID, l)
}
func downloadStopAbsence(ctx context.Context, store *Store, storeID string, l value.DownloadStopPurgeLease) error {
	if ctx == nil {
		return artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, l.Until)
	defer cancel()
	in, e := downloadStopInventory(ctx, store, storeID, l)
	if e != nil {
		return e
	}
	if len(in.versions)+len(in.uploads)+len(in.keys) > 0 || ctx.Err() != nil || !time.Now().Before(l.Until) {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func (s *DownloadStopCleanupVerifier) VerifyDownloadStopAbsence(ctx context.Context, l value.DownloadStopPurgeLease) error {
	if s == nil {
		return artifact.ErrDownloadUnavailable
	}
	return downloadStopAbsence(ctx, s.store, s.storeID, l)
}
