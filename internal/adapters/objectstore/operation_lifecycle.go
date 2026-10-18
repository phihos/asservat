package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"time"
)

// This producer owns each finite synchronous one-use handle. A returned SDK
// operation has completed and its response body is closed before the handle can
// close. No goroutine, retry, detached request or Find path can issue completion.
// The SQL claim must already have been irreversibly spent by the caller.
type ClosedOperationAuditObjects struct {
	store   *Store
	storeID string
	seal    evidence.KeySealer
	open    evidence.KeyOpener
}

func NewClosedOperationAuditObjects(store *Store, storeID string, seal evidence.KeySealer, open evidence.KeyOpener) (*ClosedOperationAuditObjects, error) {
	if store == nil || !authorization.UUID(storeID) || seal == nil || open == nil {
		return nil, app.ErrUnavailable
	}
	return &ClosedOperationAuditObjects{store, storeID, seal, open}, nil
}

var _ app.ClosedOperationObjects = (*ClosedOperationAuditObjects)(nil)

type OperationAuditCleanupObjects struct {
	store    *Store
	storeID  string
	seal     evidence.KeySealer
	open     evidence.KeyOpener
	signer   app.OperationRetirementSigner
	verifier app.OperationRetirementVerifier
}
type OperationAuditCleanupVerifier struct {
	store    *Store
	storeID  string
	open     evidence.KeyOpener
	verifier app.OperationRetirementVerifier
}

var _ app.OperationCleanupObjects = (*OperationAuditCleanupObjects)(nil)
var _ app.OperationCleanupVerifier = (*OperationAuditCleanupVerifier)(nil)

func NewOperationAuditCleanupObjects(store *Store, storeID string, seal evidence.KeySealer, open evidence.KeyOpener, signer app.OperationRetirementSigner, verifier app.OperationRetirementVerifier) (*OperationAuditCleanupObjects, error) {
	p, e := NewClosedOperationAuditObjects(store, storeID, seal, open)
	if e != nil || signer == nil || verifier == nil {
		return nil, app.ErrUnavailable
	}
	return &OperationAuditCleanupObjects{p.store, p.storeID, p.seal, p.open, signer, verifier}, nil
}
func NewOperationAuditCleanupVerifier(store *Store, storeID string, open evidence.KeyOpener, verifier app.OperationRetirementVerifier) (*OperationAuditCleanupVerifier, error) {
	if store == nil || !authorization.UUID(storeID) || open == nil || verifier == nil {
		return nil, app.ErrUnavailable
	}
	return &OperationAuditCleanupVerifier{store, storeID, open, verifier}, nil
}

func (s *ClosedOperationAuditObjects) CreateClosedOperationIntent(ctx context.Context, r value.OperationIntent) (value.OperationWriteCompletion, error) {
	if s == nil || !r.Valid() || r.Lifecycle == nil || r.Lifecycle.Policy.StoreID != s.storeID {
		return value.OperationWriteCompletion{}, app.ErrUnavailable
	}
	return s.write(ctx, r.RootID, r.ID, "intent", r.CreatedAt, r.WriteUntil, r, func(c context.Context) ([]byte, error) { return framed.SealOperationIntent(c, s.seal, r) }, func(c context.Context, b []byte) error { return framed.VerifyOperationIntent(c, s.open, r, b) })
}
func (s *ClosedOperationAuditObjects) CreateClosedOperationOutcome(ctx context.Context, r value.OperationOutcome) (value.OperationWriteCompletion, error) {
	if s == nil || !r.Valid() || r.Intent.Lifecycle == nil || r.Intent.Lifecycle.Policy.StoreID != s.storeID {
		return value.OperationWriteCompletion{}, app.ErrUnavailable
	}
	return s.write(ctx, r.Intent.RootID, r.Intent.ID, "outcome", r.Intent.CreatedAt, r.Intent.WriteUntil, r, func(c context.Context) ([]byte, error) { return framed.SealOperationOutcome(c, s.seal, r) }, func(c context.Context, b []byte) error { return framed.VerifyOperationOutcome(c, s.open, r, b) })
}
func (s *OperationAuditCleanupObjects) CreateOperationCertificate(ctx context.Context, r value.OperationRetirement) (value.OperationWriteCompletion, error) {
	if s == nil || !r.Valid() || r.StoreID != s.storeID {
		return value.OperationWriteCompletion{}, app.ErrUnavailable
	}
	p := ClosedOperationAuditObjects{s.store, s.storeID, s.seal, s.open}
	return p.write(ctx, r.RootID, r.OperationID, "deletion-certificate", r.PurgedAt, r.CertificateWriteUntil, r, func(c context.Context) ([]byte, error) { return framed.SealOperationRetirement(c, s.seal, s.signer, r) }, func(c context.Context, b []byte) error {
		return framed.VerifyOperationRetirement(c, s.open, s.verifier, r, b)
	})
}

// The single invocation is the handle: only successful PUT -> exact independent
// GET -> synchronous close yields a completion. 412 and all unknown replies deny,
// even when subsequent GET would find a perfectly valid existing object.
func (s *ClosedOperationAuditObjects) write(ctx context.Context, root, id, phase string, since, until time.Time, record any, seal func(context.Context) ([]byte, error), verify func(context.Context, []byte) error) (value.OperationWriteCompletion, error) {
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(until) {
		return value.OperationWriteCompletion{}, objectStep("expired")
	}
	live, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	b, e := seal(live)
	if e != nil || len(b) == 0 || len(b) > value.OperationCipherLimit {
		return value.OperationWriteCompletion{}, objectStep("seal")
	}
	defer clear(b)
	key := value.OperationAuditKey(root, id, phase)
	put, e := s.store.PutSmall(live, key, b)
	if e != nil {
		return value.OperationWriteCompletion{}, objectStepWith("put", e)
	}
	stored := time.Now().UTC().Truncate(time.Microsecond)
	obj, got, e := s.store.readAcknowledgedControlAudit(live, put, value.OperationCipherLimit)
	if e != nil {
		return value.OperationWriteCompletion{}, objectStepWith("read", e)
	}
	defer clear(got)
	if put != obj || verify(live, got) != nil || live.Err() != nil || ctx.Err() != nil {
		return value.OperationWriteCompletion{}, objectStep("verify")
	}
	// All owned synchronous I/O is joined before cancel closes the one-use handle.
	closed := time.Now().UTC().Truncate(time.Microsecond)
	cancel()
	c := value.OperationWriteCompletion{Protocol: value.OperationWriterProtocol, RootID: root, OperationID: id, StoreID: s.storeID, Phase: phase, RecordDigest: app.OperationLifecycleDigest(record), Receipt: value.Receipt{Key: key, Version: obj.VersionID, ETag: obj.ETag, Bytes: obj.Bytes, SHA256: obj.SHA256}, StoredAt: stored, ClosedAt: closed}
	if ctx.Err() != nil || !time.Now().Before(until) || !c.Valid(root, id, s.storeID, phase, since, until) {
		return value.OperationWriteCompletion{}, objectStep("completion")
	}
	return c, nil
}
func (s *OperationAuditCleanupVerifier) VerifyOperationCertificate(ctx context.Context, r value.OperationRetirement, receipt value.Receipt) error {
	if s == nil || ctx == nil || !r.Valid() || r.StoreID != s.storeID || !receipt.ValidOperationRetirement(r.RootID, r.OperationID) {
		return app.ErrUnavailable
	}
	if !time.Now().Before(r.CertificateWriteUntil) {
		return app.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, r.CertificateWriteUntil)
	defer cancel()
	obj, b, e := s.store.readAcknowledgedControlAudit(ctx, Object{Key: receipt.Key, VersionID: receipt.Version, ETag: receipt.ETag, Bytes: receipt.Bytes, SHA256: receipt.SHA256}, value.OperationCipherLimit)
	if e != nil {
		return app.ErrUnavailable
	}
	defer clear(b)
	got := value.Receipt{Key: obj.Key, Version: obj.VersionID, ETag: obj.ETag, Bytes: obj.Bytes, SHA256: obj.SHA256}
	if got != receipt || framed.VerifyOperationRetirement(ctx, s.open, s.verifier, r, b) != nil || ctx.Err() != nil {
		return app.ErrUnavailable
	}
	return nil
}
func operationInventory(ctx context.Context, store *Store, storeID string, l value.OperationPurgeLease) (inventory, error) {
	if store == nil || ctx == nil || !l.Valid() || l.StoreID != storeID || !time.Now().Before(l.Until) {
		return inventory{}, app.ErrUnavailable
	}
	in, e := store.inventory(ctx, value.OperationAuditKey(l.RootID, l.OperationID, ""))
	if e != nil {
		return in, e
	}
	if in.truncated {
		return in, artifact.ErrLimit
	}
	allowed := map[string]bool{value.OperationAuditKey(l.RootID, l.OperationID, "intent"): true, value.OperationAuditKey(l.RootID, l.OperationID, "outcome"): true}
	if l.Phase == "terminal" {
		allowed[value.OperationAuditKey(l.RootID, l.OperationID, "deletion-certificate")] = true
	}
	for _, v := range in.versions {
		if !allowed[v.key] {
			return inventory{}, artifact.ErrIntegrity
		}
	}
	for _, v := range in.uploads {
		if !allowed[v.key] {
			return inventory{}, artifact.ErrIntegrity
		}
	}
	for _, k := range in.keys {
		if !allowed[k] {
			return inventory{}, artifact.ErrIntegrity
		}
	}
	return in, nil
}
func (s *OperationAuditCleanupObjects) PurgeOperationObjects(ctx context.Context, l value.OperationPurgeLease) error {
	if s == nil {
		return app.ErrUnavailable
	}
	return purgeOperationObjects(ctx, s.store, s.storeID, l)
}
func purgeOperationObjects(ctx context.Context, store *Store, storeID string, l value.OperationPurgeLease) error {
	if store == nil || !l.Valid() || ctx == nil {
		return app.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, l.Until)
	defer cancel()
	in, e := operationInventory(ctx, store, storeID, l)
	if e != nil {
		return e
	}
	for _, u := range in.uploads {
		_, e = store.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &store.bucket, Key: &u.key, UploadId: &u.id})
		if e != nil {
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
	for _, key := range in.keys {
		if !covered[key] {
			if _, e = store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &store.bucket, Key: &key, VersionId: aws.String("null")}); e != nil {
				return ErrStorage
			}
		}
	}
	return operationAbsence(ctx, store, storeID, l)
}
func (s *OperationAuditCleanupVerifier) VerifyOperationAbsence(ctx context.Context, l value.OperationPurgeLease) error {
	if s == nil {
		return app.ErrUnavailable
	}
	return operationAbsence(ctx, s.store, s.storeID, l)
}
func operationAbsence(ctx context.Context, store *Store, storeID string, l value.OperationPurgeLease) error {
	if ctx == nil || !l.Valid() {
		return app.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, l.Until)
	defer cancel()
	in, e := operationInventory(ctx, store, storeID, l)
	if e != nil {
		return e
	}
	if len(in.versions)+len(in.keys)+len(in.uploads) > 0 || ctx.Err() != nil || !time.Now().Before(l.Until) {
		return app.ErrUnavailable
	}
	return nil
}
