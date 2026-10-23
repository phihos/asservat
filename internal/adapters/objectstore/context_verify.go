package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
)

type ContextVerifier struct {
	store     *CustodyStore
	keys      evidence.KeyOpener
	contracts *manifest.Validator
}

var _ evidence.ContextVerifier = (*ContextVerifier)(nil)

func NewContextVerifier(store *CustodyStore, keys evidence.KeyOpener) (*ContextVerifier, error) {
	if store == nil || keys == nil {
		return nil, artifact.ErrInvalid
	}
	v, err := manifest.New()
	if err != nil {
		return nil, err
	}
	return &ContextVerifier{store, keys, v}, nil
}

func object(loc artifact.Location, role int, c artifact.CopyReceipt) Object {
	return Object{Key: loc.Prefix() + artifact.Role(role), VersionID: c.VersionID, ETag: c.ETag, Bytes: c.Bytes, SHA256: c.SHA256}
}

func (s *Store) readSmall(ctx context.Context, o Object, limit int64) ([]byte, error) {
	if o.Bytes < 1 || o.Bytes > limit {
		return nil, artifact.ErrLimit
	}
	p, err := s.Pin(o)
	if err != nil {
		return nil, err
	}
	b, err := p.ReadRange(ctx, 0, o.Bytes)
	if err != nil {
		return nil, err
	}
	if artifact.Digest(sha256.Sum256(b)) != o.SHA256 {
		clear(b)
		return nil, artifact.ErrIntegrity
	}
	return b, nil
}

// VerifyContext runs with regional verifier credentials. No bytes or keys are
// returned, and no result is published. Bootstrap must gate this role by current
// execution/audit authority; the hub never receives an unwrap capability.
func (v *ContextVerifier) VerifyContext(ctx context.Context, e artifact.ContextExpectation, c artifact.Copies) error {
	native, err := v.readContext(ctx, e, c, e.Registration.WriteUntil)
	clear(native)
	return err
}

func (v *ContextVerifier) readContext(ctx context.Context, e artifact.ContextExpectation, c artifact.Copies, cutoff time.Time) ([]byte, error) {
	if e.Validate() != nil || c.Validate(e.Registration) != nil || e.Registration.StoreID != v.store.storeID {
		return nil, readStage(ctx, "expectation", artifact.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return nil, readStage(ctx, "cancelled", err)
	}
	r := e.Registration
	ctx, cancel := context.WithDeadline(ctx, minDeadline(cutoff, time.Now().Add(30*time.Second)))
	defer cancel()
	if !time.Now().Before(cutoff) {
		return nil, readStage(ctx, "cutoff", artifact.ErrInvalid)
	}
	commit, err := v.store.store.readSmall(ctx, object(r.Location, 3, c[3]), 32<<10)
	if err != nil {
		return nil, readStage(ctx, "commit-get", err)
	}
	defer clear(commit)
	key, err := v.contracts.ParseCommit(commit, r.Location, c[2])
	if err != nil {
		return nil, readStage(ctx, "commit-parse", err)
	}
	cipher, err := v.store.store.readSmall(ctx, object(r.Location, 2, c[2]), artifact.MaxRootBytes+artifact.CipherOverhead)
	if err != nil {
		return nil, readStage(ctx, "manifest-get", err)
	}
	defer clear(cipher)
	plain, err := framed.OpenManifest(ctx, e.Binding(), v.keys, key, cipher, c[2].SHA256)
	if err != nil {
		return nil, readStage(ctx, "manifest-open", err)
	}
	defer clear(plain)
	m, err := v.contracts.ParseContext(plain, e, c)
	if err != nil {
		return nil, readStage(ctx, "manifest-parse", err)
	}
	if m.CompletedAt.After(time.Now()) {
		return nil, readStage(ctx, "manifest-time", artifact.ErrIntegrity)
	}
	data, err := v.store.store.Pin(object(r.Location, 0, c[0]))
	if err != nil {
		return nil, readStage(ctx, "data-pin", err)
	}
	index, err := v.store.store.Pin(object(r.Location, 1, c[1]))
	if err != nil {
		return nil, readStage(ctx, "index-pin", err)
	}
	reader, err := framed.Open(ctx, m.Layout, v.keys, data, index)
	if err != nil {
		return nil, readStage(ctx, "data-open", err)
	}
	var native contextBuffer
	defer func() { clear(native.Bytes()) }()
	if err = reader.Read(ctx, 0, m.Layout.NativeBytes, &native); err != nil {
		return nil, readStage(ctx, "data-read", err)
	}
	if err = v.contracts.ValidateNative(native.Bytes(), e, m); err != nil {
		return nil, readStage(ctx, "validate", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, readStage(ctx, "cancelled", err)
	}
	if !time.Now().Before(cutoff) {
		return nil, readStage(ctx, "cutoff", artifact.ErrInvalid)
	}
	return bytes.Clone(native.Bytes()), nil
}

type contextBuffer struct{ bytes.Buffer }

func (b *contextBuffer) Send(ctx context.Context, p []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(p) > artifact.MaxContextBytes-b.Len() {
		return artifact.ErrLimit
	}
	_, err := b.Write(p)
	return err
}

// contextReadStage names the closed read step that refused, with "cancelled"
// appended when the caller's context had ended, for the operator report only.
// It unwraps to the original error unchanged.
type contextReadStage struct {
	stage string
	err   error
}

func (e *contextReadStage) Error() string     { return e.err.Error() }
func (e *contextReadStage) Unwrap() error     { return e.err }
func (e *contextReadStage) FixedStep() string { return e.stage }

func readStage(ctx context.Context, stage string, err error) error {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		stage += "/cancelled"
	}
	return &contextReadStage{stage, err}
}
