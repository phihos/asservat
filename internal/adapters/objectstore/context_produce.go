package objectstore

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
)

type ContextProducer struct {
	store     *CustodyStore
	keys      evidence.KeySealer
	contracts *manifest.Validator
	now       func() time.Time
}

var _ evidence.ContextProducer = (*ContextProducer)(nil)

func NewContextProducer(store *CustodyStore, keys evidence.KeySealer, now func() time.Time) (*ContextProducer, error) {
	if store == nil || keys == nil || now == nil {
		return nil, artifact.ErrInvalid
	}
	contracts, err := manifest.New()
	if err != nil {
		return nil, err
	}
	return &ContextProducer{store, keys, contracts, now}, nil
}
func (p *ContextProducer) PrepareContext(ctx context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	if e.Validate() != nil || e.Registration.StoreID != p.store.storeID || e.Registration.NativeLimit != artifact.MaxContextBytes || e.DataClass != "metadata" || !p.now().Before(e.Registration.WriteUntil) {
		return nil, artifact.ErrInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, minDeadline(e.Registration.WriteUntil, p.now().Add(5*time.Second)))
	defer cancel()
	encoder, err := framed.Prepare(ctx, e.Binding(), p.keys)
	if err != nil {
		return nil, err
	}
	metadata, err := framed.PrepareManifest(ctx, e.Binding(), p.keys)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !p.now().Before(e.Registration.WriteUntil) {
		return nil, privacy.ErrExpired
	}
	e.Audience = slices.Clone(e.Audience)
	e.RetentionRules = slices.Clone(e.RetentionRules)
	return &preparedContext{producer: p, expectation: e, encoder: encoder, metadata: metadata}, nil
}
func minDeadline(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

type preparedContext struct {
	mu          sync.Mutex
	producer    *ContextProducer
	expectation artifact.ContextExpectation
	encoder     *framed.Encoder
	metadata    *framed.ManifestWriter
	used        bool
	completion  artifact.ContextWriterCompletion
}

// Close drops primitive references. Go/Tink do not promise physical key erasure;
// process isolation, swap/core controls and finite memory lifecycle still apply.
func (p *preparedContext) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
}
func (p *preparedContext) closeLocked() {
	p.used = true
	p.encoder = nil
	p.metadata = nil
	if !p.completion.StoredAt.IsZero() && p.completion.ClosedAt.IsZero() {
		p.completion.ClosedAt = p.producer.now().UTC().Truncate(time.Microsecond)
	}
}
func (p *preparedContext) CompleteStored() (artifact.ContextWriterCompletion, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
	if !p.completion.Valid(p.expectation.Registration) {
		return artifact.ContextWriterCompletion{}, privacy.ErrUnavailable
	}
	return p.completion, nil
}
func (p *preparedContext) StoreContext(ctx context.Context, native []byte, started, completed time.Time) (artifact.Copies, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out artifact.Copies
	if p.used || p.encoder == nil || p.metadata == nil {
		return out, artifact.ErrInvalid
	}
	p.used = true
	defer func() { p.encoder = nil; p.metadata = nil }()
	e := p.expectation
	now := p.producer.now
	if len(native) == 0 || int64(len(native)) > e.Registration.NativeLimit || !now().Before(e.Registration.WriteUntil) || completed.Before(started) || started.Before(e.Registration.AnchorAt) || completed.After(now()) || completed.Sub(started) > 5*time.Second {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, minDeadline(e.Registration.WriteUntil, now().Add(30*time.Second)))
	defer cancel()
	if err := p.producer.contracts.ValidateNative(native, e, manifest.ContextManifest{StartedAt: started, CompletedAt: completed}); err != nil {
		return out, err
	}
	var data, index bytes.Buffer
	layout, err := p.encoder.Encode(ctx, bytes.NewReader(native), &data, &index, e.Registration.NativeLimit)
	if err != nil {
		return out, err
	}
	put := func(i int, body []byte) error {
		if ctx.Err() != nil || !now().Before(e.Registration.WriteUntil) {
			return privacy.ErrExpired
		}
		if len(body) == 0 || int64(len(body)) > e.Registration.Limits()[i] {
			return artifact.ErrLimit
		}
		object, err := p.producer.store.store.PutSmall(ctx, e.Registration.Location.Prefix()+artifact.Role(i), body)
		if err != nil {
			return err
		}
		if ctx.Err() != nil || !now().Before(e.Registration.WriteUntil) {
			return privacy.ErrExpired
		}
		out[i] = artifact.CopyReceipt{VersionID: object.VersionID, ETag: object.ETag, Bytes: object.Bytes, SHA256: object.SHA256}
		return nil
	}
	for i, body := range [][]byte{data.Bytes(), index.Bytes()} {
		if err = put(i, body); err != nil {
			return artifact.Copies{}, err
		}
	}
	plain, err := p.producer.contracts.MarshalContext(e, layout, out, started, completed)
	if err != nil {
		return artifact.Copies{}, err
	}
	defer clear(plain)
	cipher, key, err := p.metadata.Seal(ctx, plain)
	if err != nil {
		return artifact.Copies{}, err
	}
	if err = put(2, cipher); err != nil {
		return artifact.Copies{}, err
	}
	commit, err := p.producer.contracts.MarshalCommit(e.Registration.Location, out[2], key)
	if err != nil {
		return artifact.Copies{}, err
	}
	if err = put(3, commit); err != nil {
		return artifact.Copies{}, err
	}
	if out.Validate(e.Registration) != nil {
		return artifact.Copies{}, artifact.ErrIntegrity
	}
	stored := now().UTC().Truncate(time.Microsecond)
	if ctx.Err() != nil || !stored.Before(e.Registration.WriteUntil) {
		return artifact.Copies{}, privacy.ErrExpired
	}
	p.completion = artifact.ContextWriterCompletion{RegistrationDigest: privacy.RegistrationDigest(e.Registration), ExpectationDigest: evidence.ContextExpectationDigest(e), Copies: out, StoredAt: stored}
	return out, nil
}
