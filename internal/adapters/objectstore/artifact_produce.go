package objectstore

import (
	"bytes"
	"context"
	"io"
	"slices"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
)

// ArtifactProducer writes one registered native artifact (ADR-244): framed
// encryption with the wrap-only key, the data object through ADR-166 streaming
// custody above one frame, and small index, manifest and commit objects. The
// result is only stored ciphertext for StoreCopies; it is not published and
// grants no disclosure. Pod status keeps its own bounded ContextProducer.
type ArtifactProducer struct {
	store     *CustodyStore
	keys      evidence.KeySealer
	journal   privacy.StreamingJournal
	contracts *manifest.Validator
	now       func() time.Time
}

func NewArtifactProducer(store *CustodyStore, keys evidence.KeySealer, journal privacy.StreamingJournal, now func() time.Time) (*ArtifactProducer, error) {
	if store == nil || keys == nil || journal == nil || now == nil {
		return nil, artifact.ErrInvalid
	}
	contracts, err := manifest.New()
	if err != nil {
		return nil, err
	}
	return &ArtifactProducer{store, keys, journal, contracts, now}, nil
}

// PreparedArtifact holds the prepared keys of one attempt. It is single use:
// a failed store leaves its journal and charges for cleanup, never a retry.
type PreparedArtifact struct {
	snapshotRetained *uint64
	mu               sync.Mutex
	producer         *ArtifactProducer
	expectation      artifact.ContextExpectation
	plan             artifact.StreamingPlan
	encoder          *framed.Encoder
	metadata         *framed.ManifestWriter
	used             bool
}

// Prepare wraps the data, index and manifest keys before the source is read.
// writerEpoch names the accepted writer process of the already registered
// streaming plan; it is required exactly when the limit exceeds one frame.
func (p *ArtifactProducer) Prepare(ctx context.Context, e artifact.ContextExpectation, writerEpoch string) (*PreparedArtifact, error) {
	r := e.Registration
	if e.Validate() != nil || !evidence.ValidSourceSnapshotManifest(e) || e.NativeType == artifact.PodStatusArtifact || r.StoreID != p.store.storeID || !p.now().Before(r.WriteUntil) {
		return nil, artifact.ErrInvalid
	}
	plan := artifact.StreamingPlan{Registration: r, WriterEpoch: writerEpoch}
	if r.NativeLimit > artifact.FrameBytes && plan.Validate() != nil || r.NativeLimit <= artifact.FrameBytes && writerEpoch != "" {
		return nil, artifact.ErrInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, minDeadline(r.WriteUntil, p.now().Add(5*time.Second)))
	defer cancel()
	encoder, err := framed.Prepare(ctx, e.Binding(), p.keys)
	if err != nil {
		return nil, err
	}
	metadata, err := framed.PrepareManifest(ctx, e.Binding(), p.keys)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !p.now().Before(r.WriteUntil) {
		return nil, privacy.ErrExpired
	}
	e.Audience = slices.Clone(e.Audience)
	e.RetentionRules = slices.Clone(e.RetentionRules)
	e.Lifecycle = e.Lifecycle.Clone()
	e.SourceSnapshotManifest = e.SourceSnapshotManifest.Clone()
	if e.Snapshot != nil {
		e.Snapshot = e.Snapshot.Clone()
	}
	return &PreparedArtifact{producer: p, expectation: e, plan: plan, encoder: encoder, metadata: metadata}, nil
}

// checkedReader feeds every native byte to the type's streaming check while
// it is encoded, so an invalid native stream fails before completion.
type checkedReader struct {
	src   io.Reader
	check manifest.NativeCheck
}

func (r checkedReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		if e := r.check.Write(p[:n]); e != nil {
			return 0, e
		}
	}
	return n, err
}

// streamingSink adapts the journaled multipart writer to the encoder.
type streamingSink struct {
	ctx context.Context
	w   *privacy.StreamingWriter
}

func (s streamingSink) Write(p []byte) (int, error) {
	if err := s.w.Write(s.ctx, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Store encodes the native stream and writes all four objects. started and
// completed describe the actual acquisition interval, including quiet/filter
// periods in a covered source window, never a fabricated trigger time. The original
// WriteUntil bounds storage backpressure; nothing extends it.
func (a *PreparedArtifact) Store(ctx context.Context, src io.Reader, started, completed time.Time) (artifact.Copies, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.expectation.Snapshot != nil {
		return artifact.Copies{}, artifact.ErrInvalid
	}
	return a.storeLocked(ctx, src, started, completed)
}

func (a *PreparedArtifact) storeLocked(ctx context.Context, src io.Reader, started, completed time.Time) (artifact.Copies, error) {
	var out artifact.Copies
	if a.used || a.encoder == nil || a.metadata == nil || src == nil {
		return out, artifact.ErrInvalid
	}
	a.used = true
	defer func() { a.encoder = nil; a.metadata = nil }()
	e, p := a.expectation, a.producer
	r := e.Registration
	if !p.now().Before(r.WriteUntil) || completed.Before(started) || started.Before(r.AnchorAt) || completed.After(p.now()) {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, r.WriteUntil)
	defer cancel()
	check, err := p.contracts.NativeCheck(e, manifest.ContextManifest{StartedAt: started, CompletedAt: completed})
	if err != nil {
		return out, err
	}
	var index, small bytes.Buffer
	var data io.Writer = &small
	var stream *privacy.StreamingWriter
	if r.NativeLimit > artifact.FrameBytes {
		if stream, err = privacy.NewStreamingWriter(ctx, a.plan, p.journal, StreamingObjects{Store: p.store.store}); err != nil {
			return out, err
		}
		data = streamingSink{ctx, stream}
	}
	layout, err := a.encoder.Encode(ctx, checkedReader{src, check}, data, &index, r.NativeLimit)
	if err != nil {
		return out, err
	}
	if err = check.Close(); err != nil {
		return out, err
	}
	if a.snapshotRetained != nil {
		count, ok := check.(interface{ PacketCount() uint64 })
		if !ok || count.PacketCount() != *a.snapshotRetained {
			return out, artifact.ErrIntegrity
		}
	}
	put := func(i int, body []byte) error {
		if ctx.Err() != nil || !p.now().Before(r.WriteUntil) {
			return privacy.ErrExpired
		}
		if len(body) == 0 || int64(len(body)) > r.Limits()[i] {
			return artifact.ErrLimit
		}
		object, err := p.store.store.PutSmall(ctx, r.Location.Prefix()+artifact.Role(i), body)
		if err != nil {
			return err
		}
		out[i] = artifact.CopyReceipt{VersionID: object.VersionID, ETag: object.ETag, Bytes: object.Bytes, SHA256: object.SHA256}
		return nil
	}
	if stream != nil {
		// Finish completes create-only and rereads the whole ciphertext.
		if out[0], err = stream.Finish(ctx); err != nil {
			return artifact.Copies{}, err
		}
	} else if err = put(0, small.Bytes()); err != nil {
		return artifact.Copies{}, err
	}
	if layout.DataBytes != out[0].Bytes || layout.DataSHA256 != out[0].SHA256 {
		return artifact.Copies{}, artifact.ErrIntegrity
	}
	if err = put(1, index.Bytes()); err != nil {
		return artifact.Copies{}, err
	}
	plain, err := p.contracts.MarshalContext(e, layout, out, started, completed)
	if err != nil {
		return artifact.Copies{}, err
	}
	defer clear(plain)
	cipher, key, err := a.metadata.Seal(ctx, plain)
	if err != nil {
		return artifact.Copies{}, err
	}
	if err = put(2, cipher); err != nil {
		return artifact.Copies{}, err
	}
	commit, err := p.contracts.MarshalCommit(r.Location, out[2], key)
	if err != nil {
		return artifact.Copies{}, err
	}
	if err = put(3, commit); err != nil {
		return artifact.Copies{}, err
	}
	if out.Validate(r) != nil || ctx.Err() != nil || !p.now().Before(r.WriteUntil) {
		return artifact.Copies{}, privacy.ErrExpired
	}
	return out, nil
}
