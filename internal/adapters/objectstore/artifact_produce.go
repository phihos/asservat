package objectstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	logcodec "asservat.local/asservat/internal/adapters/logs"
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
	// Only PrepareOneShotProfileArtifact selects receipt-only completion.
	storedOnly       bool
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
	e.Profile = e.Profile.Clone()
	e.Audience = slices.Clone(e.Audience)
	e.RetentionRules = slices.Clone(e.RetentionRules)
	e.Lifecycle = e.Lifecycle.Clone()
	e.Logs = e.Logs.Clone()
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

// StoreLogs streams one ongoing finite API acquisition. complete must join its
// original reader and final source check and return the actual acquisition end.
// No unknown/future end is placed into a manifest; the ordinary Store API and
// every other native type retain their known-interval path.
func (a *PreparedArtifact) StoreLogs(ctx context.Context, src io.Reader, started time.Time, complete func() (time.Time, error)) (artifact.Copies, error) {
	if a == nil || complete == nil {
		return artifact.Copies{}, artifact.ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.expectation.NativeType != artifact.LogsArtifact || a.expectation.Logs == nil || a.expectation.Validate() != nil {
		return artifact.Copies{}, artifact.ErrInvalid
	}
	return a.storeLocked(ctx, src, started, time.Time{}, complete)
}

// artifactStoreError exposes only a producer-owned stage; its cause remains
// available to errors.Is but is never interpolated into diagnostic text.
type artifactStoreError struct {
	stage string
	cause error
}

func (e artifactStoreError) Error() string     { return "artifact store refused at " + e.stage }
func (e artifactStoreError) Unwrap() error     { return e.cause }
func (e artifactStoreError) FixedStep() string { return e.stage }

func (a *PreparedArtifact) storeLocked(ctx context.Context, src io.Reader, started, completed time.Time, acquiring ...func() (time.Time, error)) (copies artifact.Copies, err error) {
	stage := "prepare"
	defer func() {
		if err != nil {
			err = artifactStoreError{stage, err}
		}
	}()
	var out artifact.Copies
	if a.used || a.encoder == nil || a.metadata == nil || src == nil {
		return out, fmt.Errorf("%w: prepared artifact used", artifact.ErrInvalid)
	}
	a.used = true
	defer func() { a.encoder = nil; a.metadata = nil }()
	e, p := a.expectation, a.producer
	r := e.Registration
	if len(acquiring) > 1 || len(acquiring) == 1 && (acquiring[0] == nil || e.NativeType != artifact.LogsArtifact || e.Logs == nil) || !p.now().Before(r.WriteUntil) || started.Before(r.AnchorAt) || started.After(p.now()) || len(acquiring) == 0 && (completed.Before(started) || completed.After(p.now())) {
		return out, fmt.Errorf("%w: store interval", artifact.ErrInvalid)
	}
	ctx, cancel := context.WithDeadline(ctx, r.WriteUntil)
	defer cancel()
	stage = "native-check"
	var check manifest.NativeCheck
	var liveCheck *logcodec.StreamCheck
	if len(acquiring) == 1 {
		liveCheck, err = logcodec.NewAcquiringCheck(e, started)
		check = liveCheck
	} else {
		check, err = p.contracts.NativeCheck(e, manifest.ContextManifest{StartedAt: started, CompletedAt: completed})
	}
	if err != nil {
		return out, fmt.Errorf("%w: native check", err)
	}
	var index, small bytes.Buffer
	var data io.Writer = &small
	var stream *privacy.StreamingWriter
	if r.NativeLimit > artifact.FrameBytes {
		stage = "multipart-create"
		if stream, err = privacy.NewStreamingWriter(ctx, a.plan, p.journal, StreamingObjects{Store: p.store.store}); err != nil {
			return out, err
		}
		data = streamingSink{ctx, stream}
	}
	stage = "encode-and-parts"
	layout, err := a.encoder.Encode(ctx, checkedReader{src, check}, data, &index, r.NativeLimit)
	if err != nil {
		return out, err
	}
	stage = "native-check"
	if liveCheck != nil {
		completed, err = acquiring[0]()
		if err == nil && (completed.Before(started) || completed.After(p.now()) || !completed.Before(r.WriteUntil) || ctx.Err() != nil) {
			err = artifact.ErrInvalid
		}
		if err == nil {
			err = liveCheck.CloseAt(completed)
		}
	} else {
		err = check.Close()
	}
	if err != nil {
		return out, err
	}
	if a.snapshotRetained != nil {
		count, ok := check.(interface{ PacketCount() uint64 })
		if !ok || count.PacketCount() != *a.snapshotRetained {
			return out, artifact.ErrIntegrity
		}
	}
	put := func(i int, body []byte) error {
		stage = "put-" + artifact.Role(i)
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
		stage = "multipart-complete"
		if a.storedOnly {
			// This private profile path cannot read or release temporary charges.
			// The publisher independently verifies the complete stored artifact.
			out[0], err = stream.FinishStored(ctx)
		} else {
			out[0], err = stream.Finish(ctx)
		}
		if err != nil {
			return artifact.Copies{}, err
		}
	} else if err = put(0, small.Bytes()); err != nil {
		return artifact.Copies{}, err
	}
	stage = "data-receipt"
	if layout.DataBytes != out[0].Bytes || layout.DataSHA256 != out[0].SHA256 {
		return artifact.Copies{}, artifact.ErrIntegrity
	}
	if err = put(1, index.Bytes()); err != nil {
		return artifact.Copies{}, err
	}
	stage = "manifest"
	plain, err := p.contracts.MarshalContext(e, layout, out, started, completed)
	if err != nil {
		return artifact.Copies{}, err
	}
	defer clear(plain)
	stage = "manifest-seal"
	cipher, key, err := a.metadata.Seal(ctx, plain)
	if err != nil {
		return artifact.Copies{}, err
	}
	if err = put(2, cipher); err != nil {
		return artifact.Copies{}, err
	}
	stage = "commit"
	commit, err := p.contracts.MarshalCommit(r.Location, out[2], key)
	if err != nil {
		return artifact.Copies{}, err
	}
	if err = put(3, commit); err != nil {
		return artifact.Copies{}, err
	}
	stage = "completion"
	if out.Validate(r) != nil || ctx.Err() != nil || !p.now().Before(r.WriteUntil) {
		return artifact.Copies{}, privacy.ErrExpired
	}
	return out, nil
}
