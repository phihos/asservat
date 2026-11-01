package evidence

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"crypto/sha256"
	"slices"
	"sync"
	"time"
)

// NativeContextSource is exact verified artifact provenance, not caller-selected
// object keys or a serialized human identity. Current key/service authorization
// must independently match these facts before any read or unwrap.
type NativeContextSource struct {
	Expectation artifact.ContextExpectation
	Copies      artifact.Copies
}

// Valid admits pod status (the historical 4 KiB type) and any registered
// native type whose registered size bound fits the installed download path
// (ADR-248: at most one 8 MiB frame). Only "metadata" artifacts are served.
func (s NativeContextSource) Valid(version artifact.Digest) bool {
	e := s.Expectation
	return e.Validate() == nil && (e.NativeType == artifact.PodStatusArtifact || e.Registration.NativeLimit <= e.Type().DownloadLimit()) && e.DataClass == "metadata" && s.Copies.Validate(e.Registration) == nil && ContextCopiesDigest(s.Copies) == version
}

// podStatus reports the historical single-buffer type. Every other type is
// served through a framed source opened once per operation.
func (s NativeContextSource) podStatus() bool {
	return s.Expectation.NativeType == artifact.PodStatusArtifact
}
func cloneNativeSource(s NativeContextSource) NativeContextSource {
	s.Expectation.Audience = slices.Clone(s.Expectation.Audience)
	s.Expectation.SourceSnapshotManifest = s.Expectation.SourceSnapshotManifest.Clone()
	s.Expectation.RetentionRules = slices.Clone(s.Expectation.RetentionRules)
	if s.Expectation.Snapshot != nil {
		s.Expectation.Snapshot = s.Expectation.Snapshot.Clone()
	}
	if s.Expectation.Lifecycle != nil {
		l := *s.Expectation.Lifecycle
		l.GapReasons = slices.Clone(l.GapReasons)
		s.Expectation.Lifecycle = &l
	}
	return s
}

// expectedNativeMetadata is the exact metadata of one stored artifact of the
// source's type with the given verified size and native SHA-256: the
// server-generated filename, the recorded format and coverage, the copies ETag
// and the registered retention dates. The type comes from the expectation, so
// a worker cannot relabel an artifact.
func expectedNativeMetadata(s NativeContextSource, size int64, sum artifact.Digest) artifact.NativeDownloadMetadata {
	e := s.Expectation
	t := e.Type()
	return artifact.NativeDownloadMetadata{Filename: t.Filename(e.Registration.Location.ArtifactID), Format: t.Format, ETag: NativeETag(ContextCopiesDigest(s.Copies)), Coverage: t.CoverageFor(e.Lifecycle), Size: size, SHA256: sum, ReadUntil: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}
}
func nativeContextMetadata(s NativeContextSource, body []byte) artifact.NativeDownloadMetadata {
	return expectedNativeMetadata(s, int64(len(body)), sha256.Sum256(body))
}

// ValidNativeSourceMetadata checks metadata against the exact source: equal to
// its expected facts and within both the registered and the download bound.
func ValidNativeSourceMetadata(s NativeContextSource, m artifact.NativeDownloadMetadata) bool {
	e := s.Expectation
	return m.Size >= 1 && m.Size <= e.Registration.NativeLimit && m.Size <= e.Type().DownloadLimit() && m.SHA256 != (artifact.Digest{}) && sameNativeMetadata(m, expectedNativeMetadata(s, m.Size, m.SHA256))
}

// sameNativeMetadata compares dates as instants: a decoded wire value keeps
// its own location representation.
func sameNativeMetadata(a, b artifact.NativeDownloadMetadata) bool {
	return a.Filename == b.Filename && a.Format == b.Format && a.ETag == b.ETag && a.Coverage == b.Coverage && a.Size == b.Size && a.SHA256 == b.SHA256 && a.ReadUntil.Equal(b.ReadUntil) && a.DeleteBy.Equal(b.DeleteBy)
}

// NativeWindowReadWork bounds the ciphertext one remote response window of
// the source reads. Pod status keeps its historical fixed charge. Any other
// type is at most one frame (ADR-248), read as that frame and one index page,
// each with its fixed cipher overhead; the window's read limit and the session
// read budget are charged with this bound, not with measured reads.
func NativeWindowReadWork(t artifact.NativeType) int64 {
	if t.Name == artifact.PodStatusArtifact {
		return ContextDownloadReadWork
	}
	return artifact.FrameBytes + artifact.CipherOverhead + artifact.PageBytes + artifact.CipherOverhead
}

// The remote operation's TLS/proof/SQL admission precedes this acquisition-role
// port. Its production reader uses the exact prepaid parent/key authority; it
// must not expose a general unwrap key or accept caller supplied credentials.
// It serves pod status only.
type NativeContextRead interface {
	ReadNativeContext(context.Context, NativeContextSource, value.NativeOperation, string, time.Time) ([]byte, error)
}

// NativeArtifactOpen is the same acquisition-role reader for every other
// registered type: it opens one stored artifact once with the operation's
// exact key authority (the preparation batch, or the response window) and
// authenticates its commit and manifest against the source. A production
// NativeContextRead implements it; a reader without it serves pod status only.
type NativeArtifactOpen interface {
	OpenNativeArtifact(context.Context, NativeContextSource, value.NativeOperation, string, time.Time) (NativeArtifactSource, error)
}

// NativeArtifactSource is one opened artifact. Metadata are the facts
// authenticated by its manifest. ReadNext returns exactly length bytes at the
// next sequential offset; every returned frame is authenticated first, and
// final reports that the end of the file passed the whole-file check (or that
// the range does not reach it). Close drops the keys.
type NativeArtifactSource interface {
	Metadata() artifact.NativeDownloadMetadata
	ReadNext(ctx context.Context, offset, length int64) (b []byte, final bool, err error)
	Close()
}

// RegionalContextResult owns only one provisional/committed metadata result for
// one original worker process. No payload or unwrap key survives Prepare. The
// authenticated hub sends Commit only after durable positive outcome/audit ack.
// An uncertain read cannot be retried in this process, even through a new stream.
type RegionalContextResult struct {
	mu                                   sync.Mutex
	ctx                                  context.Context
	cancel                               context.CancelFunc
	worker                               value.WorkerCredentialTarget
	reader                               NativeContextRead
	approved                             NativeApprovedContextRead
	projectionBatches                    [query.ContextMaxReadBatches]string
	now                                  func() time.Time
	attempted, active, closed, committed bool
	source                               NativeContextSource
	preparation                          value.NativeOperation
	metadata                             artifact.NativeDownloadMetadata
	done                                 chan struct{}
	doneClosed                           bool
}

func NewRegionalContextResult(ctx context.Context, worker value.WorkerCredentialTarget, reader NativeContextRead, now func() time.Time) (*RegionalContextResult, error) {
	if ctx == nil || ctx.Err() != nil || !worker.Valid() || worker.Parent().Purpose != value.AcquisitionDownload || reader == nil || now == nil || !now().Before(worker.RunUntil) {
		return nil, artifact.ErrInvalid
	}
	work, cancel := context.WithDeadline(ctx, worker.RunUntil)
	r := &RegionalContextResult{ctx: work, cancel: cancel, worker: worker, reader: reader, now: now, done: make(chan struct{})}
	context.AfterFunc(work, r.Close)
	return r, nil
}
func (r *RegionalContextResult) finishLocked() {
	if r.closed && !r.active && !r.doneClosed {
		r.reader = nil
		r.approved = nil
		r.source = NativeContextSource{}
		r.metadata = artifact.NativeDownloadMetadata{}
		close(r.done)
		r.doneClosed = true
	}
}
func (r *RegionalContextResult) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.cancel()
	r.finishLocked()
}
func (r *RegionalContextResult) Wait(ctx context.Context) error {
	if r == nil || ctx == nil {
		return artifact.ErrInvalid
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *RegionalContextResult) matches(o value.NativeOperation) bool {
	return o.CurrentValid(r.now()) && o.Reference.InstallationID == r.worker.InstallationID && o.Reference.Parent() == r.worker.Parent() && o.Reference.WorkerID == r.worker.WorkerID && o.WorkerPodUID == r.worker.PodUID && !o.Until.After(r.worker.RunUntil)
}
func (r *RegionalContextResult) enter(ctx context.Context, o value.NativeOperation) (context.Context, func(), error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(r.now().Add(value.NativeConversationWindow(o.Kind))) {
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.active || r.ctx.Err() != nil || !r.matches(o) || !r.now().Before(o.Until) {
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	r.active = true
	call, cancel := context.WithDeadline(ctx, o.Until)
	unlink := context.AfterFunc(r.ctx, cancel)
	return call, func() {
		unlink()
		cancel()
		r.mu.Lock()
		defer r.mu.Unlock()
		r.active = false
		r.finishLocked()
	}, nil
}
func (r *RegionalContextResult) Prepare(ctx context.Context, o value.NativeOperation, source NativeContextSource) (artifact.NativeDownloadMetadata, error) {
	var zero artifact.NativeDownloadMetadata
	if o.Kind != value.NativePrepare || !source.Valid(o.SourceVersion) || o.Processing.Location != source.Expectation.Registration.Location || o.Path.StoreID != source.Expectation.Registration.StoreID {
		return zero, artifact.ErrInvalid
	}
	call, leave, e := r.enter(ctx, o)
	if e != nil {
		return zero, e
	}
	defer leave()
	r.mu.Lock()
	if r.attempted {
		r.mu.Unlock()
		return zero, artifact.ErrDownloadUnavailable
	}
	r.attempted = true
	reader := r.reader
	r.mu.Unlock()
	source = cloneNativeSource(source)
	metadata, e := r.prepareMetadata(call, reader, source, o)
	if e != nil || call.Err() != nil || !r.now().Before(o.Until) {
		return zero, artifact.ErrDownloadUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	r.source = source
	r.preparation = o
	r.metadata = metadata
	return metadata, nil
}
func (r *RegionalContextResult) Commit(ctx context.Context, o value.NativeOperation) error {
	call, leave, e := r.enter(ctx, o)
	if e != nil {
		return e
	}
	defer leave()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !sameNativeOperation(o, r.preparation) || r.metadata.SHA256 == (artifact.Digest{}) || call.Err() != nil {
		return artifact.ErrDownloadUnavailable
	}
	r.committed = true
	return nil
}
func (r *RegionalContextResult) Observe(ctx context.Context, o value.NativeOperation) (artifact.NativeDownloadMetadata, error) {
	var zero artifact.NativeDownloadMetadata
	if o.Kind != value.NativeObserve {
		return zero, artifact.ErrInvalid
	}
	call, leave, e := r.enter(ctx, o)
	if e != nil {
		return zero, e
	}
	defer leave()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.committed || o.Path != r.preparation.Path || o.Processing.Location != r.preparation.Processing.Location || o.ParentID != r.preparation.ParentID || o.Generation != r.preparation.Generation || o.SourceVersion != r.preparation.SourceVersion || o.WorkerPublicKey != r.preparation.WorkerPublicKey || !r.now().Before(r.metadata.ReadUntil) || call.Err() != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	return r.metadata, nil
}

// prepareMetadata reads pod status whole (its historical check), and opens
// any other type once to take its manifest-authenticated facts; the payload
// was fully verified before publication and is authenticated again frame by
// frame on every response.
func (r *RegionalContextResult) prepareMetadata(ctx context.Context, reader NativeContextRead, source NativeContextSource, o value.NativeOperation) (artifact.NativeDownloadMetadata, error) {
	var zero artifact.NativeDownloadMetadata
	if source.podStatus() {
		body, e := reader.ReadNativeContext(ctx, source, o, "", o.Until)
		defer clear(body)
		if e != nil || len(body) < 1 || len(body) > artifact.MaxContextBytes {
			return zero, artifact.ErrDownloadUnavailable
		}
		return nativeContextMetadata(source, body), nil
	}
	open, ok := reader.(NativeArtifactOpen)
	if !ok {
		return zero, artifact.ErrDownloadUnavailable
	}
	a, e := open.OpenNativeArtifact(ctx, source, o, "", o.Until)
	if e != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	m := a.Metadata()
	a.Close()
	if !ValidNativeSourceMetadata(source, m) {
		return zero, artifact.ErrDownloadUnavailable
	}
	return m, nil
}

// Read is deliberately a separate paid operation: committed metadata never
// supplies a read key. The caller must retain the returned buffer until final
// sink acknowledgement or joined cancellation, then clear it.
func (r *RegionalContextResult) Read(ctx context.Context, o value.NativeOperation, source NativeContextSource, window string, offset, length int64) ([]byte, error) {
	var out []byte
	e := r.ReadWindow(ctx, o, source, window, offset, length, func(_ context.Context, b []byte) error {
		out = append(out, b...)
		return nil
	})
	if e != nil {
		clear(out)
		return nil, e
	}
	return out, nil
}

// ReadWindow serves one admitted response window [offset, offset+length) as
// sequential chunks of at most DeliveryBytes, in order, to deliver, which owns
// each chunk only until it returns (the buffer is cleared afterwards). The
// keys are opened once for the whole window under the window's key binding.
// A chunk reaching the end of the file is delivered only after the whole-file
// check; any failure stops the window and is not retried in this process.
func (r *RegionalContextResult) ReadWindow(ctx context.Context, o value.NativeOperation, source NativeContextSource, window string, offset, length int64, deliver func(context.Context, []byte) error) error {
	limit := source.Expectation.Type().DownloadLimit()
	if o.Kind != value.NativeResponse || deliver == nil || !value.UUID(window) || !source.Valid(o.SourceVersion) || o.Processing.Location != source.Expectation.Registration.Location || o.Path.StoreID != source.Expectation.Registration.StoreID || offset < 0 || length < 1 || offset > limit || length > limit-offset {
		return artifact.ErrInvalid
	}
	call, leave, e := r.enter(ctx, o)
	if e != nil {
		return e
	}
	defer leave()
	r.mu.Lock()
	if !r.committed || o.Path != r.preparation.Path || o.Processing.Location != r.preparation.Processing.Location || o.SourceVersion != r.preparation.SourceVersion || o.WorkerPublicKey != r.preparation.WorkerPublicKey {
		r.mu.Unlock()
		return artifact.ErrDownloadUnavailable
	}
	reader := r.reader
	metadata := r.metadata
	r.mu.Unlock()
	if offset+length > metadata.Size {
		return artifact.ErrDownloadUnavailable
	}
	source = cloneNativeSource(source)
	if source.podStatus() {
		body, e := reader.ReadNativeContext(call, source, o, window, o.Until)
		defer clear(body)
		if e != nil || call.Err() != nil || !r.now().Before(o.Until) || int64(len(body)) != metadata.Size || sha256.Sum256(body) != metadata.SHA256 {
			return collapsed("regional-pod-status-read", artifact.ErrDownloadUnavailable, e)
		}
		for at := offset; at < offset+length; {
			n := min(artifact.DeliveryBytes, offset+length-at)
			chunk := append([]byte(nil), body[at:at+n]...)
			e = deliver(call, chunk)
			clear(chunk)
			if e != nil {
				return e
			}
			at += n
		}
		return nil
	}
	open, ok := reader.(NativeArtifactOpen)
	if !ok {
		return artifact.ErrDownloadUnavailable
	}
	a, e := open.OpenNativeArtifact(call, source, o, window, o.Until)
	if e != nil {
		return collapsed("regional-artifact-open", artifact.ErrDownloadUnavailable, e)
	}
	defer a.Close()
	if !sameNativeMetadata(a.Metadata(), metadata) {
		return artifact.ErrIntegrity
	}
	for at := offset; at < offset+length; {
		n := min(artifact.DeliveryBytes, offset+length-at)
		chunk, final, e := a.ReadNext(call, at, n)
		if e == nil && (int64(len(chunk)) != n || at+n == metadata.Size && !final || call.Err() != nil || !r.now().Before(o.Until)) {
			e = artifact.ErrDownloadUnavailable
		}
		if e == nil {
			e = deliver(call, chunk)
		}
		clear(chunk)
		if e != nil {
			return e
		}
		at += n
	}
	return nil
}
