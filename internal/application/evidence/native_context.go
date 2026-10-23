package evidence

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func (s NativeContextSource) Valid(version artifact.Digest) bool {
	return s.Expectation.Validate() == nil && s.Expectation.DataClass == "metadata" && s.Copies.Validate(s.Expectation.Registration) == nil && ContextCopiesDigest(s.Copies) == version
}
func cloneNativeSource(s NativeContextSource) NativeContextSource {
	s.Expectation.Audience = slices.Clone(s.Expectation.Audience)
	s.Expectation.RetentionRules = slices.Clone(s.Expectation.RetentionRules)
	return s
}
func nativeContextMetadata(s NativeContextSource, body []byte) artifact.NativeDownloadMetadata {
	version := ContextCopiesDigest(s.Copies)
	return artifact.NativeDownloadMetadata{Filename: "artifact-" + s.Expectation.Registration.Location.ArtifactID + ".json", Format: artifact.ContextFormat, ETag: `"v1-` + hex.EncodeToString(version[:]) + `"`, Coverage: "Selected pod-status fields only; no logs, messages or workload configuration.", Size: int64(len(body)), SHA256: sha256.Sum256(body), ReadUntil: s.Expectation.Registration.ExpiresAt, DeleteBy: s.Expectation.Registration.DeleteBy}
}

// The remote operation's TLS/proof/SQL admission precedes this acquisition-role
// port. Its production reader uses the exact prepaid parent/key authority; it
// must not expose a general unwrap key or accept caller supplied credentials.
type NativeContextRead interface {
	ReadNativeContext(context.Context, NativeContextSource, value.NativeOperation, string, time.Time) ([]byte, error)
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
	if !ok || deadline.After(r.now().Add(5*time.Second)) {
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
	body, e := reader.ReadNativeContext(call, source, o, "", o.Until)
	defer clear(body)
	if e != nil || call.Err() != nil || !r.now().Before(o.Until) || len(body) < 1 || len(body) > artifact.MaxContextBytes {
		return zero, artifact.ErrDownloadUnavailable
	}
	metadata := nativeContextMetadata(source, body)
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

// Read is deliberately a separate paid operation: committed metadata never
// supplies a read key. The caller must retain the returned buffer until final
// sink acknowledgement or joined cancellation, then clear it.
func (r *RegionalContextResult) Read(ctx context.Context, o value.NativeOperation, source NativeContextSource, window string, offset, length int64) ([]byte, error) {
	if o.Kind != value.NativeResponse || !value.UUID(window) || !source.Valid(o.SourceVersion) || o.Processing.Location != source.Expectation.Registration.Location || o.Path.StoreID != source.Expectation.Registration.StoreID || offset < 0 || length < 1 || offset > artifact.MaxContextBytes || length > artifact.MaxContextBytes-offset {
		return nil, artifact.ErrInvalid
	}
	call, leave, e := r.enter(ctx, o)
	if e != nil {
		return nil, e
	}
	defer leave()
	r.mu.Lock()
	if !r.committed || o.Path != r.preparation.Path || o.Processing.Location != r.preparation.Processing.Location || o.SourceVersion != r.preparation.SourceVersion || o.WorkerPublicKey != r.preparation.WorkerPublicKey {
		r.mu.Unlock()
		return nil, artifact.ErrDownloadUnavailable
	}
	reader := r.reader
	metadata := r.metadata
	r.mu.Unlock()
	body, e := reader.ReadNativeContext(call, cloneNativeSource(source), o, window, o.Until)
	defer clear(body)
	if e != nil || call.Err() != nil || !r.now().Before(o.Until) || int64(len(body)) != metadata.Size || sha256.Sum256(body) != metadata.SHA256 || offset+length > int64(len(body)) {
		return nil, artifact.ErrDownloadUnavailable
	}
	return append([]byte(nil), body[offset:offset+length]...), nil
}
