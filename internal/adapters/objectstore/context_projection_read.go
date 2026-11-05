package objectstore

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextProjectionReader belongs only in the regional query worker. Its
// opener is already bound to that query/batch and independently checked key
// provider. No hub constructor receives this reader or a generic unwrap key.
// An httpHeaders page (ADR-282) additionally needs the installed pager; a
// reader without one serves pod status only.
type ContextProjectionReader struct {
	store     *CustodyStore
	pages     evidence.HTTPHeaderPager
	summarize evidence.ProfileSummarizer
	syscalls  evidence.SyscallProjector
	compare   evidence.ProfileComparer
	packets   evidence.PacketSummarizer
}

func NewContextProjectionReader(store *CustodyStore) (*ContextProjectionReader, error) {
	if store == nil {
		return nil, artifact.ErrInvalid
	}
	return &ContextProjectionReader{store: store}, nil
}

// ReadProjectionNative returns the scope's one result: the pod-status DTO, or
// one rechecked httpHeaders page.
func (r *ContextProjectionReader) ReadProjectionNative(ctx context.Context, source evidence.NativeContextSource, scope value.ContextProjectionScope, keys evidence.KeyOpener, until time.Time) (value.ProjectionResult, error) {
	if r != nil && scope.NativeType == artifact.PCAPNGArtifact {
		return r.readPacketSummary(ctx, source, scope, keys, until)
	}
	if r != nil && (scope.NativeType == artifact.SyscallRecordsArtifact || scope.NativeType == artifact.SyscallArgumentsArtifact) {
		return r.readSyscallProjection(ctx, source, scope, keys, until)
	}
	if r != nil && scope.NativeType == artifact.PprofArtifact {
		return r.readProfileSummary(ctx, source, scope, keys, until)
	}
	if r != nil && scope.NativeType == artifact.HTTPHeadersArtifact {
		return r.readHeaderPage(ctx, source, scope, keys, until)
	}
	p, err := r.readPodStatus(ctx, source, scope, keys, until)
	if err != nil {
		return value.ProjectionResult{}, err
	}
	return value.ProjectionResult{PodStatus: p}, nil
}

func (r *ContextProjectionReader) readPodStatus(ctx context.Context, source evidence.NativeContextSource, scope value.ContextProjectionScope, keys evidence.KeyOpener, until time.Time) (value.PodStatusProjection, error) {
	if r == nil || r.store == nil || ctx == nil || ctx.Err() != nil || keys == nil || !scope.Valid() || !source.Valid(scope.Version) ||
		source.Expectation.Registration.NativeLimit != artifact.MaxContextBytes || source.Expectation.DataClass != "metadata" || source.Expectation.ActionID != "pod-status" ||
		source.Expectation.CaseID != scope.CaseID || source.Expectation.CaptureUID != scope.CaptureID || source.Expectation.NamespaceUID != scope.NamespaceUID ||
		source.Expectation.WorkloadUID != scope.WorkloadUID || source.Expectation.PodUID != scope.PodUID || source.Expectation.Registration.Location.ArtifactID != scope.ArtifactID ||
		source.Expectation.Registration.Location.ClusterID != scope.ClusterID {
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(until) || deadline.After(time.Now().Add(identity.EvidenceReadRequestWindow)) || !time.Now().Before(deadline) {
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	// Retain the exact expected audience/retention values across provider waits.
	source.Expectation.Audience = slices.Clone(source.Expectation.Audience)
	source.Expectation.RetentionRules = slices.Clone(source.Expectation.RetentionRules)
	source.Expectation.SourceSnapshotManifest = source.Expectation.SourceSnapshotManifest.Clone()
	// Worker read timing: each key unwrap, then the remaining object reads and
	// decryption, then parsing. Fixed step names and buckets only.
	timed := &timedKeyOpener{inner: keys}
	verifier, err := NewContextVerifier(r.store, timed)
	if err != nil {
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	// Same authenticated pinned commit/manifest/envelope/index/native machinery;
	// no download session, authority, key grant or metadata builder is invoked.
	started := time.Now()
	native, err := verifier.readContext(ctx, source.Expectation, source.Copies, minDeadline(deadline, source.Expectation.Registration.ExpiresAt))
	app.MarkDuration(ctx, "object-decrypt", time.Since(started)-timed.total())
	defer clear(native)
	if err != nil || ctx.Err() != nil {
		return value.PodStatusProjection{}, &readRefusal{value.ErrUnavailable, err}
	}
	started = time.Now()
	p, err := ParseContextProjection(native, scope)
	app.MarkStep(ctx, "parse", started)
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return value.PodStatusProjection{}, &readRefusal{value.ErrUnavailable, readStage(ctx, "parse", errors.Join(value.ErrUnavailable, err))}
	}
	return p, nil
}

// readHeaderPage opens the extract with the batch's keys, reads its single
// frame, rechecks and pages it (evidence.ReadHTTPHeaderPage). A cursor that
// does not fit the rechecked document is the invalid-cursor result.
func (r *ContextProjectionReader) readHeaderPage(ctx context.Context, source evidence.NativeContextSource, scope value.ContextProjectionScope, keys evidence.KeyOpener, until time.Time) (value.ProjectionResult, error) {
	var zero value.ProjectionResult
	if r.store == nil || r.pages == nil || ctx == nil || ctx.Err() != nil || keys == nil || !scope.Valid() || !source.Valid(scope.Version) {
		return zero, value.ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(until) || deadline.After(time.Now().Add(identity.EvidenceReadRequestWindow)) || !time.Now().Before(deadline) {
		return zero, value.ErrUnavailable
	}
	source.Expectation.Audience = slices.Clone(source.Expectation.Audience)
	source.Expectation.RetentionRules = slices.Clone(source.Expectation.RetentionRules)
	source.Expectation.SourceSnapshotManifest = source.Expectation.SourceSnapshotManifest.Clone()
	timed := &timedKeyOpener{inner: keys}
	verifier, err := NewContextVerifier(r.store, timed)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	started := time.Now()
	opened, err := verifier.openNative(ctx, ctx, source.Expectation, source.Copies, minDeadline(deadline, source.Expectation.Registration.ExpiresAt))
	if err != nil || ctx.Err() != nil {
		if opened != nil {
			opened.Close()
		}
		return zero, &readRefusal{value.ErrUnavailable, err}
	}
	page, err := evidence.ReadHTTPHeaderPage(ctx, opened, source, scope, r.pages)
	app.MarkDuration(ctx, "object-decrypt", time.Since(started)-timed.total())
	if errors.Is(err, value.ErrInvalidCursor) {
		return value.ProjectionResult{InvalidCursor: true}, nil
	}
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return zero, &readRefusal{value.ErrUnavailable, readStage(ctx, "page", errors.Join(value.ErrUnavailable, err))}
	}
	return value.ProjectionResult{Headers: page}, nil
}

var _ evidence.ContextProjectionNativeRead = (*ContextProjectionReader)(nil)

// timedKeyOpener marks each unwrap as unwrap-1, unwrap-2, ... in the call's
// step recorder and keeps their sum. It changes no key result.
type timedKeyOpener struct {
	inner evidence.KeyOpener
	mu    sync.Mutex
	n     int
	sum   time.Duration
}

func (t *timedKeyOpener) Open(ctx context.Context, key artifact.SealedKey, aad []byte) ([]byte, error) {
	started := time.Now()
	out, err := t.inner.Open(ctx, key, aad)
	d := time.Since(started)
	t.mu.Lock()
	t.n++
	t.sum += d
	n := t.n
	t.mu.Unlock()
	if n <= 8 {
		app.MarkDuration(ctx, "unwrap-"+strconv.Itoa(n), d)
	}
	return out, err
}

func (t *timedKeyOpener) total() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sum
}

// readRefusal keeps the returned refusal and carries the read step that
// caused it (FixedStep only), for the worker's report.
type readRefusal struct{ err, cause error }

func (e *readRefusal) Error() string { return e.err.Error() }
func (e *readRefusal) Unwrap() error { return e.err }
func (e *readRefusal) FixedStep() string {
	var inner interface{ FixedStep() string }
	if e.cause != nil && errors.As(e.cause, &inner) {
		return inner.FixedStep()
	}
	return "verify"
}

// ServeProfileSummaries enables the closed analyzer in a regional reader only.
func (r *ContextProjectionReader) ServeProfileSummaries(f evidence.ProfileSummarizer) {
	if r != nil {
		r.summarize = f
	}
}

func (r *ContextProjectionReader) readProfileSummary(ctx context.Context, source evidence.NativeContextSource, scope value.ContextProjectionScope, keys evidence.KeyOpener, until time.Time) (value.ProjectionResult, error) {
	var zero value.ProjectionResult
	if r.store == nil || r.summarize == nil || ctx == nil || ctx.Err() != nil || keys == nil || !scope.Valid() || scope.Comparison != (value.ProfileComparisonWindow{}) || !source.Valid(scope.Version) {
		return zero, value.ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(until) || deadline.After(time.Now().Add(identity.EvidenceReadRequestWindow)) || !time.Now().Before(deadline) {
		return zero, value.ErrUnavailable
	}
	source.Expectation.Audience = slices.Clone(source.Expectation.Audience)
	source.Expectation.RetentionRules = slices.Clone(source.Expectation.RetentionRules)
	source.Expectation.Profile = source.Expectation.Profile.Clone()
	timed := &timedKeyOpener{inner: keys}
	verifier, err := NewContextVerifier(r.store, timed)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	started := time.Now()
	opened, err := verifier.openNative(ctx, ctx, source.Expectation, source.Copies, minDeadline(deadline, source.Expectation.Registration.ExpiresAt))
	if err != nil || ctx.Err() != nil {
		if opened != nil {
			opened.Close()
		}
		return zero, &readRefusal{value.ErrUnavailable, err}
	}
	summary, err := evidence.ReadProfileSummary(ctx, opened, source, scope, r.summarize)
	app.MarkDuration(ctx, "object-decrypt", time.Since(started)-timed.total())
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		clear(summary.Top)
		return zero, &readRefusal{value.ErrUnavailable, readStage(ctx, "parse", errors.Join(value.ErrUnavailable, err))}
	}
	return value.ProjectionResult{Summary: &summary}, nil
}
