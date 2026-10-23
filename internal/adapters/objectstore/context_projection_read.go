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
type ContextProjectionReader struct{ store *CustodyStore }

func NewContextProjectionReader(store *CustodyStore) (*ContextProjectionReader, error) {
	if store == nil {
		return nil, artifact.ErrInvalid
	}
	return &ContextProjectionReader{store: store}, nil
}

func (r *ContextProjectionReader) ReadProjectionNative(ctx context.Context, source evidence.NativeContextSource, scope value.ContextProjectionScope, keys evidence.KeyOpener, until time.Time) (value.PodStatusProjection, error) {
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
