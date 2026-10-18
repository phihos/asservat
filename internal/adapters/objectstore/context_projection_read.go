package objectstore

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
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
	if !ok || deadline.After(until) || deadline.After(time.Now().Add(5*time.Second)) || !time.Now().Before(deadline) {
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	// Retain the exact expected audience/retention values across provider waits.
	source.Expectation.Audience = slices.Clone(source.Expectation.Audience)
	source.Expectation.RetentionRules = slices.Clone(source.Expectation.RetentionRules)
	verifier, err := NewContextVerifier(r.store, keys)
	if err != nil {
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	// Same authenticated pinned commit/manifest/envelope/index/native machinery;
	// no download session, authority, key grant or metadata builder is invoked.
	native, err := verifier.readContext(ctx, source.Expectation, source.Copies, minDeadline(deadline, source.Expectation.Registration.ExpiresAt))
	defer clear(native)
	if err != nil || ctx.Err() != nil {
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	p, err := ParseContextProjection(native, scope)
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	return p, nil
}

var _ evidence.ContextProjectionNativeRead = (*ContextProjectionReader)(nil)
