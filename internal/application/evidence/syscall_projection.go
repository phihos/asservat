package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// SyscallProjector is a fixed regional metadata projection, including when the
// source has raw arguments. It has no key, provider or external lookup port.
// The installed adapter additionally composes the canonical native validator.
type SyscallProjector func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time, query.SyscallSelection, artifact.Digest) (query.ProjectionResult, error)

// NativeCaptureWindow is supplied only by the authenticated native opener.
// Keeping it separate leaves ordinary download sources unchanged.
type NativeCaptureWindow interface {
	CaptureWindow() (started, completed time.Time)
}

// ReadSyscallProjection owns the full authenticated read and drops keys before
// returning. No prefix, swallowed source error or unverified final digest can
// produce a result, including an invalid-cursor response.
func ReadSyscallProjection(ctx context.Context, opened NativeArtifactSource, source NativeContextSource, scope query.ContextProjectionScope, project SyscallProjector) (query.ProjectionResult, error) {
	var zero query.ProjectionResult
	if opened == nil {
		return zero, query.ErrUnavailable
	}
	defer opened.Close()
	window, ok := opened.(NativeCaptureWindow)
	if !ok || ctx == nil || ctx.Err() != nil || project == nil || !scope.Valid() ||
		(scope.NativeType != artifact.SyscallRecordsArtifact && scope.NativeType != artifact.SyscallArgumentsArtifact) ||
		!source.Valid(scope.Version) || !projectionExpectation(source.Expectation, scope) {
		return zero, query.ErrUnavailable
	}
	from, until := window.CaptureWindow()
	if from.IsZero() || until.Before(from) {
		return zero, query.ErrUnavailable
	}
	m := opened.Metadata()
	if !ValidNativeSourceMetadata(source, m) || m.Size > artifact.RecordingNativeLimit {
		return zero, query.ErrUnavailable
	}
	r := &profileNativeReader{ctx: ctx, source: opened, size: m.Size}
	defer func() { clear(r.buffer) }()
	result, err := project(ctx, r, source.Expectation, from, until, scope.Syscalls.Selection(scope.CaseID, scope.ArtifactID), scope.Version)
	// A stale cursor may be refused by the fixed parser before its first read.
	// Authenticate the complete source before reporting the typed refusal too.
	if errors.Is(err, query.ErrInvalidCursor) {
		if _, drainErr := io.Copy(io.Discard, r); drainErr == nil {
			result.Clear()
			result.InvalidCursor, err = true, nil
		}
	}
	if err != nil || ctx.Err() != nil || r.failed || !r.final || r.offset != r.size || len(r.buffer) != 0 || !result.Valid(scope) {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	if result.SyscallEvents != nil && !result.SyscallEvents.Valid(scope.Syscalls.Selection(scope.CaseID, scope.ArtifactID), scope.Version, scope.PodUID, from, until) {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	b, err := json.Marshal(result)
	defer clear(b)
	if err != nil || len(b) > query.ContextResultBytes {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	return result, nil
}
