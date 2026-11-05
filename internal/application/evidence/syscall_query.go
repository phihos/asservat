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

// SyscallQuerier returns whole already recorded argument events. It has no
// provider, key, live-memory or external lookup capability.
type SyscallQuerier func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time, query.SyscallSelection, artifact.Digest) (query.ProjectionResult, error)

// ReadSyscallQuery owns native input and keys through final authentication and
// closure. Partial content, a stale cursor or size refusal cannot bypass EOF.
func ReadSyscallQuery(ctx context.Context, opened NativeArtifactSource, source NativeContextSource, scope query.ContextProjectionScope, queryArguments SyscallQuerier) (query.ProjectionResult, error) {
	var zero query.ProjectionResult
	if opened == nil {
		return zero, query.ErrUnavailable
	}
	closed := false
	closeSource := func() {
		if !closed {
			closed = true
			opened.Close()
		}
	}
	defer closeSource()
	window, ok := opened.(NativeCaptureWindow)
	if !ok || ctx == nil || ctx.Err() != nil || queryArguments == nil || !scope.Valid() || scope.NativeType != artifact.SyscallArgumentsArtifact || scope.DisplayVersion != query.SyscallQueryDisplayVersion || !source.Valid(scope.Version) || !projectionExpectation(source.Expectation, scope) {
		return zero, query.ErrUnavailable
	}
	from, until := window.CaptureWindow()
	if from.IsZero() || until.Before(from) {
		return zero, query.ErrUnavailable
	}
	metadata := opened.Metadata()
	if !ValidNativeSourceMetadata(source, metadata) || metadata.Size < 1 || metadata.Size > artifact.RecordingNativeLimit {
		return zero, query.ErrUnavailable
	}
	reader := &profileNativeReader{ctx: ctx, source: opened, size: metadata.Size}
	defer func() { clear(reader.buffer) }()
	result, err := queryArguments(ctx, reader, source.Expectation, from, until, scope.Syscalls.Selection(scope.CaseID, scope.ArtifactID), scope.Version)
	invalid, tooLarge := errors.Is(err, query.ErrInvalidCursor), errors.Is(err, query.ErrRecordTooLarge)
	if invalid || tooLarge {
		result.Clear()
		if _, drainErr := io.Copy(io.Discard, reader); drainErr != nil {
			err = drainErr
			invalid, tooLarge = false, false
		} else {
			err = nil
			result.InvalidCursor, result.TooLarge = invalid, tooLarge
		}
	}
	final := opened.Metadata()
	closeSource()
	if err != nil || ctx.Err() != nil || reader.failed || !reader.final || reader.offset != reader.size || len(reader.buffer) != 0 || !ValidNativeSourceMetadata(source, final) || final.Size != metadata.Size || final.SHA256 != metadata.SHA256 || !result.Valid(scope) {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	if result.SyscallQuery != nil && !result.SyscallQuery.Valid(scope.Syscalls.Selection(scope.CaseID, scope.ArtifactID), scope.Version, scope.PodUID, from, until) {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	encoded, err := json.Marshal(result)
	n := len(encoded)
	clear(encoded)
	if err != nil || n > query.ContextResultBytes {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	return result, nil
}
