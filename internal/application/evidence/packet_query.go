package evidence

import (
	"context"
	"errors"
	"io"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// PacketQuerier interprets only compiled, closed worker selections. It has no
// provider, key, authored expression or external lookup capability.
type PacketQuerier func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time, query.PacketQuerySelection) (query.PacketQueryResult, error)

// ReadPacketQuery owns the source through final authenticated EOF and key
// closure. A swallowed source error or a valid prefix can never disclose data.
func ReadPacketQuery(ctx context.Context, opened NativeArtifactSource, source NativeContextSource, scope query.ContextProjectionScope, queryPackets PacketQuerier) (query.ProjectionResult, error) {
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
	if !ok || ctx == nil || ctx.Err() != nil || queryPackets == nil || !scope.Valid() || scope.PacketQuery == (query.PacketQueryWindow{}) || (scope.NativeType != artifact.PCAPNGArtifact && scope.NativeType != artifact.RawPCAPNGArtifact) || !source.Valid(scope.Version) || !projectionExpectation(source.Expectation, scope) {
		return zero, query.ErrUnavailable
	}
	from, until := window.CaptureWindow()
	if from.IsZero() || until.Before(from) {
		return zero, query.ErrUnavailable
	}
	m := opened.Metadata()
	if !ValidNativeSourceMetadata(source, m) || m.Size < 1 || m.Size > artifact.RecordingNativeLimit || source.Expectation.Registration.NativeLimit > artifact.RecordingNativeLimit {
		return zero, query.ErrUnavailable
	}
	reader := &profileNativeReader{ctx: ctx, source: opened, size: m.Size}
	defer func() { clear(reader.buffer) }()
	summary, err := queryPackets(ctx, reader, source.Expectation, from, until, scope.PacketQuery.Selection())
	if errors.Is(err, query.ErrRecordTooLarge) {
		if _, drainErr := io.Copy(io.Discard, reader); drainErr != nil {
			err = drainErr
		}
	}
	final := opened.Metadata()
	closeSource()
	if ctx.Err() != nil || reader.failed || !reader.final || reader.offset != reader.size || len(reader.buffer) != 0 || !ValidNativeSourceMetadata(source, final) || final.Size != m.Size || final.SHA256 != m.SHA256 {
		summary.Clear()
		return zero, query.ErrUnavailable
	}
	if err != nil || !summary.Valid(scope.PacketQuery.Selection(), scope.NativeType) || (scope.NativeType == artifact.RawPCAPNGArtifact) != (summary.CaptureMode == "rawPackets") {
		summary.Clear()
		return zero, query.ErrUnavailable
	}
	if summary.EncodedSize() > query.PacketQueryPageBytes {
		summary.Clear()
		return zero, query.ErrUnavailable
	}
	result := query.ProjectionResult{PacketQuery: &summary}
	return result, nil
}
