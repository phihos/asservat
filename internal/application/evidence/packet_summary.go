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

// PacketSummarizer is a closed worker-only fixed-metadata interpreter, with no
// provider, key, query expression or external lookup capability.
type PacketSummarizer func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time) (query.PacketSummary, error)

// ReadPacketSummary owns the source through final authenticated EOF and key
// closure. A swallowed source error or a valid prefix can never disclose data.
func ReadPacketSummary(ctx context.Context, opened NativeArtifactSource, source NativeContextSource, scope query.ContextProjectionScope, summarize PacketSummarizer) (query.ProjectionResult, error) {
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
	if !ok || ctx == nil || ctx.Err() != nil || summarize == nil || !scope.Valid() || (scope.NativeType != artifact.PCAPNGArtifact && scope.NativeType != artifact.RawPCAPNGArtifact) || !source.Valid(scope.Version) || !projectionExpectation(source.Expectation, scope) {
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
	summary, err := summarize(ctx, reader, source.Expectation, from, until)
	if errors.Is(err, query.ErrRecordTooLarge) {
		if _, drainErr := io.Copy(io.Discard, reader); drainErr != nil {
			err = drainErr
		}
	}
	final := opened.Metadata()
	closeSource()
	if ctx.Err() != nil || reader.failed || !reader.final || reader.offset != reader.size || len(reader.buffer) != 0 || !ValidNativeSourceMetadata(source, final) || final.Size != m.Size || final.SHA256 != m.SHA256 {
		clear(summary.Conversations)
		return zero, query.ErrUnavailable
	}
	if err != nil || !summary.Valid() || (scope.NativeType == artifact.RawPCAPNGArtifact) != (summary.CaptureMode == "rawPackets") {
		clear(summary.Conversations)
		return zero, query.ErrUnavailable
	}
	if summary.Drops != nil {
		reporting := "captureExclusions"
		if source.Expectation.Snapshot != nil {
			reporting = "snapshotOutputLimit"
		}
		if summary.DropReporting != reporting {
			clear(summary.Conversations)
			return zero, query.ErrUnavailable
		}
	}
	result := query.ProjectionResult{PacketSummary: &summary}
	raw, err := json.Marshal(result)
	defer clear(raw)
	if err != nil {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	if len(raw) > query.ContextResultBytes {
		result.Clear()
		return zero, query.ErrUnavailable
	}
	return result, nil
}
