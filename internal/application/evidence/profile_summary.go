package evidence

import (
	"context"
	"encoding/json"
	"io"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// ProfileSummarizer is the regional worker's closed Go analyzer. Native bytes
// never enter the hub, and the analyzer receives no key or provider capability.
type ProfileSummarizer func(context.Context, io.Reader, query.ProfileSummarySelection) (query.ProfileSummary, error)

// ReadProfileSummary streams the exact authenticated native source into the
// bounded analyzer. It retains no whole compressed profile. A partial read,
// failed final hash or canceled owner never yields a result, even if an analyzer
// accidentally swallows its reader's error. Close drops the source's keys.
func ReadProfileSummary(ctx context.Context, opened NativeArtifactSource, source NativeContextSource, scope query.ContextProjectionScope, summarize ProfileSummarizer) (query.ProfileSummary, error) {
	var zero query.ProfileSummary
	if opened == nil {
		return zero, query.ErrUnavailable
	}
	defer opened.Close()
	if ctx == nil || ctx.Err() != nil || summarize == nil || !scope.Valid() || scope.NativeType != artifact.PprofArtifact || !source.Valid(scope.Version) || !projectionExpectation(source.Expectation, scope) {
		return zero, query.ErrUnavailable
	}
	m := opened.Metadata()
	if m.Format != artifact.PprofFormat || m.Size < 1 || m.Size > source.Expectation.Registration.NativeLimit || m.SHA256 == (artifact.Digest{}) {
		return zero, query.ErrUnavailable
	}
	r := &profileNativeReader{ctx: ctx, source: opened, size: m.Size}
	defer func() { clear(r.buffer) }()
	result, err := summarize(ctx, r, scope.Profile)
	if err != nil || ctx.Err() != nil || r.failed || !r.final || r.offset != r.size || len(r.buffer) != 0 || !result.Valid(scope.Profile) {
		clear(result.Top)
		return zero, query.ErrUnavailable
	}
	b, err := json.Marshal(result)
	defer clear(b)
	if err != nil || len(b) > query.ProfileSummaryBytes {
		clear(result.Top)
		return zero, query.ErrUnavailable
	}
	return result, nil
}

type profileNativeReader struct {
	ctx           context.Context
	source        NativeArtifactSource
	offset, size  int64
	final, failed bool
	buffer        []byte
}

func (r *profileNativeReader) Read(p []byte) (int, error) {
	if r.failed || r.ctx.Err() != nil {
		r.failed = true
		return 0, query.ErrUnavailable
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.buffer) == 0 {
		if r.offset == r.size && r.final {
			return 0, io.EOF
		}
		// A delivery-sized read avoids repeatedly moving the framed reader's
		// authenticated carry for each small gzip/bufio read.
		n := min(artifact.DeliveryBytes, r.size-r.offset)
		b, final, err := r.source.ReadNext(r.ctx, r.offset, n)
		if err != nil || r.ctx.Err() != nil || int64(len(b)) != n || r.offset+n == r.size && !final {
			clear(b)
			r.failed = true
			return 0, query.ErrUnavailable
		}
		r.offset += n
		r.final = r.offset == r.size && final
		r.buffer = b
	}
	n := copy(p, r.buffer)
	clear(r.buffer[:n])
	r.buffer = r.buffer[n:]
	return n, nil
}
