package evidence

import (
	"context"
	"errors"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// HTTPHeaderPager rechecks one stored httpHeaders projection under its
// recording's accepted limits and output cap and returns one page
// (httpheaders.RecordingPage). It returns no other document field.
type HTTPHeaderPager interface {
	HTTPHeaderPage([]byte, *artifact.Recording, query.HTTPHeaderSelection) (query.HTTPHeaderPage, error)
}

// ReadHTTPHeaderPage is the acquisition worker's httpHeaders branch of an
// approved query read (ADR-282). The artifact was opened with the query
// batch's own one-use key authority (NativeArtifactOpen); the native type
// fits one storage frame (RecordingNativeLimit), so it is read whole as that
// frame, rechecked and paged, and the plaintext is cleared before return.
// Only the page leaves the worker; its projection digest must equal the
// manifest-authenticated native SHA-256 the cursor binds to.
func ReadHTTPHeaderPage(ctx context.Context, opened NativeArtifactSource, s NativeContextSource, scope query.ContextProjectionScope, pager HTTPHeaderPager) (query.HTTPHeaderPage, error) {
	var zero query.HTTPHeaderPage
	if opened == nil {
		return zero, query.ErrUnavailable
	}
	defer opened.Close()
	e := s.Expectation
	if ctx == nil || ctx.Err() != nil || pager == nil || !scope.Valid() || scope.NativeType != artifact.HTTPHeadersArtifact || !s.Valid(scope.Version) || !projectionExpectation(e, scope) {
		return zero, query.ErrUnavailable
	}
	m := opened.Metadata()
	limit := min(e.Registration.NativeLimit, e.Recording.MaxBytes, artifact.RecordingNativeLimit)
	if m.Format != artifact.HTTPHeadersFormat || m.Size < 1 || m.Size > limit || m.SHA256 == (artifact.Digest{}) {
		return zero, query.ErrUnavailable
	}
	native := make([]byte, 0, m.Size)
	defer func() { clear(native[:cap(native)]) }()
	for offset := int64(0); offset < m.Size; {
		n := min(m.Size-offset, artifact.DeliveryBytes)
		b, final, err := opened.ReadNext(ctx, offset, n)
		if err != nil || int64(len(b)) != n || ctx.Err() != nil {
			clear(b)
			return zero, query.ErrUnavailable
		}
		native = append(native, b...)
		clear(b)
		offset += n
		if offset == m.Size && !final {
			return zero, query.ErrUnavailable
		}
	}
	sel := scope.Headers.Selection(scope.CaseID, scope.ArtifactID)
	page, err := pager.HTTPHeaderPage(native, e.Recording, sel)
	if errors.Is(err, query.ErrInvalidCursor) && ctx.Err() == nil {
		return zero, query.ErrInvalidCursor
	}
	if err != nil || ctx.Err() != nil || !page.Valid(sel) || page.ProjectionDigest != m.SHA256 {
		return zero, query.ErrUnavailable
	}
	return page, nil
}
