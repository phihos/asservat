package evidence

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

type summarySourceFixture struct {
	metadata               artifact.NativeDownloadMetadata
	offset, maximum        int64
	reads                  int
	closed, noFinal, short bool
	afterRead              func()
	returned               []byte
}

func (s *summarySourceFixture) Metadata() artifact.NativeDownloadMetadata { return s.metadata }
func (s *summarySourceFixture) Close()                                    { s.closed = true }
func (s *summarySourceFixture) ReadNext(ctx context.Context, offset, length int64) ([]byte, bool, error) {
	if ctx.Err() != nil || offset != s.offset || length < 1 || length > artifact.DeliveryBytes || offset+length > s.metadata.Size {
		return nil, false, errors.New("invalid sequential read")
	}
	s.reads++
	s.maximum = max(s.maximum, length)
	s.offset += length
	b := bytes.Repeat([]byte{1}, int(length))
	if s.short {
		b = b[:len(b)-1]
	}
	s.returned = b
	if s.afterRead != nil {
		s.afterRead()
	}
	return b, !s.noFinal, nil
}
func profileSummaryFixture(t *testing.T) (NativeContextSource, query.ContextProjectionScope, *summarySourceFixture) {
	t.Helper()
	source, scope, _, _ := httpHeaderPageFixture(t)
	e := &source.Expectation
	e.ExecutionClass = artifact.ContextAPIExecution
	e.NodeUID, e.NodeBootID = "", ""
	e.NativeType, e.DataClass = artifact.PprofArtifact, "raw"
	e.Recording = nil
	e.Registration.NativeLimit = 16 << 20
	e.Profile = &artifact.GoProfileAcquisition{SourceRef: "go-pprof-loopback", EndpointDigest: artifact.Digest{2}, Type: "cpu", Mode: "interval", DurationMillis: 10000}
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, query.ProfileSummaryDisplayVersion
	scope.Headers = query.HTTPHeaderWindow{}
	scope.Profile = query.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	if !source.Valid(scope.Version) || !scope.Valid() {
		t.Fatal("invalid fixture", e.Validate())
	}
	return source, scope, &summarySourceFixture{metadata: expectedNativeMetadata(source, 2*artifact.DeliveryBytes+17, artifact.Digest{1})}
}
func consumeProfileSummary(ctx context.Context, r io.Reader, s query.ProfileSummarySelection) (query.ProfileSummary, error) {
	_, err := io.Copy(io.Discard, r)
	return query.ProfileSummary{SampleType: s.SampleType, Unit: "nanoseconds", Top: []query.ProfileHotspot{}, SymbolStatus: "missing"}, err
}
func TestReadProfileSummaryStreamsExactBoundedSource(t *testing.T) {
	source, scope, opened := profileSummaryFixture(t)
	result, err := ReadProfileSummary(t.Context(), opened, source, scope, consumeProfileSummary)
	if err != nil || !result.Valid(scope.Profile) || !opened.closed || opened.offset != opened.metadata.Size || opened.reads < 2 || opened.maximum > artifact.DeliveryBytes {
		t.Fatal("streamed summary", err, opened)
	}
	if !bytes.Equal(opened.returned, make([]byte, len(opened.returned))) {
		t.Fatal("native chunk retained")
	}
}
func TestReadProfileSummaryRefusesPartialCorruptExpiredOrDifferentSource(t *testing.T) {
	for _, name := range []string{"trace", "class", "format", "version", "accepted-limit", "missing-final", "short-read", "canceled-read", "partial-analyzer", "swallowed-error", "wrong-selection"} {
		t.Run(name, func(t *testing.T) {
			source, scope, opened := profileSummaryFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			summarize := ProfileSummarizer(consumeProfileSummary)
			switch name {
			case "trace":
				source.Expectation.NativeType = artifact.GoTraceArtifact
			case "class":
				source.Expectation.DataClass = "metadata"
			case "format":
				opened.metadata.Format = artifact.GoTraceFormat
			case "version":
				scope.Version[0] ^= 1
			case "accepted-limit":
				opened.metadata.Size = source.Expectation.Registration.NativeLimit + 1
			case "missing-final":
				opened.noFinal = true
			case "short-read":
				opened.short = true
			case "canceled-read":
				opened.afterRead = cancel
			case "partial-analyzer":
				summarize = func(context.Context, io.Reader, query.ProfileSummarySelection) (query.ProfileSummary, error) {
					return query.ProfileSummary{SampleType: "cpu", Unit: "nanoseconds", Top: []query.ProfileHotspot{}, SymbolStatus: "missing"}, nil
				}
			case "swallowed-error":
				opened.noFinal = true
				summarize = func(ctx context.Context, r io.Reader, s query.ProfileSummarySelection) (query.ProfileSummary, error) {
					v, _ := consumeProfileSummary(ctx, r, s)
					return v, nil
				}
			case "wrong-selection":
				summarize = func(ctx context.Context, r io.Reader, s query.ProfileSummarySelection) (query.ProfileSummary, error) {
					v, e := consumeProfileSummary(ctx, r, s)
					v.SampleType = "allocs"
					return v, e
				}
			}
			result, err := ReadProfileSummary(ctx, opened, source, scope, summarize)
			if err == nil || result.Top != nil || !opened.closed {
				t.Fatal("refusal", err, opened.closed)
			}
		})
	}
}
func TestProfileSummaryReadFitsTenQueryUnits(t *testing.T) {
	typ, ok := artifact.LookupNativeType(artifact.PprofArtifact)
	work := NativeWindowReadWork(typ) + query.ContextBatchReadWork
	unit := int64(query.ContextMaxReadBatches * query.ContextBatchReadWork)
	if !ok || work <= 9*unit || work > query.ProfileSummaryQueryUnits*unit {
		t.Fatal("profile query funding", work, unit)
	}
}
