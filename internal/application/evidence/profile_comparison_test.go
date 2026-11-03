package evidence

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func comparisonReadFixture(t *testing.T) (ProfileComparisonSource, *summarySourceFixture) {
	t.Helper()
	source, scope, opened := profileSummaryFixture(t)
	return ProfileComparisonSource{Opened: opened, Source: source, Scope: scope}, opened
}

func consumeProfileComparison(ctx context.Context, b io.Reader, bf query.ProfileComparisonAcquisition, i io.Reader, inf query.ProfileComparisonAcquisition, s query.ProfileComparisonSelection) (query.ProfileComparison, error) {
	if _, err := io.Copy(io.Discard, b); err != nil {
		return query.ProfileComparison{}, err
	}
	if _, err := io.Copy(io.Discard, i); err != nil {
		return query.ProfileComparison{}, err
	}
	return query.ProfileComparison{SampleType: s.SampleType, Unit: "nanoseconds", Normalization: s.Normalization, Aggregation: "cumulative", Comparable: true,
		Baseline: query.ProfileComparisonFacts{ProfileComparisonAcquisition: bf, SymbolStatus: "missing"}, Incident: query.ProfileComparisonFacts{ProfileComparisonAcquisition: inf, SymbolStatus: "missing"},
		BuildStatus: "unknown", SamplingStatus: "unknown", AcquisitionStatus: "same", Rows: []query.ProfileComparisonRow{}, Limitations: []string{"Synthetic test aggregate."}}, nil
}

func TestReadProfileComparisonAuthenticatesAndClosesBothSources(t *testing.T) {
	b, bo := comparisonReadFixture(t)
	i, incidentOpened := comparisonReadFixture(t)
	s := query.ProfileComparisonSelection{SampleType: "cpu", Normalization: "none", TopN: 20}
	result, err := ReadProfileComparison(t.Context(), b, i, s, consumeProfileComparison)
	if err != nil || !result.Valid(s) || !bo.closed || !incidentOpened.closed || bo.offset != bo.metadata.Size || incidentOpened.offset != incidentOpened.metadata.Size {
		t.Fatal("comparison", result, err, bo, incidentOpened)
	}
}

func TestReadProfileComparisonRefusesEitherIncompleteSource(t *testing.T) {
	for _, side := range []string{"baseline", "incident"} {
		for _, fault := range []string{"absent", "format", "version", "accepted-limit", "missing-final", "short-read", "partial-analyzer", "swallowed-error", "canceled-read", "acquisition", "acquisition-output", "selection", "mismatch-before-completion", "native-etag", "native-filename", "native-coverage", "native-access", "native-deletion"} {
			t.Run(side+"/"+fault, func(t *testing.T) {
				b, bo := comparisonReadFixture(t)
				i, incidentOpened := comparisonReadFixture(t)
				target, opened := &b, bo
				if side == "incident" {
					target, opened = &i, incidentOpened
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				compare := ProfileComparer(consumeProfileComparison)
				switch fault {
				case "absent":
					target.Opened = nil
				case "format":
					opened.metadata.Format = artifact.GoTraceFormat
				case "version":
					target.Scope.Version[0] ^= 1
				case "accepted-limit":
					opened.metadata.Size = target.Source.Expectation.Registration.NativeLimit + 1
				case "native-etag":
					opened.metadata.ETag = `"different-copies"`
				case "native-filename":
					opened.metadata.Filename = "another-artifact.pb.gz"
				case "native-coverage":
					opened.metadata.Coverage = "Different source coverage."
				case "native-access":
					opened.metadata.ReadUntil = opened.metadata.ReadUntil.Add(-time.Second)
				case "native-deletion":
					opened.metadata.DeleteBy = opened.metadata.DeleteBy.Add(-time.Second)
				case "missing-final":
					opened.noFinal = true
				case "short-read":
					opened.short = true
				case "partial-analyzer":
					compare = func(ctx context.Context, _ io.Reader, bf query.ProfileComparisonAcquisition, _ io.Reader, inf query.ProfileComparisonAcquisition, s query.ProfileComparisonSelection) (query.ProfileComparison, error) {
						return consumeProfileComparison(ctx, &emptyReader{}, bf, &emptyReader{}, inf, s)
					}
				case "swallowed-error":
					opened.noFinal = true
					compare = func(ctx context.Context, br io.Reader, bf query.ProfileComparisonAcquisition, ir io.Reader, inf query.ProfileComparisonAcquisition, s query.ProfileComparisonSelection) (query.ProfileComparison, error) {
						_, _ = consumeProfileComparison(ctx, br, bf, ir, inf, s)
						return consumeProfileComparison(ctx, &emptyReader{}, bf, &emptyReader{}, inf, s)
					}
				case "canceled-read":
					opened.afterRead = cancel
				case "acquisition":
					target.Source.Expectation.Profile = nil
				case "acquisition-output":
					compare = func(ctx context.Context, br io.Reader, bf query.ProfileComparisonAcquisition, ir io.Reader, inf query.ProfileComparisonAcquisition, s query.ProfileComparisonSelection) (query.ProfileComparison, error) {
						out, e := consumeProfileComparison(ctx, br, bf, ir, inf, s)
						out.Baseline.ForceGC = true
						return out, e
					}
				case "selection":
					target.Scope.Profile.SampleType = "alloc_space"
				case "mismatch-before-completion":
					compare = func(context.Context, io.Reader, query.ProfileComparisonAcquisition, io.Reader, query.ProfileComparisonAcquisition, query.ProfileComparisonSelection) (query.ProfileComparison, error) {
						return query.ProfileComparison{}, query.ErrProfileIncompatible
					}
				}
				s := query.ProfileComparisonSelection{SampleType: "cpu", Normalization: "none", TopN: 20}
				result, err := ReadProfileComparison(ctx, b, i, s, compare)
				if err == nil || errors.Is(err, query.ErrProfileIncompatible) || result.Rows != nil || !bo.closed && b.Opened != nil || !incidentOpened.closed && i.Opened != nil {
					t.Fatal("invalid comparison escaped", result, err, bo.closed, incidentOpened.closed)
				}
			})
		}
	}
}

type comparisonCloseCancels struct {
	NativeArtifactSource
	cancel context.CancelFunc
	closes int
}

func (s *comparisonCloseCancels) Close() {
	s.closes++
	s.NativeArtifactSource.Close()
	s.cancel()
}

func TestReadProfileComparisonCancellationDuringCleanup(t *testing.T) {
	for _, side := range []string{"baseline", "incident"} {
		for _, outcome := range []string{"result", "mismatch"} {
			t.Run(side+"/"+outcome, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				b, bo := comparisonReadFixture(t)
				i, incidentOpened := comparisonReadFixture(t)
				target := &b
				if side == "incident" {
					target = &i
				}
				closed := &comparisonCloseCancels{NativeArtifactSource: target.Opened, cancel: cancel}
				target.Opened = closed
				compare := ProfileComparer(consumeProfileComparison)
				if outcome == "mismatch" {
					compare = func(ctx context.Context, br io.Reader, bf query.ProfileComparisonAcquisition, ir io.Reader, inf query.ProfileComparisonAcquisition, s query.ProfileComparisonSelection) (query.ProfileComparison, error) {
						if _, err := consumeProfileComparison(ctx, br, bf, ir, inf, s); err != nil {
							return query.ProfileComparison{}, err
						}
						return query.ProfileComparison{}, query.ErrProfileIncompatible
					}
				}
				selection := query.ProfileComparisonSelection{SampleType: "cpu", Normalization: "none", TopN: 20}
				result, err := ReadProfileComparison(ctx, b, i, selection, compare)
				if err == nil || errors.Is(err, query.ErrProfileIncompatible) || result.Rows != nil || ctx.Err() == nil || closed.closes != 1 || !bo.closed || !incidentOpened.closed || bo.offset != bo.metadata.Size || incidentOpened.offset != incidentOpened.metadata.Size {
					t.Fatal("cleanup released an expired result or mismatched close", result, err, closed.closes, bo, incidentOpened)
				}
			})
		}
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestReadProfileComparisonMismatchRequiresBothFinalHashes(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt"}[corrupt], func(t *testing.T) {
			b, bo := comparisonReadFixture(t)
			i, incidentOpened := comparisonReadFixture(t)
			incidentOpened.noFinal = corrupt
			compare := func(ctx context.Context, br io.Reader, bf query.ProfileComparisonAcquisition, ir io.Reader, inf query.ProfileComparisonAcquisition, s query.ProfileComparisonSelection) (query.ProfileComparison, error) {
				_, _ = consumeProfileComparison(ctx, br, bf, ir, inf, s)
				return query.ProfileComparison{}, query.ErrProfileIncompatible
			}
			s := query.ProfileComparisonSelection{SampleType: "cpu", Normalization: "none", TopN: 20}
			_, err := ReadProfileComparison(t.Context(), b, i, s, compare)
			if errors.Is(err, query.ErrProfileIncompatible) == corrupt || !bo.closed || !incidentOpened.closed {
				t.Fatal("mismatch authentication", err)
			}
		})
	}
}
