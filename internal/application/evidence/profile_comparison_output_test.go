package evidence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func TestComparisonOutputSizeRequiresBothFinalAuthenticationAndCleanup(t *testing.T) {
	for _, mode := range []string{"complete", "full-result", "baseline-final", "incident-final", "partial", "cancel-close", "input-limit"} {
		t.Run(mode, func(t *testing.T) {
			b, bo := comparisonReadFixture(t)
			i, ioSource := comparisonReadFixture(t)
			b.Scope.Profile.TopN, i.Scope.Profile.TopN = 100, 100
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "baseline-final" {
				bo.noFinal = true
			}
			if mode == "incident-final" {
				ioSource.noFinal = true
			}
			var closing *comparisonCloseCancels
			if mode == "cancel-close" {
				closing = &comparisonCloseCancels{NativeArtifactSource: i.Opened, cancel: cancel}
				i.Opened = closing
			}
			compare := func(ctx context.Context, br io.Reader, bf query.ProfileComparisonAcquisition, ir io.Reader, inf query.ProfileComparisonAcquisition, s query.ProfileComparisonSelection) (query.ProfileComparison, error) {
				var full query.ProfileComparison
				if mode != "partial" {
					full, _ = consumeProfileComparison(ctx, br, bf, ir, inf, s)
				}
				if mode == "full-result" {
					full.Baseline.SymbolStatus, full.Incident.SymbolStatus = "complete", "complete"
					full.Baseline.Total, full.Incident.Total = 100, 100
					for n := range 100 {
						name := fmt.Sprintf("%03d.%s", n, strings.Repeat("x", 508))
						full.Rows = append(full.Rows, query.ProfileComparisonRow{Function: &name, Baseline: 1, Incident: 1})
					}
					return full, nil
				}
				if mode == "input-limit" {
					return query.ProfileComparison{}, artifact.ErrLimit
				}
				return query.ProfileComparison{}, query.ErrRecordTooLarge
			}
			result, err := ReadProfileComparison(ctx, b, i, query.ProfileComparisonSelection{SampleType: "cpu", Normalization: query.ProfileComparisonRaw, TopN: 100}, compare)
			if errors.Is(err, query.ErrRecordTooLarge) != (mode == "complete" || mode == "full-result") || err == nil || result.Rows != nil || !bo.closed || !ioSource.closed {
				t.Fatal("unverified size refusal escaped", err, bo.closed, ioSource.closed)
			}
			if closing != nil && closing.closes != 1 {
				t.Fatal("source cleanup repeated", closing.closes)
			}
		})
	}
}
