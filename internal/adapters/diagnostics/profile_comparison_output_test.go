package diagnostics

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func TestPprofComparisonOutputSizeIsDistinctFromInputLimits(t *testing.T) {
	names, values := make([]string, 100), make([]int64, 100)
	for n := range names {
		names[n] = fmt.Sprintf("%03d.%s", n, strings.Repeat("<", 508))
		values[n] = 1
	}
	b := comparisonFixture(names, values, 1)
	selection := comparisonSelection(t, query.ProfileComparisonRaw, 100)
	result, err := runComparison(t, b, b, selection)
	if !errors.Is(err, query.ErrRecordTooLarge) || errors.Is(err, artifact.ErrLimit) || result.Rows != nil {
		t.Fatal("output size was not identified distinctly", err)
	}
	// Input preallocation/shape limits must remain unavailable, not a request
	// to select fewer output rows. This shape stops before protobuf allocation.
	input := bytes.Repeat(wireBytes(5, nil), MaxPprofFunctions+1)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = ComparePprof(context.Background(), bytes.NewReader(compressed.Bytes()), cpuComparisonFacts, bytes.NewReader(encoded(t, b)), cpuComparisonFacts, selection)
	if !errors.Is(err, artifact.ErrLimit) || errors.Is(err, query.ErrRecordTooLarge) {
		t.Fatal("input limit became output-size refusal", err)
	}
	malformed := append(encoded(t, b), 0xff)
	_, err = ComparePprof(context.Background(), bytes.NewReader(malformed), cpuComparisonFacts, bytes.NewReader(encoded(t, b)), cpuComparisonFacts, selection)
	if err == nil || errors.Is(err, query.ErrRecordTooLarge) {
		t.Fatal("malformed tail became output-size refusal", err)
	}
}
