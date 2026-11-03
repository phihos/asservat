package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	analysis "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/pprof/profile"
)

func comparisonFixture(names []string, values []int64, seconds int64) *profile.Profile {
	p := validProfile()
	p.Function = nil
	p.Location = nil
	p.Sample = nil
	p.DurationNanos = seconds * int64(time.Second)
	p.Mapping[0].BuildID = "synthetic-build"
	for i, name := range names {
		f := &profile.Function{ID: uint64(i + 1), Name: name, Filename: "SECRET-PATH"}
		l := &profile.Location{ID: uint64(i + 1), Mapping: p.Mapping[0], Line: []profile.Line{{Function: f}}}
		p.Function = append(p.Function, f)
		p.Location = append(p.Location, l)
		p.Sample = append(p.Sample, &profile.Sample{Location: []*profile.Location{l}, Value: []int64{1, values[i]}, Label: map[string][]string{"token": {"SECRET-LABEL"}}})
	}
	p.Comments = []string{"SECRET-COMMENT"}
	p.Mapping[0].File = "SECRET-MAPPING"
	return p
}
func comparisonSelection(t testing.TB, normalization string, n int) analysis.ProfileComparisonSelection {
	t.Helper()
	s, err := analysis.NormalizeProfileComparisonSelection("cpu", normalization, n)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var cpuComparisonFacts = analysis.ProfileComparisonAcquisition{ProfileType: "cpu", Mode: "interval"}

func runComparison(t testing.TB, b, i *profile.Profile, s analysis.ProfileComparisonSelection) (analysis.ProfileComparison, error) {
	t.Helper()
	return ComparePprof(context.Background(), bytes.NewReader(encoded(t, b)), cpuComparisonFacts, bytes.NewReader(encoded(t, i)), cpuComparisonFacts, s)
}

func TestPprofComparisonUsesFullAggregatesBeforeTopN(t *testing.T) {
	b := comparisonFixture([]string{"a", "b", "c"}, []int64{100, 90, 0}, 30)
	i := comparisonFixture([]string{"a", "b", "c"}, []int64{100, 0, 80}, 10)
	// Both standalone top-1 summaries contain only a=100. Their subtraction
	// would invent no change and lose the largest difference b=-90.
	s := comparisonSelection(t, analysis.ProfileComparisonRaw, 1)
	out, err := runComparison(t, b, i, s)
	if err != nil || !out.Valid(s) || len(out.Rows) != 1 || out.Rows[0].Function == nil || *out.Rows[0].Function != "b" || out.Rows[0].Baseline != 90 || out.Rows[0].Incident != 0 || out.Rows[0].Delta != -90 {
		t.Fatal(out, err)
	}
	s.TopN = 100
	out, err = runComparison(t, b, i, s)
	if err != nil || len(out.Rows) != 3 || *out.Rows[1].Function != "c" || out.Rows[1].Baseline != 0 || out.Rows[1].Delta != 80 {
		t.Fatal(out, err)
	}
	before, _ := json.Marshal(out)
	b.Sample[0], b.Sample[2] = b.Sample[2], b.Sample[0]
	i.Sample[0], i.Sample[1] = i.Sample[1], i.Sample[0]
	again, err := runComparison(t, b, i, s)
	after, _ := json.Marshal(again)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("map/input order changed result", err, string(after))
	}
}

func TestPprofComparisonDurationNormalizationAndSignedValues(t *testing.T) {
	b := comparisonFixture([]string{"work"}, []int64{300}, 30)
	i := comparisonFixture([]string{"work"}, []int64{100}, 10)
	s := comparisonSelection(t, analysis.ProfileComparisonRate, 0)
	out, err := runComparison(t, b, i, s)
	if err != nil || out.Unit != "nanoseconds" || out.Normalization != "perSecond" || out.Aggregation != "cumulative" || out.Rows[0].Baseline != 10 || out.Rows[0].Incident != 10 || out.Rows[0].Delta != 0 || *out.Baseline.DurationSeconds != 30 || *out.Incident.DurationSeconds != 10 {
		t.Fatal(out, err)
	}
	s.Normalization = analysis.ProfileComparisonRaw
	out, err = runComparison(t, b, i, s)
	if err != nil || out.Rows[0].Delta != -200 {
		t.Fatal(out, err)
	}
	for _, v := range [][2]int64{{-10, -4}, {10, -4}, {0, 0}, {-10, 10}} {
		b.Sample[0].Value[1], i.Sample[0].Value[1] = v[0], v[1]
		out, err = runComparison(t, b, i, s)
		if err != nil || out.Rows[0].Baseline != float64(v[0]) || out.Rows[0].Delta != float64(v[1]-v[0]) {
			t.Fatal(v, out, err)
		}
	}
}

func TestPprofComparisonBaselineOnlyFunctionsAndDeterministicTies(t *testing.T) {
	b := comparisonFixture([]string{"z", "b"}, []int64{10, 4}, 10)
	i := comparisonFixture([]string{"a"}, []int64{10}, 10)
	s := comparisonSelection(t, analysis.ProfileComparisonRaw, 2)
	out, err := runComparison(t, b, i, s)
	if err != nil || len(out.Rows) != 2 || *out.Rows[0].Function != "a" || *out.Rows[1].Function != "z" || out.Rows[0].Delta != 10 || out.Rows[1].Delta != -10 {
		t.Fatal(out, err)
	}
}

func TestPprofComparisonIncompatibleAndUnknownNativeFacts(t *testing.T) {
	for _, mode := range []string{"units", "missing-sample", "ambiguous-sample", "unknown-baseline-duration", "unknown-incident-duration", "different-family", "state-v-window", "snapshot-rate"} {
		t.Run(mode, func(t *testing.T) {
			b := comparisonFixture([]string{"work"}, []int64{10}, 30)
			i := comparisonFixture([]string{"work"}, []int64{20}, 10)
			bf, ifacts := cpuComparisonFacts, cpuComparisonFacts
			s := comparisonSelection(t, analysis.ProfileComparisonRate, 20)
			switch mode {
			case "units":
				i.SampleType[1].Unit = "bytes"
			case "missing-sample":
				i.SampleType[1].Type = "other"
			case "ambiguous-sample":
				i.SampleType = append(i.SampleType, &profile.ValueType{Type: "cpu", Unit: "nanoseconds"})
				i.Sample[0].Value = append(i.Sample[0].Value, 1)
			case "unknown-baseline-duration":
				b.DurationNanos = 0
			case "unknown-incident-duration":
				i.DurationNanos = 0
			case "different-family":
				ifacts = analysis.ProfileComparisonAcquisition{ProfileType: "mutex", Mode: "delta"}
			case "state-v-window":
				bf = analysis.ProfileComparisonAcquisition{ProfileType: "heap", Mode: "snapshot"}
				ifacts = analysis.ProfileComparisonAcquisition{ProfileType: "allocs", Mode: "delta"}
				s.Normalization = analysis.ProfileComparisonRaw
			case "snapshot-rate":
				bf = analysis.ProfileComparisonAcquisition{ProfileType: "heap", Mode: "snapshot"}
				ifacts = bf
			}
			out, err := ComparePprof(t.Context(), bytes.NewReader(encoded(t, b)), bf, bytes.NewReader(encoded(t, i)), ifacts, s)
			want := analysis.ErrProfileIncompatible
			if mode == "missing-sample" || mode == "ambiguous-sample" {
				want = ErrProfileSampleType
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(out, analysis.ProfileComparison{}) {
				t.Fatal("incompatible inputs emitted partial result", out, err)
			}
		})
	}
	b := comparisonFixture([]string{"work"}, []int64{10}, 0)
	i := comparisonFixture([]string{"work"}, []int64{20}, 0)
	out, err := runComparison(t, b, i, comparisonSelection(t, analysis.ProfileComparisonRaw, 20))
	if err != nil || out.Baseline.DurationSeconds != nil || out.Incident.DurationSeconds != nil {
		t.Fatal("raw comparison invented unknown duration", out, err)
	}
}

func TestPprofComparisonConfigurationChangesAndPrivacy(t *testing.T) {
	b := comparisonFixture([]string{"work"}, []int64{10}, 0)
	i := comparisonFixture([]string{"work"}, []int64{20}, 0)
	b.SampleType[1] = &profile.ValueType{Type: "alloc_space", Unit: "bytes"}
	i.SampleType[1] = &profile.ValueType{Type: "alloc_space", Unit: "bytes"}
	b.Mapping[0].BuildID = "SECRET-BASELINE-BUILD"
	i.Mapping[0].BuildID = "SECRET-INCIDENT-BUILD"
	i.Period = b.Period * 2
	s, _ := analysis.NormalizeProfileComparisonSelection("alloc_space", analysis.ProfileComparisonRaw, 20)
	bf := analysis.ProfileComparisonAcquisition{ProfileType: "heap", Mode: "snapshot", ForceGC: true}
	ifacts := analysis.ProfileComparisonAcquisition{ProfileType: "allocs", Mode: "cumulative"}
	out, err := ComparePprof(t.Context(), bytes.NewReader(encoded(t, b)), bf, bytes.NewReader(encoded(t, i)), ifacts, s)
	if err != nil || !out.Valid(s) || out.BuildStatus != "different" || out.SamplingStatus != "different" || out.AcquisitionStatus != "different" || !out.Baseline.ForceGC || out.Incident.ForceGC {
		t.Fatal("compatible heap counters were rejected or configuration lost", out, err)
	}
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte("SECRET")) {
		t.Fatal("raw native field escaped", string(raw))
	}
	i.Mapping[0].BuildID = ""
	i.Period = 0
	out, err = ComparePprof(t.Context(), bytes.NewReader(encoded(t, b)), bf, bytes.NewReader(encoded(t, i)), ifacts, s)
	if err != nil || out.BuildStatus != "unknown" || out.SamplingStatus != "unknown" || out.Incident.Period != nil {
		t.Fatal(out, err)
	}
}

func TestPprofComparisonUnresolvedSymbolsStayNull(t *testing.T) {
	b := comparisonFixture([]string{"work"}, []int64{10}, 10)
	i := comparisonFixture([]string{"work"}, []int64{20}, 10)
	b.Location[0].Line = nil
	i.Sample[0].Location = nil
	out, err := runComparison(t, b, i, comparisonSelection(t, analysis.ProfileComparisonRaw, 20))
	if err != nil || out.Baseline.SymbolStatus != "missing" || out.Incident.SymbolStatus != "missing" || len(out.Rows) != 1 || out.Rows[0].Function != nil || out.Rows[0].Delta != 10 || !strings.Contains(strings.Join(out.Limitations, " "), "null function bucket") {
		t.Fatal(out, err)
	}
}

func TestPprofComparisonEmptyInputsHaveExplicitEmptyRows(t *testing.T) {
	b, i := comparisonFixture(nil, nil, 0), comparisonFixture(nil, nil, 0)
	s := comparisonSelection(t, analysis.ProfileComparisonRaw, 20)
	out, err := runComparison(t, b, i, s)
	if err != nil || !out.Valid(s) || out.Rows == nil || len(out.Rows) != 0 || out.Baseline.Total != 0 || out.Baseline.DurationSeconds != nil || out.Incident.SymbolStatus != "missing" {
		t.Fatal(out, err)
	}
}

type comparisonEOFReader struct {
	io.Reader
	eof        bool
	beforeRead func()
}

func (r *comparisonEOFReader) Read(p []byte) (int, error) {
	if r.beforeRead != nil {
		r.beforeRead()
	}
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		r.eof = true
	}
	return n, err
}

func TestPprofComparisonSequentialReadAndMalformedTail(t *testing.T) {
	native := encoded(t, comparisonFixture([]string{"work"}, []int64{1}, 10))
	s := comparisonSelection(t, analysis.ProfileComparisonRaw, 20)
	b := &comparisonEOFReader{Reader: bytes.NewReader(native)}
	i := &comparisonEOFReader{Reader: bytes.NewReader(native), beforeRead: func() {
		if !b.eof {
			t.Fatal("second profile read before complete first EOF")
		}
	}}
	if _, err := ComparePprof(t.Context(), b, cpuComparisonFacts, i, cpuComparisonFacts, s); err != nil || !i.eof {
		t.Fatal("sequential full native read", err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(native), 0), native[:len(native)-3], append(bytes.Clone(native), native...)} {
		out, err := ComparePprof(t.Context(), bytes.NewReader(native), cpuComparisonFacts, bytes.NewReader(bad), cpuComparisonFacts, s)
		if err == nil || !reflect.DeepEqual(out, analysis.ProfileComparison{}) {
			t.Fatal("malformed second tail yielded first-source result", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out, err := ComparePprof(ctx, bytes.NewReader(native), cpuComparisonFacts, bytes.NewReader(native), cpuComparisonFacts, s)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, analysis.ProfileComparison{}) {
		t.Fatal(out, err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	i = &comparisonEOFReader{Reader: bytes.NewReader(native), beforeRead: cancel}
	out, err = ComparePprof(ctx, bytes.NewReader(native), cpuComparisonFacts, i, cpuComparisonFacts, s)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, analysis.ProfileComparison{}) {
		t.Fatal("cancellation during second parse yielded partial data", out, err)
	}
}

func TestPprofComparisonRefusesUnsafeDeltasAndOversizedResults(t *testing.T) {
	b := comparisonFixture([]string{"work"}, []int64{-analysis.ProfileSummaryMaximumValue}, 10)
	i := comparisonFixture([]string{"work"}, []int64{analysis.ProfileSummaryMaximumValue}, 10)
	out, err := runComparison(t, b, i, comparisonSelection(t, analysis.ProfileComparisonRaw, 20))
	if !errors.Is(err, artifact.ErrLimit) || !reflect.DeepEqual(out, analysis.ProfileComparison{}) {
		t.Fatal("unsafe delta escaped", out, err)
	}
	var names []string
	var values []int64
	for n := range 100 {
		names = append(names, fmt.Sprintf("%03d%s", n, strings.Repeat("<", 509)))
		values = append(values, 1)
	}
	b = comparisonFixture(names, values, 10)
	i = comparisonFixture(names, values, 10)
	out, err = runComparison(t, b, i, comparisonSelection(t, analysis.ProfileComparisonRaw, 100))
	if !errors.Is(err, artifact.ErrLimit) || !reflect.DeepEqual(out, analysis.ProfileComparison{}) {
		t.Fatal("oversized selected comparison was trimmed or emitted", err)
	}
}

// Local parser/aggregate cost only: native authentication, keys, worker cgroup
// and SQL are deliberately outside this microbenchmark's evidence boundary.
func BenchmarkPprofComparisonFullAggregates(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("functions-%d", n), func(b *testing.B) {
			names, values := make([]string, n), make([]int64, n)
			for i := range names {
				names[i] = fmt.Sprintf("synthetic.function.%05d", i)
				values[i] = int64(i % 100)
			}
			baseline := encoded(b, comparisonFixture(names, values, 30))
			incident := encoded(b, comparisonFixture(names, values, 10))
			s := comparisonSelection(b, analysis.ProfileComparisonRate, 20)
			b.ReportAllocs()
			b.SetBytes(int64(len(baseline) + len(incident)))
			b.ResetTimer()
			b.ReportMetric(float64(len(baseline)+len(incident)), "native-bytes/op")
			for range b.N {
				if _, err := ComparePprof(context.Background(), bytes.NewReader(baseline), cpuComparisonFacts, bytes.NewReader(incident), cpuComparisonFacts, s); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
