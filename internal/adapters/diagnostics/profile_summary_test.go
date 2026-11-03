package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	analysis "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/pprof/profile"
)

func summarySelection(t testing.TB, sample string, n int) analysis.ProfileSummarySelection {
	t.Helper()
	s, err := analysis.NormalizeProfileSummarySelection(sample, n)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func summaryFixture() *profile.Profile {
	p := validProfile()
	p.Function[0].Name = "leaf"
	inline := &profile.Function{ID: 2, Name: "inlineParent", Filename: "SECRET-PATH"}
	root := &profile.Function{ID: 3, Name: "root"}
	p.Function = append(p.Function, inline, root)
	p.Location[0].Line = append(p.Location[0].Line, profile.Line{Function: inline})
	rootLoc := &profile.Location{ID: 2, Mapping: p.Mapping[0], Line: []profile.Line{{Function: root}}}
	recursion := &profile.Location{ID: 3, Mapping: p.Mapping[0], Line: []profile.Line{{Function: p.Function[0]}}}
	p.Location = append(p.Location, rootLoc, recursion)
	p.Sample = []*profile.Sample{
		{Location: []*profile.Location{p.Location[0], rootLoc, recursion}, Value: []int64{2, 10}, Label: map[string][]string{"token": {"SECRET-LABEL"}}, NumLabel: map[string][]int64{"SECRET-NUMERIC-LABEL": {123}}},
		{Location: []*profile.Location{rootLoc}, Value: []int64{1, 5}},
	}
	p.Comments = []string{"SECRET-COMMENT"}
	p.Mapping[0].File = "SECRET-MAPPING"
	p.Mapping[0].BuildID = "SECRET-BUILD"
	return p
}

func TestPprofSummaryInlineRecursionAndPrivacy(t *testing.T) {
	p := summaryFixture()
	s := summarySelection(t, "cpu", 0)
	got, err := SummarizePprof(t.Context(), bytes.NewReader(encoded(t, p)), s)
	if err != nil || !got.Valid(s) {
		t.Fatal(got, err)
	}
	if got.Total != 15 || got.Unit != "nanoseconds" || got.DurationSeconds == nil || *got.DurationSeconds != 10 || got.SymbolStatus != "complete" || len(got.Top) != 3 {
		t.Fatal(got)
	}
	for i, want := range []struct {
		name      string
		flat, cum int64
	}{{"root", 5, 15}, {"leaf", 10, 10}, {"inlineParent", 0, 10}} {
		h := got.Top[i]
		if h.Function == nil || *h.Function != want.name || h.Flat != want.flat || h.Cumulative != want.cum || h.Fraction == nil || *h.Fraction != float64(want.flat)/15 {
			t.Fatal(i, h)
		}
	}
	raw, _ := json.Marshal(got)
	if bytes.Contains(raw, []byte("SECRET")) {
		t.Fatal("nonapproved fields escaped", string(raw))
	}
	// Selecting another type preserves its unit and values, without implicit scaling.
	counts, err := SummarizePprof(t.Context(), bytes.NewReader(encoded(t, p)), summarySelection(t, "samples", 1))
	if err != nil || counts.Total != 3 || counts.Unit != "count" || len(counts.Top) != 1 {
		t.Fatal(counts, err)
	}
	// Input ordering must not change ties or the bounded top-N selection.
	p.Sample[0], p.Sample[1] = p.Sample[1], p.Sample[0]
	again, err := SummarizePprof(t.Context(), bytes.NewReader(encoded(t, p)), s)
	other, _ := json.Marshal(again)
	if err != nil || !bytes.Equal(raw, other) {
		t.Fatal("unstable summary", err, string(other))
	}
}

func TestPprofSummarySignedZeroAndMissingSymbols(t *testing.T) {
	for _, values := range [][2]int64{{10, -10}, {10, -5}, {-10, -5}, {0, 0}, {10, 5}} {
		p := summaryFixture()
		p.Sample[0].Value[1], p.Sample[1].Value[1] = values[0], values[1]
		s := summarySelection(t, "cpu", 100)
		got, err := SummarizePprof(t.Context(), bytes.NewReader(encoded(t, p)), s)
		if err != nil || got.Total != values[0]+values[1] || !got.Valid(s) {
			t.Fatal(values, got, err)
		}
		defined := values[0] >= 0 && values[1] >= 0 && got.Total > 0
		for _, h := range got.Top {
			if (h.Fraction != nil) != defined {
				t.Fatal("undefined fraction misrepresented", values, h)
			}
		}
	}
	for _, mode := range []string{"stripped", "empty-stack", "mixed", "empty-profile"} {
		p := summaryFixture()
		p.DurationNanos = 0
		switch mode {
		case "stripped":
			for _, l := range p.Location {
				l.Line = nil
			}
		case "empty-stack":
			for _, s := range p.Sample {
				s.Location = nil
			}
		case "mixed":
			p.Location[0].Line = nil
		case "empty-profile":
			p.Sample = nil
		}
		s := summarySelection(t, "cpu", 20)
		got, err := SummarizePprof(t.Context(), bytes.NewReader(encoded(t, p)), s)
		if err != nil || !got.Valid(s) || got.DurationSeconds != nil {
			t.Fatal(mode, got, err)
		}
		want := "missing"
		if mode == "mixed" {
			want = "partial"
		}
		if got.SymbolStatus != want {
			t.Fatal(mode, got)
		}
		if mode == "empty-profile" && (len(got.Top) != 0 || got.Total != 0) {
			t.Fatal(got)
		}
	}
}

func TestPprofSummaryRefusesUnsupportedSelectionsAndValues(t *testing.T) {
	for name, change := range map[string]func(*profile.Profile){
		"ambiguous-type": func(p *profile.Profile) { p.SampleType[0].Type = "cpu" },
		"overflow": func(p *profile.Profile) {
			p.Sample[0].Value[1] = analysis.ProfileSummaryMaximumValue
			p.Sample[1].Value[1] = 1
		},
		"nonexact-value": func(p *profile.Profile) { p.Sample[0].Value[1] = analysis.ProfileSummaryMaximumValue + 1 },
		"name-control":   func(p *profile.Profile) { p.Function[0].Name = "leaf\nsecret" },
		"name-limit":     func(p *profile.Profile) { p.Function[0].Name = strings.Repeat("x", 513) },
	} {
		t.Run(name, func(t *testing.T) {
			p := summaryFixture()
			change(p)
			got, err := SummarizePprof(t.Context(), bytes.NewReader(encoded(t, p)), summarySelection(t, "cpu", 20))
			if err == nil || got.Top != nil {
				t.Fatal("unsupported profile returned result", got, err)
			}
		})
	}
	if _, err := SummarizePprof(t.Context(), bytes.NewReader(encoded(t, validProfile())), summarySelection(t, "absent", 20)); !errors.Is(err, ErrProfileSampleType) {
		t.Fatal(err)
	}
	for _, input := range [][]byte{[]byte("not gzip"), append(encoded(t, validProfile()), 0), gzipped(t, bytes.Repeat([]byte{0}, int(artifact.MaxPprofDecompressedBytes+1)))} {
		if got, err := SummarizePprof(t.Context(), bytes.NewReader(input), summarySelection(t, "cpu", 20)); err == nil || got.Top != nil {
			t.Fatal("invalid stream returned result", err)
		}
	}
}

func TestPprofSummaryWorkAndOutputLimits(t *testing.T) {
	s := summarySelection(t, "cpu", 100)
	for _, mode := range []string{"samples", "locations", "functions", "sample-frames", "total-frames", "output"} {
		t.Run(mode, func(t *testing.T) {
			p := validProfile()
			switch mode {
			case "samples":
				p.Sample = make([]*profile.Sample, MaxSummarySamples+1)
			case "locations":
				p.Location = make([]*profile.Location, MaxSummaryLocations+1)
			case "functions":
				p.Function = make([]*profile.Function, MaxSummaryFunctions+1)
			case "sample-frames":
				for range MaxSummarySampleFrames {
					p.Sample[0].Location = append(p.Sample[0].Location, p.Location[0])
				}
			case "total-frames":
				sample := p.Sample[0]
				sample.Location = make([]*profile.Location, MaxSummarySampleFrames)
				for i := range sample.Location {
					sample.Location[i] = p.Location[0]
				}
				p.Sample = make([]*profile.Sample, MaxSummaryFrameVisits/MaxSummarySampleFrames+1)
				for i := range p.Sample {
					p.Sample[i] = sample
				}
			case "output":
				p.Sample = nil
				p.Location = nil
				p.Function = nil
				for i := range 100 {
					f := &profile.Function{ID: uint64(i + 1), Name: fmt.Sprintf("%03d%s", i, strings.Repeat("x", 509))}
					l := &profile.Location{ID: uint64(i + 1), Line: []profile.Line{{Function: f}}}
					p.Function = append(p.Function, f)
					p.Location = append(p.Location, l)
					p.Sample = append(p.Sample, &profile.Sample{Location: []*profile.Location{l}, Value: []int64{1, 1}})
				}
			}
			got, err := summarizePprof(t.Context(), p, s)
			if !errors.Is(err, artifact.ErrLimit) || got.Top != nil {
				t.Fatal("bound not enforced", mode, got, err)
			}
		})
	}
}

type cancelSummaryReader struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (r cancelSummaryReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	r.cancel()
	return n, e
}
func TestPprofSummaryCancellationReturnsNoResult(t *testing.T) {
	for _, before := range []bool{true, false} {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var r io.Reader = bytes.NewReader(encoded(t, validProfile()))
		if before {
			cancel()
		} else {
			r = cancelSummaryReader{r, cancel}
		}
		got, err := SummarizePprof(ctx, r, summarySelection(t, "cpu", 20))
		if !errors.Is(err, context.Canceled) || got.Top != nil {
			t.Fatal(got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := summarizePprof(ctx, validProfile(), summarySelection(t, "cpu", 20)); !errors.Is(err, context.Canceled) || got.Top != nil {
		t.Fatal(got, err)
	}
}

func FuzzPprofSummary(f *testing.F) {
	f.Add(encoded(f, summaryFixture()), "cpu", uint8(20))
	f.Add(encoded(f, validProfile()), "samples", uint8(1))
	f.Add([]byte("invalid"), "cpu", uint8(100))
	f.Fuzz(func(t *testing.T, input []byte, sample string, top uint8) {
		if len(input) > 64<<10 {
			return
		}
		s, err := analysis.NormalizeProfileSummarySelection(sample, int(top))
		if err != nil {
			return
		}
		got, err := SummarizePprof(t.Context(), bytes.NewReader(input), s)
		if err != nil {
			if got.Top != nil {
				t.Fatal("failure leaked a partial result")
			}
			return
		}
		if !got.Valid(s) {
			t.Fatal("invalid result")
		}
		again, err := SummarizePprof(t.Context(), bytes.NewReader(input), s)
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(again)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("nondeterministic result", err)
		}
	})
}
