package diagnostics

import (
	"bytes"
	"errors"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestPprofAllocationRejectsValidLabelAmplification(t *testing.T) {
	p := validProfile()
	p.Sample[0].Label = map[string][]string{"synthetic": make([]string, 1000000)}
	for i := range p.Sample[0].Label["synthetic"] {
		p.Sample[0].Label["synthetic"][i] = "value"
	}
	if err := p.CheckValid(); err != nil {
		t.Fatal(err)
	}
	if err := CheckPprof(bytes.NewReader(encoded(t, p))); !errors.Is(err, artifact.ErrLimit) {
		t.Fatalf("valid oversized labels must refuse before parser allocation: %v", err)
	}
}

// Helpers encode wire shapes only; semantic interpretation remains pprof's job.
func wireBytes(field protowire.Number, p []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, field, protowire.BytesType), p)
}
func wireVarint(field protowire.Number, v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, field, protowire.VarintType), v)
}

func TestPprofPreflightShapeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field protowire.Number
		limit int
	}{
		{"sample types", 1, maxPprofSampleTypes}, {"samples", 2, MaxPprofSamples}, {"mappings", 3, MaxPprofMappings},
		{"locations", 4, MaxPprofLocations}, {"functions", 5, MaxPprofFunctions}, {"strings", 6, MaxPprofStrings}, {"period allocations", 11, maxPprofSampleTypes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := wireBytes(tc.field, nil)
			if err := preflightPprof(bytes.Repeat(record, tc.limit)); err != nil {
				t.Fatal("at limit", err)
			}
			if err := preflightPprof(bytes.Repeat(record, tc.limit+1)); !errors.Is(err, artifact.ErrLimit) {
				t.Fatal("above limit", err)
			}
		})
	}
	for _, tc := range []struct {
		name          string
		parent, field protowire.Number
		limit         int
		message       bool
	}{
		{"sample labels", 2, 3, MaxPprofSampleLabels, true}, {"sample locations", 2, 1, MaxPprofSampleLocations, false},
		{"sample values", 2, 2, maxPprofSampleTypes, false}, {"location lines", 4, 4, MaxPprofLocationLines, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := wireVarint(tc.field, 1)
			if tc.message {
				record = wireBytes(tc.field, nil)
			}
			for _, extra := range []int{0, 1} {
				err := preflightPprof(wireBytes(tc.parent, bytes.Repeat(record, tc.limit+extra)))
				if extra == 0 && err != nil || extra == 1 && !errors.Is(err, artifact.ErrLimit) {
					t.Fatal(extra, err)
				}
			}
		})
	}
	for _, tc := range []struct {
		name          string
		parent, field protowire.Number
		per, total    int
		message       bool
	}{
		{"aggregate labels", 2, 3, MaxPprofSampleLabels, MaxPprofLabels, true},
		{"aggregate locations", 2, 1, MaxPprofSampleLocations, MaxPprofLocationReferences, false},
		{"aggregate lines", 4, 4, MaxPprofLocationLines, MaxPprofLines, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := wireVarint(tc.field, 1)
			if tc.message {
				item = wireBytes(tc.field, nil)
			}
			record := wireBytes(tc.parent, bytes.Repeat(item, tc.per))
			data := bytes.Repeat(record, tc.total/tc.per)
			if rem := tc.total % tc.per; rem > 0 {
				data = append(data, wireBytes(tc.parent, bytes.Repeat(item, rem))...)
			}
			if err := preflightPprof(data); err != nil {
				t.Fatal("at aggregate limit", err)
			}
			data = append(data, wireBytes(tc.parent, item)...)
			if err := preflightPprof(data); !errors.Is(err, artifact.ErrLimit) {
				t.Fatal("above aggregate limit", err)
			}
		})
	}
}

func TestPprofPreflightPackedSplitAndMalformed(t *testing.T) {
	for _, field := range []protowire.Number{1, 2, 13} {
		limit := maxPprofSampleTypes
		parent := protowire.Number(2)
		if field == 1 {
			limit = MaxPprofSampleLocations
		}
		if field == 13 {
			limit = MaxPprofComments
			parent = 0
		}
		wrap := func(b []byte) []byte {
			if parent != 0 {
				return wireBytes(parent, b)
			}
			return b
		}
		for _, extra := range []int{0, 1} {
			data := wireBytes(field, bytes.Repeat([]byte{0}, limit-1))
			data = append(data, wireVarint(field, 0)...)
			if extra == 1 {
				data = append(data, wireBytes(field, []byte{0})...)
			}
			err := preflightPprof(wrap(data))
			if extra == 0 && err != nil || extra == 1 && !errors.Is(err, artifact.ErrLimit) {
				t.Fatal(field, extra, err)
			}
		}
	}
	for name, data := range map[string][]byte{
		"bad tag": {0}, "truncated tag": {128}, "truncated length": {18, 128}, "oversize length": {18, 10},
		"truncated varint": wireBytes(2, []byte{16, 128}), "packed bad varint": wireBytes(2, wireBytes(2, []byte{128})),
		"packed wrong type": wireBytes(2, []byte{17, 0, 0, 0, 0, 0, 0, 0, 0}), "table wrong type": wireVarint(2, 1),
		"label wrong type": wireBytes(2, wireVarint(3, 1)), "line wrong type": wireBytes(4, wireVarint(4, 1)),
		"group": {0x1b, 0x1c}, "unknown group": {0xfb, 1, 0xfc, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := preflightPprof(data); !errors.Is(err, ErrNotProfile) {
				t.Fatal(err)
			}
		})
	}
	// Unknown ordinary wire fields remain ignored, matching the pinned library.
	for _, data := range [][]byte{wireBytes(99, []byte{0x80}), wireVarint(99, 1), {0x99, 6, 0, 0, 0, 0, 0, 0, 0, 0}, {0x9d, 6, 0, 0, 0, 0}} {
		if err := preflightPprof(data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPprofPreflightPreservesSemanticChecksAndAllocatesNoTables(t *testing.T) {
	p := validProfile()
	p.Sample[0].Label = map[string][]string{"synthetic": make([]string, MaxPprofSampleLabels)}
	for i := range p.Sample[0].Label["synthetic"] {
		p.Sample[0].Label["synthetic"][i] = "value"
	}
	if err := CheckPprof(bytes.NewReader(encoded(t, p))); err != nil {
		t.Fatal(err)
	}
	p.Sample[0].Location[0].ID = 0
	if err := CheckPprof(bytes.NewReader(encoded(t, p))); !errors.Is(err, ErrNotProfile) {
		t.Fatal("library must reject bad ID", err)
	}
	data := bytes.Repeat(wireBytes(2, wireVarint(2, 1)), 1000)
	if got := testing.AllocsPerRun(100, func() {
		if err := preflightPprof(data); err != nil {
			panic(err)
		}
	}); got != 0 {
		t.Fatal("preflight allocates", got)
	}
}

func FuzzPprofPreflight(f *testing.F) {
	f.Add([]byte{18, 2, 16, 1})
	f.Add(wireBytes(2, wireBytes(3, wireVarint(1, 1))))
	f.Add(wireBytes(4, wireBytes(4, wireVarint(1, 1))))
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		err := preflightPprof(data)
		if err != nil && !errors.Is(err, ErrNotProfile) && !errors.Is(err, artifact.ErrLimit) {
			t.Fatal(err)
		}
		if err == nil {
			_ = CheckPprof(bytes.NewReader(gzipped(t, data)))
		}
	})
}
