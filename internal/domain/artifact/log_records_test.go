package artifact

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestLogRecordValuesRemainRawAndClosed(t *testing.T) {
	data := []byte{0xff, 0, 0xfe, '\n'}
	f := LogFragment{Record: "fragment", Line: 1, EndLine: true, Data: base64.StdEncoding.EncodeToString(data)}
	raw, err := f.Bytes()
	if err != nil || string(raw) != string(data) {
		t.Fatal("raw bytes changed", err)
	}
	for name, change := range map[string]func(*LogFragment){"empty": func(f *LogFragment) { f.Data = "" }, "oversize": func(f *LogFragment) { f.Data = base64.StdEncoding.EncodeToString(make([]byte, LogMaxFragmentBytes+1)) }, "lineZero": func(f *LogFragment) { f.Line = 0 }, "inventedEnd": func(f *LogFragment) { f.EndLine = false }, "newlineInside": func(f *LogFragment) { f.Data = base64.StdEncoding.EncodeToString([]byte("a\nb\n")) }, "continuation": func(f *LogFragment) { f.Continuation = true }, "noncanonical": func(f *LogFragment) { f.Data += "\n" }, "invalidTime": func(f *LogFragment) { v := "unknown"; f.SourceTime = &v }} {
		t.Run(name, func(t *testing.T) {
			copy := f
			change(&copy)
			if raw, err := copy.Bytes(); err == nil {
				clear(raw)
				t.Fatal("invalid fragment accepted")
			}
		})
	}
}
func TestLogRecordOriginAndFetchTimesNeverInventProvenance(t *testing.T) {
	o := LogOrigin{Record: "origin", ContainerKind: "ephemeral", ContainerName: "debugger", Source: "previous", Stream: "combined"}
	if !o.WellFormed() {
		t.Fatal("nullable previous identity refused")
	}
	v := strings.Repeat("&", 256)
	o.RuntimeID = &v
	if !o.WellFormed() {
		t.Fatal("bounded opaque runtime identity refused")
	}
	o.Stream = "stdout"
	if o.WellFormed() {
		t.Fatal("invented stream accepted")
	}
	at := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	end := at.Add(time.Second)
	c := LogCoverage{Record: "coverage", FetchOutcome: "complete", FetchStartedAt: &at, FetchFinishedAt: &end, Gaps: []string{"rotationUnknown"}}
	if !c.WellFormed() {
		t.Fatal("successful empty fetch refused")
	}
	c.FetchFinishedAt = nil
	if c.WellFormed() {
		t.Fatal("partial interval accepted")
	}
	c = LogCoverage{Record: "coverage", FetchOutcome: "unavailable", Gaps: []string{"previousUnavailable"}}
	if !c.WellFormed() {
		t.Fatal("unfetched source refused")
	}
	c.SourceBytes = 1
	if c.WellFormed() {
		t.Fatal("unavailable source claimed bytes")
	}
}
