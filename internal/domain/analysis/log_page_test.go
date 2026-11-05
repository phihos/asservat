package analysis

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestLogPagePreservesInvalidBytesAndOwnsProvenance(t *testing.T) {
	const caseID = "10000000-0000-4000-8000-000000000001"
	const artifactID = "10000000-0000-4000-8000-000000000002"
	s, _ := NormalizeLogSelection(caseID, artifactID, "", 0)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	runtime := "containerd://original"
	restarts := uint32(0)
	origin := artifact.LogOrigin{Record: "origin", OriginID: 0, ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined", RuntimeID: &runtime, RestartCount: &restarts}
	p := LogPage{Version: artifact.Digest{1}, PodUID: artifactID, WindowStart: now, WindowEnd: now.Add(time.Second), OriginCount: 1, CompleteOrigins: 1, GappedOrigins: 1, UnknownTimestampOrigins: 1, TotalFragments: 1, SourceBytes: 2, Entries: []LogEntry{{Origin: origin, Fragment: 0, Line: 1, EndLine: true, Data: base64.StdEncoding.EncodeToString([]byte{0xff, '\n'})}}}
	if !p.ValidShape(s, artifact.Digest{1}, artifactID) {
		t.Fatal("invalid bytes or zero restart count lost")
	}
	cloned := CloneLogPage(p)
	*cloned.Entries[0].Origin.RuntimeID = "replacement"
	*cloned.Entries[0].Origin.RestartCount = 9
	cloned.Clear()
	if *p.Entries[0].Origin.RuntimeID != runtime || *p.Entries[0].Origin.RestartCount != 0 || p.Entries[0].Data != "/wo=" {
		t.Fatal("borrowed provenance or changed original bytes")
	}
	for _, mutate := range []func(*LogPage){
		func(p *LogPage) { p.PodUID = caseID },
		func(p *LogPage) { p.Version = artifact.Digest{2} },
		func(p *LogPage) { p.Entries[0].Data = "//==" },
		func(p *LogPage) {
			p.Entries[0].Data = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 1025)))
		},
		func(p *LogPage) { p.Entries[0].Fragment = 1 },
		func(p *LogPage) { p.UnavailableOrigins = 1 },
		func(p *LogPage) { p.HasNext = true },
	} {
		bad := CloneLogPage(p)
		mutate(&bad)
		if bad.ValidShape(s, artifact.Digest{1}, artifactID) {
			t.Fatal("accepted changed scope, noncanonical bytes or impossible page")
		}
	}
}

func logPageFixture() (LogSelection, LogPage) {
	s, _ := NormalizeLogSelection(queryTestID, queryOtherID, "", 100)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	o := artifact.LogOrigin{Record: "origin", ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined"}
	p := LogPage{Version: artifact.Digest{1}, PodUID: queryOtherID, WindowStart: now, WindowEnd: now.Add(time.Hour), OriginCount: 1, CompleteOrigins: 1, GappedOrigins: 1, UnknownTimestampOrigins: 1, TotalFragments: 2, SourceBytes: 5000, HasNext: true, NextFragment: 0, NextOffset: 2048, Entries: []LogEntry{{Origin: o, Fragment: 0, Line: 1, Data: base64.StdEncoding.EncodeToString(make([]byte, 1024))}, {Origin: o, Fragment: 0, Line: 1, Offset: 1024, LineOffset: 1024, Continuation: true, Data: base64.StdEncoding.EncodeToString(make([]byte, 1024))}}}
	return s, p
}
func TestLogPageRejectsDroppedRepeatedOrMisassociatedBytes(t *testing.T) {
	s, p := logPageFixture()
	if !p.ValidShape(s, p.Version, p.PodUID) {
		t.Fatal("positive split fragment")
	}
	for name, change := range map[string]func(*LogPage){"offsetGap": func(p *LogPage) { p.Entries[1].Offset++ }, "overlap": func(p *LogPage) { p.Entries[1].Offset-- }, "lineOffsetGap": func(p *LogPage) { p.Entries[1].LineOffset++ }, "lineChange": func(p *LogPage) { p.Entries[1].Line++ }, "sameFragmentOriginChange": func(p *LogPage) { p.Entries[1].Origin.Source = "previous" }, "ordinalJump": func(p *LogPage) { p.TotalFragments = 4; p.Entries[1].Fragment = 2 }, "nextOverlap": func(p *LogPage) { p.NextOffset = 1 }, "nextGap": func(p *LogPage) { p.NextOffset = 3000 }, "nextOrdinalJump": func(p *LogPage) { p.TotalFragments = 4; p.NextFragment = 2; p.NextOffset = 0 }, "missingNext": func(p *LogPage) { p.HasNext = false; p.NextFragment = 0; p.NextOffset = 0 }, "entryBeyondBytes": func(p *LogPage) { p.SourceBytes = 1025 }, "timeOutsideWindow": func(p *LogPage) { at := "2020-01-01T00:00:00Z"; p.Entries[0].SourceTime = &at }} {
		t.Run(name, func(t *testing.T) {
			bad := CloneLogPage(p)
			change(&bad)
			if bad.ValidShape(s, bad.Version, bad.PodUID) {
				t.Fatal("accepted skipped/repeated/misassociated bytes")
			}
		})
	}
}
func TestLogPageBudgetIncludesPublicTextEscaping(t *testing.T) {
	s, p := logPageFixture()
	p.HasNext = false
	p.NextFragment = 0
	p.NextOffset = 0
	p.Entries = nil
	p.TotalFragments = 8
	p.SourceBytes = 8 * 1024
	for i := uint64(0); i < 8; i++ {
		p.Entries = append(p.Entries, LogEntry{Origin: artifact.LogOrigin{Record: "origin", ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined"}, Fragment: i, Line: 1, Offset: i * 1024, LineOffset: i * 1024, Continuation: i > 0, Data: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("&", 1024)))})
	}
	if p.ValidShape(s, p.Version, p.PodUID) {
		t.Fatal("base64-only size accepted public text above24KiB")
	}
}

func TestLogPageCursorCanSplitAndCompleteOneOriginalFragment(t *testing.T) {
	s, p := logPageFixture()
	cursor := s.Cursor(0, 1024, p.Version)
	s, err := NormalizeLogSelection(s.CaseID, s.ArtifactID, cursor, 1)
	if err != nil {
		t.Fatal(err)
	}
	p.StartOffset = 1024
	p.TotalFragments = 1
	p.SourceBytes = 2048
	p.Entries = p.Entries[1:]
	p.HasNext = false
	p.NextFragment = 0
	p.NextOffset = 0
	if !p.ValidShape(s, p.Version, p.PodUID) {
		t.Fatal("last slice lost original offset")
	}
	p.HasNext = true
	p.TotalFragments = 2
	p.SourceBytes = 3000
	p.NextFragment = 1
	if !p.ValidShape(s, p.Version, p.PodUID) {
		t.Fatal("completed nativefragment cannot advance to next ordinal")
	}
}
func TestLogPageAllowsUnavailableOriginsBetweenExactByteStreams(t *testing.T) {
	s, p := logPageFixture()
	a := p.Entries[0]
	a.Data = base64.StdEncoding.EncodeToString([]byte("a\n"))
	a.EndLine = true
	b := a
	b.Fragment = 1
	b.Origin.OriginID = 2
	b.Origin.Source = "previous"
	b.Data = base64.StdEncoding.EncodeToString([]byte("b\n"))
	p.Entries = []LogEntry{a, b}
	p.SourceBytes = 4
	p.TotalFragments = 2
	p.OriginCount = 3
	p.CompleteOrigins = 1
	p.PartialOrigins = 1
	p.UnavailableOrigins = 1
	p.HasNext = false
	p.NextFragment = 0
	p.NextOffset = 0
	if !p.ValidShape(s, p.Version, p.PodUID) {
		t.Fatal("skipped unavailable origin invented missing byte fragments")
	}
	cloned := CloneLogPage(p)
	cloned.Clear()
	if p.Entries[0].Data == "" {
		t.Fatal("clone clear changed original")
	}
}
func TestLogEntryUpperBoundCoversActualEscapedPublicRepresentation(t *testing.T) {
	_, p := logPageFixture()
	e := p.Entries[0]
	runtime := strings.Repeat("&", 256)
	e.Origin.RuntimeID = &runtime
	payload := strings.Repeat("<&\x00\"", 256)
	e.Data = base64.StdEncoding.EncodeToString([]byte(payload))
	wire := map[string]any{"origin": e.Origin, "fragment": e.Fragment, "line": e.Line, "offset": e.Offset, "line_offset": e.LineOffset, "continuation": e.Continuation, "end_line": e.EndLine, "source_time": e.SourceTime, "text": payload, "bytes_base64": nil}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > e.EncodedUpperBound() {
		t.Fatal("escapedpublic exceedsentrybound", err, len(encoded), e.EncodedUpperBound())
	}
	e.Data = "malformed"
	if e.EncodedUpperBound() <= LogQueryPageBytes {
		t.Fatal("invalidbytevalue hasplausiblewirecost")
	}
}
