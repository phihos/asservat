package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"encoding/json"
	"strings"
	"testing"
)

func TestRawSyscallQueryIsDistinctGrantFundedSource(t *testing.T) {
	s, err := NormalizeSyscallSelection(headerCase, headerArtifact, SyscallView("raw"), "", 1, []string{"write"}, true)
	if err != nil || s.View.DisplayVersion() != "approved-syscall-query/v1" {
		t.Fatal("raw recorded-argument selection unavailable", err)
	}
	source, ok := LookupProjectionSourceFor(artifact.SyscallArgumentsArtifact, s.View.DisplayVersion())
	if !ok || source.ReadOperation() != authorization.ReadSyscallQuery || source.OutputClass() != "raw" {
		t.Fatal("raw query source unavailable", source, ok)
	}
}

func rawSyscallScope(t *testing.T) ContextProjectionScope {
	t.Helper()
	s := testAuthority().Scope
	sel, err := NormalizeSyscallSelection(s.CaseID, s.ArtifactID, SyscallQueryView, "", 1, []string{"write"}, false)
	if err != nil {
		t.Fatal(err)
	}
	src, ok := LookupProjectionSourceFor(artifact.SyscallArgumentsArtifact, SyscallQueryDisplayVersion)
	if !ok {
		t.Fatal("missing raw source")
	}
	s.NativeType, s.SourceFormat, s.DisplayVersion, s.SourceProjectionDigest = src.NativeType, src.Format, src.DisplayVersion, src.ProjectionDigest
	s.Selection = LineSelection{}
	s.Syscalls = sel.Window()
	s.RawGrantID = headerCase
	return s
}
func TestRawSyscallQueryGrantAndCursorNeverConferAuthority(t *testing.T) {
	s := rawSyscallScope(t)
	if !s.Valid() || s.BeginTool() != "syscall_query" || s.ReadBatches() != 2 || s.QueryUnits() != 4 {
		t.Fatal("raw scope accounting", s)
	}
	without := s
	without.RawGrantID = ""
	if without.Valid() || !without.PreGrantValid() {
		t.Fatal("missing grant became authority")
	}
	request := RawSyscallQueryRequest{CaseID: s.CaseID, ArtifactID: s.ArtifactID, Selection: s.Syscalls, IdempotencyKey: "same"}
	if !request.Valid() {
		t.Fatal("discovery request refused")
	}
	request.GrantID = "invalid"
	if request.Valid() {
		t.Fatal("malformed grant")
	}
	metadata := s
	metadata.NativeType = artifact.SyscallRecordsArtifact
	metadata.SourceFormat = artifact.SyscallRecordsFormat
	if metadata.Valid() || metadata.PreGrantValid() {
		t.Fatal("metadata source obtained raw query")
	}
	selection := s.Syscalls.Selection(s.CaseID, s.ArtifactID)
	cursor := selection.Cursor(1, s.Version)
	next, err := NormalizeSyscallSelection(s.CaseID, s.ArtifactID, SyscallQueryView, cursor, 100, []string{"write"}, false)
	if err != nil || !next.Matches(s.Version) {
		t.Fatal("page size cannot change", err)
	}
	changed := next
	changed.ErrorsOnly = true
	if changed.Matches(s.Version) {
		t.Fatal("filter changed under continuation")
	}
	changed = next
	changed.View = SyscallEventsView
	if changed.Matches(s.Version) {
		t.Fatal("metadata/raw cursor mixed")
	}
	a := testAuthority()
	a.Scope = s
	if a.Valid(a.CheckedAt) {
		t.Fatal("scope alone created raw grant")
	}
}
func TestRawSyscallQueryPageOwnsValuesAndIsExclusive(t *testing.T) {
	s := rawSyscallScope(t)
	sel := s.Syscalls.Selection(s.CaseID, s.ArtifactID)
	duration := uint64(0)
	e := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{ProcessRef: "p:1:1", ThreadRef: "t:1:1", PodUID: s.PodUID}, Syscall: "write", ABI: "x86_64", Timestamp: "2026-11-05T10:00:00Z", DurationNS: &duration, Outcome: "success", Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:0"}, {Name: "buffer", Value: "base64:", Truncated: true}}}
	p := SyscallArgumentPage{Version: s.Version, Events: []artifact.RawArgumentEvent{e}, TotalMatching: 2, SyscallRecordCounts: SyscallRecordCounts{RecordCount: 2}}
	if !p.ValidShape(sel, s.Version, s.PodUID) || p.Next(sel, s.Version) == "" {
		t.Fatal("valid whole-event page refused")
	}
	r := ProjectionResult{SyscallQuery: &p}
	if !r.Valid(s) {
		t.Fatal("raw result refused")
	}
	mixed := r
	mixed.SyscallEvents = &SyscallEventPage{}
	if mixed.Valid(s) {
		t.Fatal("mixed argument/metadata result")
	}
	old := testAuthority().Scope
	if r.Valid(old) {
		t.Fatal("raw values under ordinary display")
	}
	clone := CloneSyscallArgumentPage(p)
	clone.Events[0].Arguments[0].Value = "decimal:1"
	*clone.Events[0].DurationNS = 1
	if p.Events[0].Arguments[0].Value != "decimal:0" || *p.Events[0].DurationNS != 0 {
		t.Fatal("borrowed raw values")
	}
	invalid := p
	invalid.Events = append([]artifact.RawArgumentEvent{}, p.Events...)
	invalid.Events[0].Arguments = nil
	if CloneSyscallArgumentPage(invalid).ValidShape(sel, s.Version, s.PodUID) {
		t.Fatal("clone rehabilitated null arguments")
	}
	r.Clear()
	if r.SyscallQuery != nil || p.Events != nil {
		t.Fatal("raw result references retained")
	}
}

func TestRawSyscallQueryEncodedSizeMatchesWholeJSON(t *testing.T) {
	n := uint64(60000000000)
	event := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{ProcessRef: "p:1:1@boot@epoch", ThreadRef: "t:1:1@boot@epoch", PodUID: strings.Repeat("<&\"\\\n\x01\u2028界", 3)}, Syscall: "pwrite64", ABI: "x86_64", Timestamp: "2026-11-05T10:00:00.123456789Z", DurationNS: &n, Outcome: "error", Errno: "E<&\"\\\n", Arguments: []artifact.ArgumentValue{{Name: "offset", Value: "decimal:-9223372036854775808"}, {Name: "buffer", Value: "base64:", Truncated: true}}}
	for _, events := range [][]artifact.RawArgumentEvent{nil, {}, {event}} {
		p := SyscallArgumentPage{Version: artifact.Digest{255}, Start: 999999, TotalMatching: 1000000, Events: events, SyscallRecordCounts: SyscallRecordCounts{RecordCount: 1000000}}
		b, err := json.Marshal(p)
		if err != nil || p.EncodedSize() != len(b) {
			t.Fatal("size differs from actual encodedpage", p.EncodedSize(), len(b), err)
		}
	}
}
