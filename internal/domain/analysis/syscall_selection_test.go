package analysis

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestSyscallCursorBindsSourceViewAndFilter(t *testing.T) {
	version := artifact.Digest{1}
	names := []string{"write", "read"}
	s, err := NormalizeSyscallSelection(headerCase, headerArtifact, SyscallEventsView, "", 0, names, true)
	if err != nil || s.Limit != 100 || !reflect.DeepEqual(s.Names, []string{"read", "write"}) || !s.Matches(version) {
		t.Fatal(s, err)
	}
	names[0] = "changed"
	if s.Names[1] != "write" {
		t.Fatal("borrowed input names")
	}
	cursor := s.Cursor(100, version)
	next, err := NormalizeSyscallSelection(headerCase, headerArtifact, SyscallEventsView, cursor, 7, []string{"read", "write"}, true)
	if err != nil || next.Start != 100 || !next.Matches(version) || next.Matches(artifact.Digest{2}) {
		t.Fatal(next, err)
	}
	for _, change := range []func(*SyscallSelection){
		func(s *SyscallSelection) { s.CaseID = headerArtifact },
		func(s *SyscallSelection) { s.ArtifactID = headerCase },
		func(s *SyscallSelection) { s.ErrorsOnly = false },
		func(s *SyscallSelection) { s.Names = []string{"read"} },
		func(s *SyscallSelection) { s.View = SyscallSummaryView; s.Names = nil; s.ErrorsOnly = false },
	} {
		c := next
		change(&c)
		if c.Matches(version) {
			t.Fatal("cursor crossed display selection", c)
		}
	}
	summary, err := NormalizeSyscallSelection(headerCase, headerArtifact, SyscallSummaryView, "", 0, nil, false)
	if err != nil || summary.Cursor(1, version) == s.Cursor(1, version) {
		t.Fatal(summary, err)
	}
}

func TestSyscallSelectionRejectsMalformedContinuationAndFilters(t *testing.T) {
	for _, cursor := range []string{"x", "0:" + strings.Repeat("a", 32), "01:" + strings.Repeat("a", 32), "+1:" + strings.Repeat("a", 32), "1:" + strings.Repeat("A", 32), "1000000:" + strings.Repeat("a", 32), "1:" + strings.Repeat("a", 31)} {
		if _, err := NormalizeSyscallSelection(headerCase, headerArtifact, SyscallEventsView, cursor, 0, nil, false); !errors.Is(err, ErrInvalidCursor) {
			t.Fatal(cursor, err)
		}
	}
	for _, names := range [][]string{{""}, {"read", "read"}, {strings.Repeat("a", 65)}, make([]string, 65), {string([]byte{255})}} {
		if _, err := NormalizeSyscallSelection(headerCase, headerArtifact, SyscallEventsView, "", 0, names, false); !errors.Is(err, ErrInvalid) {
			t.Fatal(names, err)
		}
	}
	for _, view := range []SyscallView{"", "arguments"} {
		if _, err := NormalizeSyscallSelection(headerCase, headerArtifact, view, "", 0, nil, false); err == nil {
			t.Fatal(view)
		}
	}
	if _, err := NormalizeSyscallSelection(headerCase, headerArtifact, SyscallSummaryView, "", 0, []string{"read"}, false); err == nil {
		t.Fatal("summary filter accepted")
	}
}
