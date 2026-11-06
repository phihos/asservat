package analysis

import (
	"errors"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestLogCursorRetainsEveryByteAndBindsOriginalSource(t *testing.T) {
	const caseID = "10000000-0000-4000-8000-000000000001"
	const artifactID = "10000000-0000-4000-8000-000000000002"
	s, err := NormalizeLogSelection(caseID, artifactID, "", 0)
	if err != nil || !s.Matches(artifact.Digest{1}) {
		t.Fatal(err)
	}
	for _, position := range []struct {
		fragment uint64
		offset   uint16
	}{{0, 1024}, {1, 0}, {30, 4095}} {
		cursor := s.Cursor(position.fragment, position.offset, artifact.Digest{1})
		next, err := NormalizeLogSelection(caseID, artifactID, cursor, 7)
		if err != nil || next.Fragment != position.fragment || next.Offset != position.offset || !next.Matches(artifact.Digest{1}) || next.Limit != 7 || next.Matches(artifact.Digest{2}) {
			t.Fatal("lost position, source binding or flexible page size", next, err)
		}
		next.CaseID = artifactID
		if next.Matches(artifact.Digest{1}) {
			t.Fatal("cursor crossed cases")
		}
		next.CaseID, next.ArtifactID = caseID, caseID
		if next.Matches(artifact.Digest{1}) {
			t.Fatal("cursor crossed artifacts")
		}
	}
	for _, cursor := range []string{"0:0:" + strings.Repeat("a", 32), "01:0:" + strings.Repeat("a", 32), "1:00:" + strings.Repeat("a", 32), "1:4096:" + strings.Repeat("a", 32), "67108864:0:" + strings.Repeat("a", 32), "1:0:" + strings.Repeat("A", 32), "1:0:short", "-1:0:" + strings.Repeat("a", 32)} {
		if _, err := NormalizeLogSelection(caseID, artifactID, cursor, 1); !errors.Is(err, ErrInvalidCursor) {
			t.Fatal("accepted noncanonical or out-of-bounds position", cursor, err)
		}
	}
}
