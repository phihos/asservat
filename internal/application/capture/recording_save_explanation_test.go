package capture

import (
	"testing"
	"unicode/utf8"

	"asservat.local/asservat/internal/application/planning"
)

// The public capture_assessment impact explanation has maxLength 256.
func TestRecordingSaveExplanationsFitPublicContract(t *testing.T) {
	for _, s := range []string{planning.SourceSnapshotExplanation, recordingSaveGroupExplanation} {
		if n := utf8.RuneCountInString(s); n > 256 {
			t.Fatal(n, s)
		}
	}
}
