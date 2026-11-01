package capture

import (
	"testing"

	"asservat.local/asservat/internal/domain/authorization"
)

// ADR-275: a further recorder's capture key is a stable UUID per
// (occurrence, action) and never equals the occurrence's own key.
func TestOccurrenceCaptureKey(t *testing.T) {
	occurrence := "10000000-0000-4000-8000-000000000001"
	a, b := OccurrenceCaptureKey(occurrence, "a1"), OccurrenceCaptureKey(occurrence, "a2")
	if !authorization.UUID(a) || a != OccurrenceCaptureKey(occurrence, "a1") || a == b || a == occurrence || a[14] != '8' {
		t.Fatal(a, b)
	}
}
