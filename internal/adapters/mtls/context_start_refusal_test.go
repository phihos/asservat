package mtls

import (
	"errors"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/fleet"
)

// The hub's 426 text is bounded and reduced to printable ASCII before it
// reaches a log line (ADR-333).
func TestHubRefusalTextIsBoundedAndPrintable(t *testing.T) {
	got := hubRefusalText(strings.NewReader("protocol 1\n\x1b[31m" + strings.Repeat("x", 600)))
	if len(got) > 512 || strings.ContainsAny(got, "\n\x1b") || !strings.HasPrefix(got, "protocol 1[31m") {
		t.Fatalf("%q", got)
	}
	var e error = &HubProtocolRefusal{Message: got}
	if !errors.Is(e, value.ErrDenied) || e.(*HubProtocolRefusal).FixedStep() != "connector-protocol" {
		t.Fatal("refusal class")
	}
}
