//go:build !(cgo && libpcap)

package pcap

import (
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/planning"
)

// A build without the libpcap tag never pretends to compile a filter.
func TestStubReportsUnavailableCompiler(t *testing.T) {
	if _, err := NewCompiler().CompileFilter("tcp port 80"); !errors.Is(err, value.ErrFilterCompilerUnavailable) {
		t.Fatal(err)
	}
}
