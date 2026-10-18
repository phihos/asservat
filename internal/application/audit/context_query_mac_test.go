package audit

import (
	"bytes"
	"testing"
)

func TestContextQueryInputMACIsPurposeSeparated(t *testing.T) {
	m, err := NewOperationMAC("v1", bytes.Repeat([]byte{1}, 32), "accounts", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	query, err := m.Digest("context-query-input/v1", []byte("same input"))
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"context-input/v1", "native-content-input/v1", "mcp-result/v1"} {
		other, err := m.Digest(domain, []byte("same input"))
		if err != nil || other == query {
			t.Fatal("query MAC purpose collision", domain, err)
		}
	}
	if _, err := m.Digest("arbitrary-query-input/v1", []byte("same input")); err == nil {
		t.Fatal("arbitrary domain accepted")
	}
}
