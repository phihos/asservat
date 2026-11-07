package audit

import (
	"bytes"
	"testing"
)

func TestLiveMACPurposeSeparationClosureAndStableAccountKey(t *testing.T) {
	m, e := NewOperationMAC("audit-a", bytes.Repeat([]byte{1}, 32), "account", bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	n, e := NewOperationMAC("audit-b", bytes.Repeat([]byte{3}, 32), "account", bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	seen := map[[32]byte]bool{}
	for _, purpose := range []string{"cursor", "principal", "workload", "open-key", "selection", "source-handle"} {
		a, e := m.LiveDigest(purpose, []byte("same"))
		b, other := n.LiveDigest(purpose, []byte("same"))
		if e != nil || other != nil || a != b || seen[a] {
			t.Fatal("purpose collision or audit rotation reset", purpose, e, other)
		}
		seen[a] = true
	}
	if _, e = m.LiveDigest("payload", []byte("same")); e == nil {
		t.Fatal("unknown purpose")
	}
	m.Close()
	if _, e = m.LiveDigest("cursor", []byte("same")); e == nil {
		t.Fatal("closed keys")
	}
}
