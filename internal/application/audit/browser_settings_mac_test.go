package audit

import (
	"bytes"
	"testing"
)

func TestBrowserSettingsDigestKeepsExistingDomainAndGeneralBound(t *testing.T) {
	m, err := NewOperationMAC("audit", bytes.Repeat([]byte{1}, 32), "account", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	a, _ := m.Digest("mcp-result/v1", []byte("same bytes"))
	b, _ := m.BrowserSettingsResultDigest([]byte("same bytes"))
	if a != b {
		t.Fatal("settings changed existing audit hash domain")
	}
	large := bytes.Repeat([]byte("x"), 128<<10)
	if _, err = m.Digest("mcp-result/v1", large); err == nil {
		t.Fatal("general digest bound raised")
	}
	if _, err = m.BrowserSettingsResultDigest(large); err != nil {
		t.Fatal(err)
	}
	if _, err = m.BrowserSettingsResultDigest(bytes.Repeat([]byte("x"), 160<<10+1)); err == nil {
		t.Fatal("settings digest unbounded")
	}
}
