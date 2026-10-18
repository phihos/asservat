package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// ADR-205 decision 4: the operator's evidence delete credential is a static
// owner storage credential; the immutable Secret cannot renew a temporary
// one, so a session token is refused.
func TestEvidenceDeleteCredential(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if b, err := readEvidenceDeleteCredential(""); err != nil || b != nil {
		t.Fatal("absent flag", err)
	}
	if _, err := readEvidenceDeleteCredential(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	for name, body := range map[string]string{
		"session":    `{"accessKeyID":"a","secretAccessKey":"b","sessionToken":"c"}`,
		"no-secret":  `{"accessKeyID":"a","secretAccessKey":"","sessionToken":""}`,
		"no-access":  `{"accessKeyID":"","secretAccessKey":"b","sessionToken":""}`,
		"unknown":    `{"accessKeyID":"a","secretAccessKey":"b","sessionToken":"","x":1}`,
		"not-json":   `access=a`,
		"two-values": `{"accessKeyID":"a","secretAccessKey":"b","sessionToken":""}{}`,
	} {
		if _, err := readEvidenceDeleteCredential(write(name, body)); err == nil {
			t.Fatal("accepted", name)
		}
	}
	const ok = `{"accessKeyID":"synthetic","secretAccessKey":"synthetic-secret","sessionToken":""}`
	raw, err := readEvidenceDeleteCredential(write("ok", ok))
	if err != nil || string(raw) != ok || !validEvidenceDeleteCredential(raw) {
		t.Fatal("static credential refused", err)
	}
}
