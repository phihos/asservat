package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestProjectedCaptureAccountsRequireOriginalProvenanceAndNoInputKey(t *testing.T) {
	id := func(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012d", n) }
	for _, mode := range []string{"valid", "missing", "changed-root", "changed-setup", "changed-version", "changed-installation", "short-key", "extra-input-key"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			files, e := os.OpenRoot(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer files.Close()
			v := contracts.CaptureAccountKey{Format: contracts.CaptureAccountKeyFormat, InstallationID: id(1), RootUID: id(2), SetupID: id(3), Version: id(3) + "-account/v1", Key: bytes.Repeat([]byte{7}, 32)}
			switch mode {
			case "changed-root":
				v.RootUID = id(4)
			case "changed-setup":
				v.SetupID = id(4)
			case "changed-version":
				v.Version = id(4) + "-account/v1"
			case "changed-installation":
				v.InstallationID = id(4)
			case "short-key":
				v.Key = v.Key[:31]
			}
			b, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "extra-input-key" {
				b = append(b[:len(b)-1], []byte(`,"inputKey":"forbidden"}`)...)
			}
			if mode != "missing" {
				if e = os.WriteFile(filepath.Join(dir, contracts.CaptureAccountKeyFile), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			m, e := ReadProjectedCaptureAccounts(t.Context(), files, id(1), id(2), id(3), id(3)+"-account/v1")
			if mode != "valid" {
				if e == nil || m != nil {
					t.Fatal("changed/missing projection supplied account capability")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close()
			first, e := m.CaptureAccount(id(5), id(6))
			if e != nil {
				t.Fatal(e)
			}
			m.Close()
			// A restart reuses the original protected file/version rather than
			// generating another seed or changing the derived account namespace.
			again, e := ReadProjectedCaptureAccounts(t.Context(), files, id(1), id(2), id(3), id(3)+"-account/v1")
			if e != nil {
				t.Fatal(e)
			}
			defer again.Close()
			second, e := again.CaptureAccount(id(5), id(6))
			if e != nil || first != second {
				t.Fatal("restart changed stable capture account")
			}
		})
	}
}
