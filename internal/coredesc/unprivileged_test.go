package coredesc

import (
	"os"
	"path/filepath"
	"testing"
)

// Where gdb runs as nobody, a file that its container keeps to its own
// user is one gdb cannot read: the description names it, so that frames
// without functions have their reason told.
func TestFilesKeptToTheirUserAreTold(t *testing.T) {
	was := lowered
	lowered = func() bool { return true }
	defer func() { lowered = was }()
	dir := t.TempDir()
	for name, want := range map[string]bool{"app-0700": true, "lib-0600": true, "lib-0644": false, "lib-0755": false} {
		path := filepath.Join(dir, name)
		var mode os.FileMode
		switch name[len(name)-4:] {
		case "0700":
			mode = 0o700
		case "0600":
			mode = 0o600
		case "0644":
			mode = 0o644
		case "0755":
			mode = 0o755
		}
		os.WriteFile(path, []byte("x"), 0o600)
		os.Chmod(path, mode)
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := kept(f); got != want {
			t.Errorf("%s: kept to its user %v", name, got)
		}
		f.Close()
	}
	lowered = func() bool { return false }
	if f, _ := os.Open(filepath.Join(dir, "lib-0600")); kept(f) {
		t.Error("where gdb runs as the describer itself, nothing is kept from it")
	}
}
