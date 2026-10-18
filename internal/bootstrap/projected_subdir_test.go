package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The kubelet's atomic writer: files live in a timestamped directory, ..data
// points at it and each top-level entry is a symlink through ..data. A
// refresh writes a new directory, swaps ..data and deletes the old one.
func kubeletProjection(t *testing.T, base, stamp, content string) {
	t.Helper()
	dir := filepath.Join(base, stamp, "permission")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sql.json"), []byte(content), 0o440); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(base, "..data_tmp")
	if err := os.Symlink(stamp, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(base, "..data")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(base, "permission")); os.IsNotExist(err) {
		if err = os.Symlink("..data/permission", filepath.Join(base, "permission")); err != nil {
			t.Fatal(err)
		}
	}
}

// A root opened on a projected subdirectory keeps the deleted directory after
// a refresh (hub-worker runs failed at begin-credential); reading through the
// stable mount root with dir follows the refresh.
func TestProjectedSubdirectoryReadsSurviveAKubeletRefresh(t *testing.T) {
	base := t.TempDir()
	kubeletProjection(t, base, "..2026_10_18_a", "first")
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pinned, err := root.OpenRoot("permission")
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	in := &providerInputs{files: root, dir: "permission"}
	if b, err := in.read(context.Background(), "sql.json", 64); err != nil || string(b) != "first" {
		t.Fatal(string(b), err)
	}
	kubeletProjection(t, base, "..2026_10_18_b", "second")
	if err := os.RemoveAll(filepath.Join(base, "..2026_10_18_a")); err != nil {
		t.Fatal(err)
	}
	if _, err := pinned.ReadFile("sql.json"); err == nil {
		t.Fatal("the pinned subdirectory root still reads after the refresh; the test does not model the kubelet")
	}
	if b, err := in.read(context.Background(), "sql.json", 64); err != nil || string(b) != "second" {
		t.Fatal("dir read did not follow the refresh", string(b), err)
	}
}
