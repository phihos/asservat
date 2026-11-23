package coredesc

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The archive of a core's program holds the executables and libraries it
// maps, not its data files, and unpacks to nowhere but its directory.
func TestProgramFiles(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{"app/server": "\x7fELF program", "lib/libc.so.6": "\x7fELF library", "data/orders.db": "SQLite format 3"} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755)
		os.WriteFile(filepath.Join(root, name), []byte(content), 0o644)
	}
	report := []byte(`{"mappings":[{"file":"/app/server"},{"file":"/app/server"},{"file":"/lib/libc.so.6"},{"file":"/data/orders.db"},{"file":"/lib/gone.so (deleted)"},{"file":"[heap]"},{"file":""}]}`)
	files := Files(report, root)
	if len(files) != 2 || files[0] != "/app/server" || files[1] != "/lib/libc.so.6" {
		t.Fatal(files)
	}
	var archive bytes.Buffer
	if err := WriteFiles(&archive, root, files); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ExtractFiles(bytes.NewReader(archive.Bytes()), dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "lib/libc.so.6")); string(b) != "\x7fELF library" {
		t.Fatalf("unpacked %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
		t.Fatal("a data file was archived")
	}

	for name, header := range map[string]tar.Header{
		"a path out of the directory": {Name: "../outside", Typeflag: tar.TypeReg, Size: 1},
		"an absolute path":            {Name: "/etc/passwd", Typeflag: tar.TypeReg, Size: 1},
		"a link":                      {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	} {
		var bad bytes.Buffer
		w := tar.NewWriter(&bad)
		w.WriteHeader(&header)
		if header.Size > 0 {
			w.Write([]byte("x"))
		}
		w.Close()
		parent := t.TempDir()
		if err := ExtractFiles(&bad, filepath.Join(parent, "in")); err == nil {
			t.Error(name, "was unpacked")
		}
		if _, err := os.Stat(filepath.Join(parent, "outside")); err == nil {
			t.Error(name, "wrote outside")
		}
	}
	if DescribedBy([]byte(`{"threads":[]}`)) != 1 || DescribedBy([]byte(`{"describer":2}`)) != 2 {
		t.Error("the version of a description")
	}
}
