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
	// The program asked for the library by a link, as most do: with a
	// target as the program saw it, from the root of its container.
	os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755)
	os.Symlink("/lib/libc.so.6", filepath.Join(root, "usr/lib/libc.so"))
	os.Symlink("/etc/passwd", filepath.Join(root, "usr/lib/libout.so")) // leads to nothing in the container
	report := []byte(`{"mappings":[{"file":"/app/server"},{"file":"/app/server"},{"file":"/lib/libc.so.6"},{"file":"/data/orders.db"},{"file":"/lib/gone.so (deleted)"},{"file":"[heap]"},{"file":""}],
 "modules":[{"file":"/usr/lib/libc.so"},{"file":"/usr/lib/libout.so"}]}`)
	files := Files(report, root)
	if len(files) != 3 || files[0] != "/app/server" || files[1] != "/lib/libc.so.6" || files[2] != "/usr/lib/libc.so" {
		t.Fatal(files)
	}
	var archive bytes.Buffer
	if err := WriteFiles(&archive, root, files); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ExtractFiles(bytes.NewReader(archive.Bytes()), dir, int64(archive.Len())); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "lib/libc.so.6")); string(b) != "\x7fELF library" {
		t.Fatalf("unpacked %q", b)
	}
	if to, _ := os.Readlink(filepath.Join(dir, "usr/lib/libc.so")); to != "../../lib/libc.so.6" {
		t.Fatalf("the link leads to %q", to)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "usr/lib/libc.so")); string(b) != "\x7fELF library" {
		t.Fatalf("through the link: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
		t.Fatal("a data file was archived")
	}

	for name, header := range map[string]tar.Header{
		"a path out of the directory": {Name: "../outside", Typeflag: tar.TypeReg, Size: 1},
		"an absolute path":            {Name: "/etc/passwd", Typeflag: tar.TypeReg, Size: 1},
		"a link to an absolute path":  {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		"a link out of the directory": {Name: "lib/link", Typeflag: tar.TypeSymlink, Linkname: "../../outside"},
		"a hard link":                 {Name: "link", Typeflag: tar.TypeLink, Linkname: "lib/libc.so.6"},
	} {
		var bad bytes.Buffer
		w := tar.NewWriter(&bad)
		w.WriteHeader(&header)
		if header.Size > 0 {
			w.Write([]byte("x"))
		}
		w.Close()
		parent := t.TempDir()
		if err := ExtractFiles(&bad, filepath.Join(parent, "in"), 1<<20); err == nil {
			t.Error(name, "was unpacked")
		}
		if _, err := os.Stat(filepath.Join(parent, "outside")); err == nil {
			t.Error(name, "wrote outside")
		}
	}
	// An archive unpacks to no more than its own size; one that would, as
	// with files made of holes, is refused.
	if err := ExtractFiles(bytes.NewReader(archive.Bytes()), t.TempDir(), 20); err == nil {
		t.Error("an archive was unpacked to more than it was said to hold")
	}
	if DescribedBy([]byte(`{"threads":[]}`)) != 1 || DescribedBy([]byte(`{"describer":2}`)) != 2 {
		t.Error("the version of a description")
	}
}

// A container can make any part of a path a link to an absolute path. On a
// node, where the root is /proc/<pid>/root, the kernel follows such a link
// on the agent's own filesystem. No file is taken from there: links are
// followed within the root, as the program saw them.
func TestFilesStayWithinTheRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(outside, "agent.so"), []byte("\x7fELF of the node"), 0o644)
	os.WriteFile(filepath.Join(outside, "os-release"), []byte("ID=node\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/lib/libc.so"), []byte("\x7fELF library"), 0o644)
	// /app and /etc lead out of the container on the node; /lib leads within it.
	os.Symlink(outside, filepath.Join(root, "app"))
	os.Symlink(outside, filepath.Join(root, "etc"))
	os.Symlink("/usr/lib", filepath.Join(root, "lib"))
	report := []byte(`{"mappings":[{"file":"/app/agent.so"},{"file":"/lib/libc.so"}]}`)
	files := Files(report, root)
	for _, name := range files {
		if name == "/app/agent.so" || name == "/etc/os-release" {
			t.Fatalf("a file from outside the root is taken: %v", files)
		}
	}
	if file, _ := resolve(root, "/lib/libc.so"); file != "/usr/lib/libc.so" {
		t.Fatalf("a link within the root leads to %q", file)
	}
	var archive bytes.Buffer
	if err := WriteFiles(&archive, root, []string{"/lib/libc.so"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ExtractFiles(bytes.NewReader(archive.Bytes()), dir, int64(archive.Len())); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "lib/libc.so")); string(b) != "\x7fELF library" {
		t.Fatalf("the library under its name with a link on the way: %q", b)
	}
}
