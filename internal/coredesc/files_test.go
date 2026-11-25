package coredesc

import (
	"archive/tar"
	"bytes"
	"io/fs"
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

// A core taken by the agent numbers its threads as the node does. What
// they are numbered inside the container is read from the node's /proc and
// kept in the description.
func TestThreadNumbersInsideTheContainer(t *testing.T) {
	proc := t.TempDir()
	for task, status := range map[string]string{
		"5000": "Name:\tdotnet\nNSpid:\t5000\t1\n", "5007": "Name:\tdotnet\nNSpid:\t5007\t8\n",
	} {
		os.MkdirAll(filepath.Join(proc, "5000/task", task), 0o755)
		os.WriteFile(filepath.Join(proc, "5000/task", task, "status"), []byte(status), 0o644)
	}
	ids := NamespaceThreadIDs(proc, 5000)
	if len(ids) != 2 || ids[5000] != 1 || ids[5007] != 8 {
		t.Fatal(ids)
	}
	// A process of the node's own namespace needs none.
	os.MkdirAll(filepath.Join(proc, "6000/task/6000"), 0o755)
	os.WriteFile(filepath.Join(proc, "6000/task/6000/status"), []byte("NSpid:\t6000\n"), 0o644)
	if ids := NamespaceThreadIDs(proc, 6000); ids != nil {
		t.Fatal("of a process in the node's namespace:", ids)
	}
	if got := ThreadIDs([]byte(`{"threadIds":{"5000":1,"5007":8}}`)); len(got) != 2 || got[5007] != 8 {
		t.Fatal("read back from a description:", got)
	}
	if d := (Describer{ThreadIDs: ids}); d.onNode(8) != 5007 || d.onNode(99) != 99 {
		t.Fatal("a runtime's thread on the node")
	}
}

// A program may ask for a library by a path through another directory, as
// the Python of its official image does (/usr/local/bin/../lib/...). The
// archive holds the file at the path it leads to, and unpacked the name
// that was asked for leads to it.
func TestProgramFileAskedForThroughAnotherDirectory(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{"usr/local/bin/python3.12": "\x7fELF program", "usr/local/lib/libpython3.12.so.1.0": "\x7fELF library"} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755)
		os.WriteFile(filepath.Join(root, name), []byte(content), 0o644)
	}
	const asked = "/usr/local/bin/../lib/libpython3.12.so.1.0"
	files := Files([]byte(`{"mappings":[{"file":"/usr/local/bin/python3.12"},{"file":"/usr/local/lib/libpython3.12.so.1.0"}],"modules":[{"file":"`+asked+`"}]}`), root)
	if len(files) != 2 || files[0] != "/usr/local/bin/python3.12" || files[1] != "/usr/local/lib/libpython3.12.so.1.0" {
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
	if b, _ := os.ReadFile(filepath.Join(dir, asked)); string(b) != "\x7fELF library" {
		t.Fatalf("unpacked, the name asked for leads to %q", b)
	}
}

// Archives from before the files of a name through another directory were
// kept at the path it leads to hold such names, some beside the same file
// at that path. They unpack to the path within the directory; a name that
// leads out of it is refused as before.
func TestArchiveWithANameThroughAnotherDirectoryUnpacks(t *testing.T) {
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	for _, name := range []string{"usr/local/bin/python3.13", "usr/local/lib/libpython3.13.so.1.0", "usr/local/bin/../lib/libpython3.13.so.1.0"} {
		w.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len("\x7fELF synthetic"))})
		w.Write([]byte("\x7fELF synthetic"))
	}
	w.Close()
	dir := t.TempDir()
	if err := ExtractFiles(bytes.NewReader(archive.Bytes()), dir, int64(archive.Len())); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "usr/local/lib/libpython3.13.so.1.0")); string(b) != "\x7fELF synthetic" {
		t.Fatalf("unpacked %q", b)
	}
	// A link under both of its names unpacks; a file where a link stands
	// does not, and neither does a second copy that makes the archive
	// unpack to more than its size.
	entries := func(list ...tar.Header) *bytes.Buffer {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		for _, h := range list {
			w.WriteHeader(&h)
			w.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
		w.Close()
		return &b
	}
	twice := entries(tar.Header{Name: "lib/libc.so.6", Typeflag: tar.TypeReg, Size: 4}, tar.Header{Name: "usr/lib/libc.so", Typeflag: tar.TypeSymlink, Linkname: "../../lib/libc.so.6"}, tar.Header{Name: "usr/bin/../lib/libc.so", Typeflag: tar.TypeSymlink, Linkname: "../../lib/libc.so.6"})
	if err := ExtractFiles(twice, t.TempDir(), int64(twice.Len())); err != nil {
		t.Fatal("a link under both of its names:", err)
	}
	inTheWay := entries(tar.Header{Name: "lib/libc.so", Typeflag: tar.TypeSymlink, Linkname: "libc.so.6"}, tar.Header{Name: "usr/../lib/libc.so", Typeflag: tar.TypeReg, Size: 4})
	if err := ExtractFiles(inTheWay, t.TempDir(), int64(inTheWay.Len())); err == nil {
		t.Fatal("a file was unpacked where a link stands")
	}
	more := entries(tar.Header{Name: "lib/x", Typeflag: tar.TypeReg, Size: 8}, tar.Header{Name: "usr/../lib/x", Typeflag: tar.TypeReg, Size: 8})
	if err := ExtractFiles(more, t.TempDir(), 12); err == nil {
		t.Fatal("a second copy made the archive unpack to more than its size")
	}
	var out bytes.Buffer
	w = tar.NewWriter(&out)
	w.WriteHeader(&tar.Header{Name: "usr/../../outside", Typeflag: tar.TypeReg, Size: 1})
	w.Write([]byte("x"))
	w.Close()
	if err := ExtractFiles(bytes.NewReader(out.Bytes()), t.TempDir(), int64(out.Len())); err == nil {
		t.Fatal("a name that leads out of the directory was unpacked")
	}
}

// An archive from a cluster's agent is not trusted: one that climbs out of
// the directory through links that it made before, each of which stays
// inside when looked at by itself, writes nothing outside.
func TestAnArchiveCannotClimbThroughItsOwnLinks(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "work", "describe", "root")
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	for _, link := range []string{"x/l1", "x/l1/l2", "x/l1/l2/l3"} {
		w.WriteHeader(&tar.Header{Name: link, Linkname: "..", Typeflag: tar.TypeSymlink, Mode: 0o777})
	}
	w.WriteHeader(&tar.Header{Name: "x/l1/l2/l3/json.py", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4})
	w.Write([]byte("evil"))
	w.Close()
	err := ExtractFiles(bytes.NewReader(archive.Bytes()), dir, int64(archive.Len()))
	var outside []string
	filepath.WalkDir(parent, func(path string, d fs.DirEntry, _ error) error {
		if d != nil && d.Type().IsRegular() {
			outside = append(outside, path)
		}
		return nil
	})
	if err == nil || len(outside) != 0 {
		t.Fatal("the archive wrote", outside, "and unpacking said", err)
	}
}
