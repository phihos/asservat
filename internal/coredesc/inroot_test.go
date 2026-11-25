package coredesc

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A container can change a file into a link between the moment a path is
// looked at and the moment it is opened. What is opened is then still a
// file of the container: a link to an absolute path leads to the path
// under the container's root, never to the file of that name on the node.
func TestFilesAreOpenedWithinTheRoot(t *testing.T) {
	root, outside := t.TempDir(), filepath.Join(t.TempDir(), "token")
	secret := "\x7fELF the node's own file"
	if err := os.WriteFile(outside, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	// The container has a file at the same path, as it may.
	inside := filepath.Join(root, outside)
	os.MkdirAll(filepath.Dir(inside), 0o755)
	os.WriteFile(inside, []byte("\x7fELF the container's file"), 0o644)
	os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755)
	lib, link := filepath.Join(root, "usr/lib/libx.so"), filepath.Join(root, "usr/lib/.swap")
	os.WriteFile(lib, []byte("\x7fELF a library"), 0o644)
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	// The link itself, opened by its name: within the root.
	f, err := openIn(root, "/usr/lib/.swap")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if string(got) != "\x7fELF the container's file" {
		t.Fatalf("a link to an absolute path led to %q", got)
	}

	// And under a container that keeps exchanging the file and the link
	// while the files are collected.
	stop, swapped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(swapped)
		for {
			select {
			case <-stop:
				return
			default:
				unix.Renameat2(unix.AT_FDCWD, lib, unix.AT_FDCWD, link, unix.RENAME_EXCHANGE)
			}
		}
	}()
	defer func() { close(stop); <-swapped }()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		var archive bytes.Buffer
		if err := WriteFiles(&archive, root, []string{"/usr/lib/libx.so"}); err != nil {
			continue // the file was a link to nothing the archive takes: no harm
		}
		for r := tar.NewReader(&archive); ; {
			if _, err := r.Next(); err != nil {
				break
			}
			if content, _ := io.ReadAll(r); strings.Contains(string(content), "the node's own file") {
				t.Fatal("the archive holds a file from outside the root")
			}
		}
	}
}
